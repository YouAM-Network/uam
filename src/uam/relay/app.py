"""FastAPI application factory for the UAM relay server."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.exceptions import HTTPException, RequestValidationError
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from uam.relay.config import Settings
from uam.relay.connections import ConnectionManager
from uam.relay.database import cleanup_expired_dedup, cleanup_expired_messages, close_db, init_db
from uam.relay.demo_sessions import SessionManager
from uam.relay.heartbeat import HeartbeatManager
from uam.relay.rate_limit import SlidingWindowCounter

logger = logging.getLogger(__name__)

# How often to prune stale rate-limiter buckets (seconds)
_RATE_LIMIT_CLEANUP_INTERVAL: float = 300.0  # 5 minutes

# How often to sweep expired dedup entries (seconds)
_DEDUP_CLEANUP_INTERVAL: float = 3600.0  # 1 hour

# How often to sweep expired stored messages (seconds)
_EXPIRED_MESSAGE_SWEEP_INTERVAL: float = 300.0  # 5 minutes


async def _rate_limiter_cleanup_loop(app: FastAPI) -> None:
    """Periodically prune expired rate-limiter buckets to prevent memory leak."""
    while True:
        await asyncio.sleep(_RATE_LIMIT_CLEANUP_INTERVAL)
        app.state.sender_limiter.cleanup()
        app.state.recipient_limiter.cleanup()
        app.state.register_limiter.cleanup()
        app.state.domain_limiter.cleanup()
        logger.debug("Rate limiter buckets cleaned up")


# How often to prune expired demo sessions (seconds)
_DEMO_SESSION_CLEANUP_INTERVAL: float = 60.0


async def _demo_session_cleanup_loop(app: FastAPI) -> None:
    """Periodically remove expired ephemeral demo sessions."""
    while True:
        await asyncio.sleep(_DEMO_SESSION_CLEANUP_INTERVAL)
        count = await app.state.demo_sessions.cleanup_expired()
        if count:
            logger.info("Cleaned up %d expired demo sessions", count)


async def _dedup_cleanup_loop(app: FastAPI) -> None:
    """Periodically sweep expired dedup entries (older than 7 days)."""
    while True:
        await asyncio.sleep(_DEDUP_CLEANUP_INTERVAL)
        count = await cleanup_expired_dedup(app.state.db)
        if count:
            logger.info("Cleaned up %d expired dedup entries", count)


async def _expired_message_sweep_loop(app: FastAPI) -> None:
    """Periodically delete stored messages whose expires timestamp has passed."""
    while True:
        await asyncio.sleep(_EXPIRED_MESSAGE_SWEEP_INTERVAL)
        count = await cleanup_expired_messages(app.state.db)
        if count:
            logger.info("Swept %d expired stored messages", count)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage database and connection resources across app lifetime."""
    settings = app.state.settings
    app.state.db = await init_db(settings.database_path)
    app.state.manager = ConnectionManager()

    # Spam defense: allow/block list (SPAM-01) -- loaded BEFORE accepting requests
    from uam.relay.spam_filter import AllowBlockList

    spam_filter = AllowBlockList()
    await spam_filter.load(app.state.db)
    app.state.spam_filter = spam_filter

    # Spam defense: reputation manager (SPAM-02) -- cache warmed BEFORE accepting requests
    from uam.relay.reputation import ReputationManager

    reputation_manager = ReputationManager(app.state.db)
    await reputation_manager.load_cache()
    app.state.reputation_manager = reputation_manager

    # Rate limiters on app.state so each create_app() gets fresh instances (RELAY-05)
    app.state.sender_limiter = SlidingWindowCounter(limit=60, window_seconds=60.0)
    app.state.recipient_limiter = SlidingWindowCounter(limit=100, window_seconds=60.0)
    app.state.register_limiter = SlidingWindowCounter(limit=5, window_seconds=60.0)
    # Domain-level rate limiter (SPAM-03)
    app.state.domain_limiter = SlidingWindowCounter(
        limit=settings.domain_rate_limit, window_seconds=60.0
    )

    # Heartbeat manager (RELAY-06)
    heartbeat = HeartbeatManager(app.state.manager)
    app.state.heartbeat = heartbeat
    await heartbeat.start()

    # Webhook delivery service (HOOK-02)
    from uam.relay.webhook import WebhookCircuitBreaker, WebhookDeliveryService

    circuit_breaker = WebhookCircuitBreaker(settings=settings)
    webhook_service = WebhookDeliveryService(app.state.db, circuit_breaker, app.state.manager)
    await webhook_service.start()
    app.state.webhook_service = webhook_service

    # Ephemeral demo sessions (DEMO-01)
    app.state.demo_sessions = SessionManager(ttl_minutes=10, max_sessions=1000)

    # Background cleanup for rate limiter buckets (prevents memory leak)
    cleanup_task = asyncio.create_task(_rate_limiter_cleanup_loop(app))
    # Background cleanup for expired demo sessions
    demo_cleanup_task = asyncio.create_task(_demo_session_cleanup_loop(app))

    # Background re-verification of domain verifications (DNS-08)
    from uam.relay.verification import reverification_loop

    reverification_task = asyncio.create_task(reverification_loop(app))

    # Background sweep for expired dedup entries (MSG-03)
    dedup_cleanup_task = asyncio.create_task(_dedup_cleanup_loop(app))

    # Background sweep for expired stored messages (MSG-04)
    expired_msg_task = asyncio.create_task(_expired_message_sweep_loop(app))

    yield

    expired_msg_task.cancel()
    try:
        await expired_msg_task
    except asyncio.CancelledError:
        pass
    dedup_cleanup_task.cancel()
    try:
        await dedup_cleanup_task
    except asyncio.CancelledError:
        pass
    reverification_task.cancel()
    try:
        await reverification_task
    except asyncio.CancelledError:
        pass
    demo_cleanup_task.cancel()
    try:
        await demo_cleanup_task
    except asyncio.CancelledError:
        pass
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    await webhook_service.stop()
    await heartbeat.stop()
    await close_db(app.state.db)


def create_app() -> FastAPI:
    """Create and configure the UAM relay FastAPI application.

    .. note:: SEC-01: TLS is handled by the deployment platform (Railway,
       Fly.io, nginx, etc.).  The relay app runs on plain HTTP/WS; the
       platform terminates TLS and provides HTTPS/WSS.  Do NOT add TLS
       certificate handling in application code.
    """
    settings = Settings()

    # Configure logging from settings
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if settings.debug:
        logging.getLogger("uam").setLevel(logging.DEBUG)

    app = FastAPI(
        title="UAM Relay",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Store settings on app.state so lifespan and routes can access it
    app.state.settings = settings

    # Consistent JSON error shape: {"error": "<code>", "detail": "<message>"}
    _STATUS_TO_ERROR = {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        409: "conflict",
        422: "validation_error",
        429: "rate_limited",
        503: "service_unavailable",
    }

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": _STATUS_TO_ERROR.get(exc.status_code, "error"),
                "detail": exc.detail,
            },
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "error": "validation_error",
                "detail": str(exc),
            },
        )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # REST routes with /api/v1 prefix
    from uam.relay.routes.register import router as register_router
    from uam.relay.routes.agents import router as agents_router
    from uam.relay.routes.send import router as send_router
    from uam.relay.routes.inbox import router as inbox_router
    from uam.relay.routes.federation import router as federation_router
    from uam.relay.routes.demo import router as demo_router
    from uam.relay.routes.verify_domain import router as verify_domain_router
    from uam.relay.routes.webhook_admin import router as webhook_admin_router
    from uam.relay.routes.admin import router as admin_router
    from uam.relay.routes.presence import router as presence_router

    app.include_router(register_router, prefix="/api/v1")
    app.include_router(agents_router, prefix="/api/v1")
    app.include_router(send_router, prefix="/api/v1")
    app.include_router(inbox_router, prefix="/api/v1")
    app.include_router(federation_router, prefix="/api/v1")
    app.include_router(demo_router, prefix="/api/v1")
    app.include_router(verify_domain_router, prefix="/api/v1")
    app.include_router(webhook_admin_router, prefix="/api/v1")
    app.include_router(admin_router, prefix="/api/v1")
    app.include_router(presence_router, prefix="/api/v1")

    # Health and WebSocket (no prefix)
    from uam.relay.routes.health import router as health_router
    from uam.relay.ws import router as ws_router

    app.include_router(health_router)
    app.include_router(ws_router)

    return app
