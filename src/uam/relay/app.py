"""FastAPI application factory for the UAM relay server (v0.3.1)."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.exceptions import HTTPException, RequestValidationError
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from uam.relay.config import Settings
from uam.relay.connections import ConnectionManager
from uam.relay.demo_sessions import SessionManager
from uam.relay.heartbeat import HeartbeatManager
from uam.relay.rate_limit import SlidingWindowCounter

logger = logging.getLogger(__name__)

# How often to prune stale rate-limiter buckets (seconds)
_RATE_LIMIT_CLEANUP_INTERVAL: float = 300.0  # 5 minutes

# Federation retry loop interval (seconds)
_FEDERATION_RETRY_INTERVAL: float = 30.0

# How often to sweep expired dedup entries (seconds)
_DEDUP_CLEANUP_INTERVAL: float = 3600.0  # 1 hour

# How often to sweep expired stored messages (seconds)
_EXPIRED_MESSAGE_SWEEP_INTERVAL: float = 300.0  # 5 minutes

# How often to run the retention purge (seconds)
_RETENTION_PURGE_INTERVAL: float = 3600.0  # 1 hour

# Default retention window in days (configurable via MESSAGE_RETENTION_DAYS env var)
_DEFAULT_RETENTION_DAYS: int = 90


async def _rate_limiter_cleanup_loop(app: FastAPI) -> None:
    """Periodically prune expired rate-limiter buckets to prevent memory leak."""
    while True:
        await asyncio.sleep(_RATE_LIMIT_CLEANUP_INTERVAL)
        app.state.sender_limiter.cleanup()
        app.state.recipient_limiter.cleanup()
        app.state.register_limiter.cleanup()
        app.state.domain_limiter.cleanup()
        federation_limiter = getattr(app.state, "federation_limiter", None)
        if federation_limiter:
            federation_limiter.cleanup()
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
    from uam.db.crud.dedup import cleanup_expired
    from uam.db.retry import is_transient_error
    from uam.db.session import async_session_factory
    from uam.db.engine import get_engine

    while True:
        await asyncio.sleep(_DEDUP_CLEANUP_INTERVAL)
        try:
            factory = async_session_factory(get_engine())
            async with factory() as session:
                count = await cleanup_expired(session)
            if count:
                logger.info("Cleaned up %d expired dedup entries", count)
        except Exception as exc:
            if is_transient_error(exc):
                logger.warning("Transient DB error in dedup cleanup, will retry next cycle: %s", exc)
            else:
                logger.exception("Error in dedup cleanup loop")


async def _expired_message_sweep_loop(app: FastAPI) -> None:
    """Periodically mark stored messages whose expires timestamp has passed."""
    from uam.db.crud.messages import mark_expired
    from uam.db.retry import is_transient_error
    from uam.db.session import async_session_factory
    from uam.db.engine import get_engine

    while True:
        await asyncio.sleep(_EXPIRED_MESSAGE_SWEEP_INTERVAL)
        try:
            factory = async_session_factory(get_engine())
            async with factory() as session:
                count = await mark_expired(session)
            if count:
                logger.info("Swept %d expired stored messages", count)
        except Exception as exc:
            if is_transient_error(exc):
                logger.warning("Transient DB error in expired message sweep, will retry next cycle: %s", exc)
            else:
                logger.exception("Error in expired message sweep")


async def _retention_worker_loop(app: FastAPI) -> None:
    """Periodically hard-purge soft-deleted and expired/delivered messages past retention window.

    Two-step lifecycle:
    1. mark_expired() catches messages whose expires_at has passed (status -> 'expired')
    2. purge_expired() hard-deletes messages that have been expired/delivered/soft-deleted
       for longer than the retention window (default 90 days)

    Step 1 is handled by _expired_message_sweep_loop (every 5 min).
    This worker handles step 2 (every 1 hour).
    """
    from uam.db.crud.messages import purge_expired
    from uam.db.retry import is_transient_error
    from uam.db.session import async_session_factory
    from uam.db.engine import get_engine

    retention_days = int(os.environ.get("MESSAGE_RETENTION_DAYS", str(_DEFAULT_RETENTION_DAYS)))

    while True:
        await asyncio.sleep(_RETENTION_PURGE_INTERVAL)
        try:
            factory = async_session_factory(get_engine())
            async with factory() as session:
                count = await purge_expired(session, retention_days=retention_days)
            if count:
                logger.info("Retention worker purged %d old records (retention=%d days)", count, retention_days)
        except Exception as exc:
            if is_transient_error(exc):
                logger.warning("Transient DB error in retention worker, will retry next cycle: %s", exc)
            else:
                logger.exception("Error in retention worker loop")


async def _federation_retry_loop(app: FastAPI) -> None:
    """Process the federation_queue: retry failed/pending federation deliveries (FED-10).

    Picks messages from federation_queue where status='pending' and next_retry <= now.
    For each, attempts forward via FederationService. On success, marks status='delivered'.
    On failure, increments attempt_count, computes next_retry from retry_delays schedule,
    marks status='failed' if all retries exhausted.
    """
    import json
    from datetime import datetime as dt, timedelta

    from uam.db.crud.federation import get_pending_queue, update_queue_entry
    from uam.db.retry import is_transient_error
    from uam.db.session import async_session_factory
    from uam.db.engine import get_engine

    while True:
        await asyncio.sleep(_FEDERATION_RETRY_INTERVAL)
        try:
            federation_service = getattr(app.state, "federation_service", None)
            settings = app.state.settings
            if not federation_service or not settings.federation_enabled:
                continue

            factory = async_session_factory(get_engine())

            # Get pending messages ready for retry
            async with factory() as session:
                pending = await get_pending_queue(session, limit=50)

            for entry in pending:
                envelope_dict = json.loads(entry.envelope)
                via_list = json.loads(entry.via)

                result = await federation_service.forward(
                    envelope_dict=envelope_dict,
                    from_relay=settings.relay_domain,
                    via=via_list,
                    hop_count=entry.hop_count,
                )

                if result.delivered:
                    async with factory() as session:
                        await update_queue_entry(session, entry.id, status="delivered")
                    logger.info("Federation retry delivered: queue_id=%d to %s", entry.id, entry.target_domain)
                else:
                    new_attempt = entry.attempt_count + 1
                    retry_delays = settings.federation_retry_delays
                    if new_attempt >= len(retry_delays):
                        async with factory() as session:
                            await update_queue_entry(
                                session, entry.id,
                                status="failed",
                                error=result.error or "max retries",
                            )
                        logger.warning("Federation retry exhausted: queue_id=%d to %s after %d attempts", entry.id, entry.target_domain, new_attempt)
                    else:
                        delay = retry_delays[new_attempt]
                        next_retry = dt.utcnow() + timedelta(seconds=delay)
                        async with factory() as session:
                            await update_queue_entry(
                                session, entry.id,
                                status="pending",
                                error=result.error,
                                next_retry=next_retry,
                            )
                        logger.info("Federation retry scheduled: queue_id=%d to %s, attempt %d, next in %ds", entry.id, entry.target_domain, new_attempt, delay)
        except Exception as exc:
            if is_transient_error(exc):
                logger.warning("Transient DB error in federation retry loop, will retry next cycle: %s", exc)
            else:
                logger.exception("Error in federation retry loop")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manage database and connection resources across app lifetime."""
    settings = app.state.settings

    # ---------------------------------------------------------------
    # Database: async engine + session factory (Phase 33/34 infra)
    # ---------------------------------------------------------------
    # Construct DATABASE_URL from settings if not set in environment
    if not os.environ.get("DATABASE_URL"):
        db_path = os.path.abspath(settings.database_path)
        os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"

    from uam.db.engine import init_engine, dispose_engine
    from uam.db.session import init_session_factory, create_tables

    engine = init_engine()
    session_factory = init_session_factory(engine)

    # Enable WAL mode for SQLite to allow concurrent reads during writes
    database_url = os.environ.get("DATABASE_URL", "")
    if "sqlite" in database_url:
        async with engine.begin() as conn:
            await conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            await conn.exec_driver_sql("PRAGMA busy_timeout=5000")

    # Run Alembic migrations if available, fall back to create_tables for dev/test
    try:
        import asyncio as _asyncio

        from alembic.command import upgrade as alembic_upgrade
        from uam.cli.main import _get_alembic_config

        alembic_cfg = _get_alembic_config(os.environ["DATABASE_URL"])
        # Run sync Alembic in a thread — env.py uses asyncio.run() which
        # cannot nest inside the already-running lifespan event loop.
        await _asyncio.to_thread(alembic_upgrade, alembic_cfg, "head")
        logger.info("Alembic migrations applied successfully")
    except Exception as exc:
        logger.warning("Alembic migration unavailable (%s), falling back to create_tables", exc)
        await create_tables(engine)

    app.state.manager = ConnectionManager()

    # Spam defense: allow/block list (SPAM-01) -- loaded BEFORE accepting requests
    from uam.relay.spam_filter import AllowBlockList

    spam_filter = AllowBlockList()
    async with session_factory() as session:
        await spam_filter.load(session)
    app.state.spam_filter = spam_filter

    # Spam defense: reputation manager (SPAM-02) -- cache warmed BEFORE accepting requests
    from uam.relay.reputation import ReputationManager

    reputation_manager = ReputationManager(session_factory)
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
    webhook_service = WebhookDeliveryService(circuit_breaker, app.state.manager)
    await webhook_service.start()
    app.state.webhook_service = webhook_service

    # Federation: relay keypair, federation service, safety modules (FED-01 through FED-10)
    from uam.relay.relay_auth import load_or_generate_relay_keypair
    from uam.relay.federation import FederationService
    from uam.relay.relay_blocklist import RelayAllowBlockList
    from uam.relay.relay_reputation import RelayReputationManager

    if settings.federation_enabled:
        relay_sk, relay_vk = load_or_generate_relay_keypair(settings.relay_key_path)
        app.state.relay_signing_key = relay_sk
        app.state.relay_verify_key = relay_vk
        logger.info("Relay keypair loaded from %s", settings.relay_key_path)

        # Federation service (FED-01, FED-02)
        federation_service = FederationService(settings, relay_sk, relay_vk)
        app.state.federation_service = federation_service

        # Relay-level blocklist/allowlist (FED-07)
        relay_blocklist = RelayAllowBlockList()
        async with session_factory() as session:
            await relay_blocklist.load(session)
        app.state.relay_blocklist = relay_blocklist

        # Relay-level reputation (FED-08)
        relay_reputation = RelayReputationManager(
            session_factory,
            base_rate_limit=settings.federation_relay_rate_limit,
        )
        await relay_reputation.load_cache()
        app.state.relay_reputation = relay_reputation

        # Per-source-relay rate limiter (FED-06)
        app.state.federation_limiter = SlidingWindowCounter(
            limit=settings.federation_relay_rate_limit,
            window_seconds=60.0,
        )
    else:
        app.state.relay_signing_key = None
        app.state.relay_verify_key = None
        app.state.federation_service = None
        app.state.relay_blocklist = None
        app.state.relay_reputation = None
        app.state.federation_limiter = None
        logger.info("Federation is disabled")

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

    # Background retention worker -- hard-purge old records (RES-04)
    retention_task = asyncio.create_task(_retention_worker_loop(app))

    # Federation retry loop (FED-10)
    federation_retry_task = asyncio.create_task(_federation_retry_loop(app)) if settings.federation_enabled else None

    # Record startup time for uptime calculation (RES-03)
    app.state.startup_time = time.monotonic()

    yield

    # Cancel federation retry loop (FED-10)
    if federation_retry_task:
        federation_retry_task.cancel()
        try:
            await federation_retry_task
        except asyncio.CancelledError:
            pass

    # Cancel retention worker (RES-04)
    retention_task.cancel()
    try:
        await retention_task
    except asyncio.CancelledError:
        pass

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

    # Federation resource cleanup
    if app.state.federation_service:
        await app.state.federation_service.close()
    if getattr(app.state, "federation_limiter", None):
        app.state.federation_limiter.cleanup()

    await webhook_service.stop()
    await heartbeat.stop()

    # Dispose async engine
    await dispose_engine()


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
    from uam.relay.routes.federation import well_known_router
    from uam.relay.routes.demo import router as demo_router
    from uam.relay.routes.verify_domain import router as verify_domain_router
    from uam.relay.routes.webhook_admin import router as webhook_admin_router
    from uam.relay.routes.admin import router as admin_router
    from uam.relay.routes.presence import router as presence_router
    from uam.relay.routes.handshakes import router as handshakes_router

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
    app.include_router(handshakes_router, prefix="/api/v1")

    # Health, WebSocket, and .well-known (no prefix)
    from uam.relay.routes.health import router as health_router
    from uam.relay.ws import router as ws_router

    app.include_router(health_router)
    app.include_router(ws_router)
    app.include_router(well_known_router)

    return app
