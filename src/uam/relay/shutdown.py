"""Graceful shutdown drain (Phase 48 Q7).

Drain semantics:
- WS clients receive ``{"type": "shutdown", "drain_seconds": N}`` notice
- HTTP returns 503 + ``Retry-After: 30`` for non-``/health`` paths during drain
- ``/health`` passes through (load-balancer probes succeed until pod removal)
- Pending federation tasks get up to 5 s grace via ``asyncio.wait_for``
- Webhook retries abandoned (already idempotent at peer)

Drain window configurable via ``UAM_DRAIN_SECONDS`` env (default 15).

The broadcast uses ``asyncio.gather(..., return_exceptions=True)`` so that an
already-disconnected client cannot abort the drain for the rest of the fleet
(RESEARCH § Pitfall 6). The per-client ``manager.send_to`` call goes through
Phase 44's :class:`uam.relay.connections.LockedWebSocket`, so the drain notice
shares the per-connection send lock with peer forwarding, heartbeat, and the
stored-message drain — no frame interleave.

This module deliberately accepts BOTH calling conventions for
``manager.online_addresses``: the real :class:`ConnectionManager` exposes it as
a ``@property`` (``mgr.online_addresses`` returns the list), while Wave-0
contract tests' ``_FakeManager`` uses a regular method
(``mgr.online_addresses()`` returns the list). ``begin_drain`` checks
``callable`` and adapts so either works without modification.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Any, Final

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

DRAIN_RESPONSE_RETRY_AFTER: Final[int] = 30
DEFAULT_DRAIN_SECONDS: Final[int] = int(os.environ.get("UAM_DRAIN_SECONDS", "15"))


class DrainingShutdownManager:
    """Coordinates graceful shutdown across WS + HTTP surfaces.

    The drain manager owns one piece of state: an :class:`asyncio.Event`
    flag (``self.draining``) that the HTTP middleware reads to decide
    whether to return 503. ``begin_drain`` sets the flag, broadcasts a
    shutdown notice to every connected WS client, then sleeps the drain
    window so well-behaved clients can disconnect cleanly before the
    lifespan teardown forcibly cancels remaining tasks.
    """

    def __init__(self, drain_seconds: int = DEFAULT_DRAIN_SECONDS) -> None:
        self.drain_seconds = drain_seconds
        self.draining: asyncio.Event = asyncio.Event()

    async def begin_drain(self, manager: Any) -> None:
        """Notify all connected WS clients, then wait the drain window.

        Uses ``asyncio.gather(..., return_exceptions=True)`` to tolerate
        already-disconnected clients. Each per-client failure is counted
        in the summary log line but does not abort the drain.

        Args:
            manager: A connection manager exposing
                ``online_addresses`` (either as a property returning an
                iterable of address strings or as a callable returning
                the same) AND ``send_to(addr, msg)`` returning an
                awaitable. Phase 44's :class:`ConnectionManager` (property)
                and Wave-0 contract test fakes (method) both satisfy this.
        """
        # Set the drain flag FIRST so the HTTP middleware starts returning
        # 503 immediately, even before the broadcast completes. New WS
        # connections initiated mid-drain still go through, but uvicorn's
        # ``--graceful-timeout`` (operator-configured to be >= drain_seconds
        # — see FORWARD_COMPAT) closes the listening socket so this is
        # bounded in practice (RESEARCH Pitfall 3).
        self.draining.set()

        notice = {
            "type": "shutdown",
            "drain_seconds": self.drain_seconds,
        }

        # Adapter for property-vs-method online_addresses (see module
        # docstring). Wrap in try/except so an unexpected manager shape
        # cannot abort the drain — log and continue with no broadcast.
        try:
            attr = manager.online_addresses
            raw = attr() if callable(attr) else attr
            addresses = list(raw)
        except Exception:
            logger.exception("shutdown.failed_to_enumerate_addresses")
            addresses = []

        if addresses:
            results = await asyncio.gather(
                *(manager.send_to(addr, notice) for addr in addresses),
                return_exceptions=True,
            )
            failures = [r for r in results if isinstance(r, Exception)]
            logger.info(
                "shutdown.drain_notice_sent ok=%d failed=%d total=%d",
                len(addresses) - len(failures),
                len(failures),
                len(addresses),
            )
        else:
            logger.info("shutdown.drain_notice_no_clients")

        # ``drain_seconds=0`` disables the wait — used by Wave-0 tests
        # and as an operator escape hatch ("act like the old behavior").
        if self.drain_seconds > 0:
            await asyncio.sleep(self.drain_seconds)


class DrainBlockMiddleware(BaseHTTPMiddleware):
    """Returns 503 + ``Retry-After`` during drain. ``/health`` passes through.

    The ``/health`` whitelist is required for load-balancer health
    probes to keep succeeding until the pod is removed from rotation;
    if the probe fails first, the LB might rip the pod out before the
    drain notice has a chance to reach connected clients. Production
    deployments may also want to whitelist ``/admin/health`` and
    federation ``.well-known`` paths — extend the condition as needed.
    """

    def __init__(self, app, drain_manager: DrainingShutdownManager) -> None:
        super().__init__(app)
        self._drain = drain_manager

    async def dispatch(self, request: Request, call_next) -> Response:
        if self._drain.draining.is_set() and request.url.path != "/health":
            return JSONResponse(
                status_code=503,
                content={"error": "draining", "detail": "server shutting down"},
                headers={"Retry-After": str(DRAIN_RESPONSE_RETRY_AFTER)},
            )
        return await call_next(request)


async def drain_pending_tasks(*tasks: asyncio.Task, timeout: float = 5.0) -> None:
    """Give pending tasks up to ``timeout`` seconds before forced cancellation.

    Use this for federation/queue tasks that should complete-or-die.
    Webhook retries should NOT be passed here — they are idempotent at
    the peer and can be cancelled outright per RESEARCH § Q7 scope.

    Args:
        *tasks: Tasks to wait on (any number; zero tasks is a no-op).
        timeout: Total seconds to wait for ALL tasks combined.
    """
    if not tasks:
        return
    try:
        await asyncio.wait_for(
            asyncio.gather(*tasks, return_exceptions=True),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.warning("shutdown.tasks_timed_out_after=%.1fs", timeout)
        for t in tasks:
            if not t.done():
                t.cancel()
