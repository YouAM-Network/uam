"""Application-level heartbeat manager for WebSocket connections (RELAY-06).

Sends periodic ping messages and disconnects unresponsive agents.
"""

from __future__ import annotations

import asyncio
import logging
import time

from uam.relay.connections import ConnectionManager

logger = logging.getLogger(__name__)

PING_INTERVAL: float = 30.0  # seconds between pings
PONG_TIMEOUT: float = 10.0   # seconds to wait for pong after ping


class HeartbeatManager:
    """Tracks WebSocket liveness via application-level ping/pong.

    Parameters
    ----------
    manager:
        The ``ConnectionManager`` instance that owns the WebSocket map.
    ping_interval:
        Seconds between ping sweeps (default ``PING_INTERVAL``).
    pong_timeout:
        Seconds to wait for a pong before considering the connection dead
        (default ``PONG_TIMEOUT``).
    """

    def __init__(
        self,
        manager: ConnectionManager,
        ping_interval: float = PING_INTERVAL,
        pong_timeout: float = PONG_TIMEOUT,
    ) -> None:
        self._manager = manager
        self._ping_interval = ping_interval
        self._pong_timeout = pong_timeout
        self._last_pong: dict[str, float] = {}
        self._task: asyncio.Task | None = None

    # -- public lifecycle --------------------------------------------------

    async def start(self) -> None:
        """Start the background ping loop."""
        self._task = asyncio.create_task(self._ping_loop())

    async def stop(self) -> None:
        """Cancel the background ping loop and wait for clean shutdown."""
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    # -- connection tracking -----------------------------------------------

    def record_connect(self, address: str) -> None:
        """Give *address* an initial pong credit on connect."""
        self._last_pong[address] = time.monotonic()

    def record_pong(self, address: str) -> None:
        """Update the last-pong timestamp for *address*."""
        self._last_pong[address] = time.monotonic()

    def record_disconnect(self, address: str) -> None:
        """Remove *address* from tracking."""
        self._last_pong.pop(address, None)

    # -- background loop ---------------------------------------------------

    async def _ping_loop(self) -> None:
        """Periodically ping online agents and disconnect unresponsive ones."""
        while True:
            await asyncio.sleep(self._ping_interval)
            now = time.monotonic()

            # Snapshot addresses to avoid mutation during iteration
            addresses = list(self._last_pong.keys())
            for address in addresses:
                last = self._last_pong.get(address)
                if last is None:
                    continue
                if now - last > self._ping_interval + self._pong_timeout:
                    logger.warning(
                        "Heartbeat timeout for %s (%.1fs since last pong), disconnecting",
                        address,
                        now - last,
                    )
                    await self._manager.disconnect(address)
                    self._last_pong.pop(address, None)
                else:
                    await self._manager.send_to(address, {"type": "ping", "ts": now})
