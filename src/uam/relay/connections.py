"""WebSocket connection manager for real-time message routing."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from starlette.websockets import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Tracks active WebSocket connections keyed by agent address.

    All dict mutations are protected by an asyncio.Lock to prevent race
    conditions during concurrent connect/disconnect/send operations.
    """

    def __init__(self) -> None:
        self._connections: dict[str, WebSocket] = {}
        self._lock = asyncio.Lock()

    async def connect(self, address: str, websocket: WebSocket) -> None:
        """Register a WebSocket connection for *address*.

        Last-connect-wins: if *address* already has a connection, the old
        one is closed before the new one is stored.
        """
        async with self._lock:
            old = self._connections.get(address)
            if old is not None:
                try:
                    await old.close(code=1000, reason="new connection")
                except Exception:
                    pass  # old connection may already be dead
            self._connections[address] = websocket

    async def disconnect(self, address: str) -> None:
        """Remove the connection for *address*."""
        async with self._lock:
            self._connections.pop(address, None)

    def is_online(self, address: str) -> bool:
        """Return True if *address* has an active WebSocket connection."""
        return address in self._connections

    async def send_to(self, address: str, data: dict[str, Any]) -> bool:
        """Send JSON *data* to *address*. Returns True if delivered.

        On send failure (dead connection), disconnects and returns False.
        """
        async with self._lock:
            ws = self._connections.get(address)
        if ws is None:
            return False
        try:
            await ws.send_json(data)
            return True
        except Exception:
            logger.debug("Send to %s failed, disconnecting", address)
            await self.disconnect(address)
            return False

    @property
    def online_count(self) -> int:
        """Number of currently connected agents."""
        return len(self._connections)

    @property
    def online_addresses(self) -> list[str]:
        """List of currently connected agent addresses."""
        return list(self._connections.keys())
