"""WebSocket connection manager for real-time message routing."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from starlette.websockets import WebSocket

logger = logging.getLogger(__name__)


class LockedWebSocket:
    """Wraps a Starlette WebSocket so every send/close is serialized
    on a per-connection asyncio.Lock (T4.1).

    Frame interleaving is the canonical 'no per-connection send lock'
    bug class — WebSocket.send_json is implemented as multiple
    ``await self.send({...})`` ASGI events; two concurrent coroutines
    that each call send_json can interleave the websocket text frames
    mid-message.

    Receive-side calls (receive_json, receive_text) are NOT locked because
    the contract is "exactly one coroutine reads from a given socket at a
    time" (the recv loop in websocket_endpoint).
    """

    def __init__(self, websocket: WebSocket) -> None:
        self._ws = websocket
        self._lock = asyncio.Lock()

    async def send_json(self, data: Any) -> None:
        async with self._lock:
            await self._ws.send_json(data)

    async def send_text(self, data: str) -> None:
        async with self._lock:
            await self._ws.send_text(data)

    async def send_bytes(self, data: bytes) -> None:
        async with self._lock:
            await self._ws.send_bytes(data)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        async with self._lock:
            await self._ws.close(code=code, reason=reason)

    # Pass-through receive (single-reader contract — no lock needed)
    async def receive_json(self) -> Any:
        return await self._ws.receive_json()

    async def receive_text(self) -> str:
        return await self._ws.receive_text()

    # Property pass-throughs for code that introspects the underlying WS
    @property
    def client(self):
        return self._ws.client

    @property
    def headers(self):
        return self._ws.headers

    @property
    def scope(self):
        return self._ws.scope

    @property
    def query_params(self):
        return self._ws.query_params

    @property
    def app(self):
        return self._ws.app

    @property
    def url(self):
        return self._ws.url

    async def accept(self, subprotocol: str | None = None) -> None:
        # accept happens before any other coroutine can hold the lock; safe without locking.
        if subprotocol is not None:
            await self._ws.accept(subprotocol=subprotocol)
        else:
            await self._ws.accept()


class ConnectionManager:
    """Tracks active WebSocket connections keyed by agent address.

    All dict mutations are protected by an asyncio.Lock to prevent race
    conditions during concurrent connect/disconnect/send operations.

    Each registered WebSocket is wrapped in a :class:`LockedWebSocket` on
    connect (T4.1), so every send/close issued through the manager is
    serialized on a per-connection asyncio.Lock — preventing frame
    interleave when the recv loop, heartbeat, drain, peer forwarding, and
    webhook receipt paths fire concurrently against the same connection.
    """

    def __init__(self) -> None:
        self._connections: dict[str, LockedWebSocket] = {}
        self._lock = asyncio.Lock()

    async def connect(self, address: str, websocket: WebSocket) -> LockedWebSocket:
        """Register a WebSocket connection for *address*.

        Last-connect-wins: if *address* already has a connection, the old
        one is closed AFTER the registry lock is released so a slow close
        (peer that doesn't ACK the close frame, half-dead client, NAT
        timeout, etc.) cannot wedge the entire registry behind ``self._lock``
        — see C3 in REVIEW-relay-core.

        Returns the wrapped :class:`LockedWebSocket` so the caller (the
        ``websocket_endpoint`` recv loop) can use it for its own send
        paths — every error response, ack, and rate-limit reply must go
        through the wrapper to share the per-connection lock with peer
        forwarding, heartbeat, and the stored-message drain.

        T4.3: capture the OLD socket inside the registry lock, swap in the
        NEW wrapped socket, RELEASE the lock, THEN await ``old.close()``
        OUTSIDE the lock. Concurrent ``connect`` / ``disconnect`` /
        ``send_to`` operations on OTHER addresses now complete in
        milliseconds even while one address's old socket takes seconds to
        close. (Wave 0 contract:
        ``tests/relay/test_connections_concurrency.py::test_connect_does_not_block_registry_during_close``.)
        """
        wrapped = LockedWebSocket(websocket)
        async with self._lock:
            # T4.3: capture OLD inside the lock, swap in the NEW socket,
            # then RELEASE the lock before awaiting old.close() below.
            old = self._connections.get(address)
            self._connections[address] = wrapped
        # Lock RELEASED. Now await old.close() OUTSIDE the lock — a slow
        # close() must not wedge the entire registry behind self._lock.
        # See C3 in REVIEW-relay-core; concurrent operations on OTHER
        # addresses complete in milliseconds even while the old socket
        # takes seconds to close.
        if old is not None:
            try:
                await old.close(code=1000, reason="new connection")
            except Exception:
                pass  # old connection may already be dead
        return wrapped

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

        The dict lookup is protected by the registry lock, but the
        ``await ws.send_json(...)`` happens OUTSIDE that lock — the
        per-connection lock owned by :class:`LockedWebSocket` provides
        the send-side serialization, while the registry lock only
        protects the address→socket dict.
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
