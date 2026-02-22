"""WebSocket transport with exponential backoff and jitter (SDK-05)."""

from __future__ import annotations

import asyncio
import json
import logging
import random
from typing import Any, Awaitable, Callable

import websockets
from websockets.asyncio.client import connect

from uam.sdk.transport.base import TransportBase

logger = logging.getLogger(__name__)

# Reconnection constants
BASE_DELAY = 1.0    # Initial delay in seconds
MAX_DELAY = 60.0    # Maximum delay cap
JITTER_RANGE = 1.0  # Random jitter 0 to JITTER_RANGE


class WebSocketTransport(TransportBase):
    """WebSocket transport with exponential backoff and jitter (SDK-05).

    Maintains a persistent connection to the relay, automatically
    reconnecting on disconnection with exponential backoff plus
    random jitter to prevent thundering herd.
    """

    def __init__(
        self,
        ws_url: str,
        token: str,
        on_message: Callable[[dict], Awaitable[None]] | None = None,
    ) -> None:
        self._url = f"{ws_url}?token={token}"
        self._on_message = on_message
        self._ws: websockets.asyncio.client.ClientConnection | None = None
        self._listen_task: asyncio.Task | None = None
        self._pending: list[dict] = []  # Messages received before explicit receive()
        self._connected = asyncio.Event()

    async def connect(self) -> None:
        """Start the WebSocket connection with automatic reconnection."""
        self._listen_task = asyncio.create_task(self._connection_loop())
        # Wait for initial connection
        await asyncio.wait_for(self._connected.wait(), timeout=30.0)

    async def disconnect(self) -> None:
        """Close the WebSocket connection."""
        if self._listen_task:
            self._listen_task.cancel()
            try:
                await self._listen_task
            except asyncio.CancelledError:
                pass
        if self._ws:
            await self._ws.close()

    async def send(self, envelope: dict[str, Any]) -> None:
        """Send an envelope dict over the WebSocket."""
        if self._ws is None:
            raise RuntimeError("WebSocket not connected")
        await self._ws.send(json.dumps(envelope))

    async def receive(self, limit: int = 50) -> list[dict[str, Any]]:
        """Drain pending messages (received via WebSocket push)."""
        result = self._pending[:limit]
        self._pending = self._pending[limit:]
        return result

    async def listen(self, callback: Callable[[dict], Awaitable[None]]) -> None:
        """Register a callback for real-time message delivery."""
        self._on_message = callback

    async def _connection_loop(self) -> None:
        """Reconnection loop with exponential backoff and jitter."""
        attempt = 0
        while True:
            try:
                async with connect(
                    self._url,
                    ping_interval=20,
                    ping_timeout=20,
                    open_timeout=10,
                ) as ws:
                    self._ws = ws
                    self._connected.set()
                    attempt = 0  # Reset on successful connection
                    logger.info("WebSocket connected to relay")

                    async for raw_text in ws:
                        msg = json.loads(raw_text)
                        await self._handle_message(msg)

            except (
                websockets.exceptions.ConnectionClosed,
                OSError,
                asyncio.TimeoutError,
            ) as exc:
                self._connected.clear()
                self._ws = None
                attempt += 1
                delay = min(BASE_DELAY * (2**attempt), MAX_DELAY)
                jitter = random.uniform(0, JITTER_RANGE)
                total_delay = delay + jitter
                logger.warning(
                    "WebSocket disconnected (%s), reconnecting in %.1fs (attempt %d)",
                    type(exc).__name__,
                    total_delay,
                    attempt,
                )
                await asyncio.sleep(total_delay)

            except asyncio.CancelledError:
                break

    async def _handle_message(self, msg: dict) -> None:
        """Route incoming WebSocket messages by type."""
        msg_type = msg.get("type")

        if msg_type == "ping":
            # Respond to relay heartbeat
            if self._ws:
                await self._ws.send(json.dumps({"type": "pong"}))

        elif msg_type == "ack":
            logger.debug(
                "ACK for message %s (delivered=%s)",
                msg.get("message_id"),
                msg.get("delivered"),
            )

        elif msg_type == "error" or "error" in msg:
            logger.error(
                "Relay error: [%s] %s",
                msg.get("error") or msg.get("code"),
                msg.get("detail"),
            )

        elif "uam_version" in msg:
            # Inbound envelope
            if self._on_message:
                await self._on_message(msg)
            else:
                self._pending.append(msg)
