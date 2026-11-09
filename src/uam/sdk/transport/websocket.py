"""WebSocket transport with exponential backoff and jitter (SDK-05)."""

from __future__ import annotations

import asyncio
import json
import logging
import random
from typing import Any, Awaitable, Callable

import websockets
from websockets.asyncio.client import connect

from uam.protocol.errors import SendRefusedError
from uam.sdk.transport.base import TransportBase

logger = logging.getLogger(__name__)

# Reconnection constants
BASE_DELAY = 1.0    # Initial delay in seconds
MAX_DELAY = 60.0    # Maximum delay cap
JITTER_RANGE = 1.0  # Random jitter 0 to JITTER_RANGE
SEND_SETTLE_SECONDS = 5.0  # How long a close waits for the relay to answer sends
ACK_TIMEOUT_SECONDS = 5.0  # How long send() waits for the relay's answer


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
        # T2.2 (Phase 43 Plan 04): authenticate via Sec-WebSocket-Protocol
        # subprotocol rather than ?token= in the URL.  This keeps the bearer
        # token out of HTTP server access logs, reverse-proxy logs, browser
        # address-bar history, and third-party JS error trackers that capture
        # the URL.  The relay echoes the chosen subprotocol back via
        # ``websocket.accept(subprotocol=...)`` to complete the handshake.
        self._url = ws_url
        self._token = token
        self._on_message = on_message
        self._ws: websockets.asyncio.client.ClientConnection | None = None
        self._listen_task: asyncio.Task | None = None
        self._pending: list[dict] = []  # Messages received before explicit receive()
        self._connected = asyncio.Event()
        self._unanswered = 0  # Envelopes sent that the relay hasn't answered yet
        self._all_answered = asyncio.Event()
        self._all_answered.set()
        # send() waiting for the relay's answer, by message_id
        self._waiting: dict[str, asyncio.Future] = {}

    async def connect(self) -> None:
        """Start the WebSocket connection with automatic reconnection."""
        self._listen_task = asyncio.create_task(self._connection_loop())
        # Wait for initial connection
        await asyncio.wait_for(self._connected.wait(), timeout=30.0)

    async def disconnect(self) -> None:
        """Close the WebSocket connection, once the relay has answered what was sent.

        The relay stops reading a socket when it can't write an ack to it, so
        closing straight after send() loses every frame but the first.
        """
        try:
            await asyncio.wait_for(self._all_answered.wait(), timeout=SEND_SETTLE_SECONDS)
        except asyncio.TimeoutError:
            logger.warning("Closing with %d sends unanswered", self._unanswered)
        if self._listen_task:
            self._listen_task.cancel()
            try:
                await self._listen_task
            except asyncio.CancelledError:
                pass
        self._abandon_waiting()
        if self._ws:
            await self._ws.close()

    async def send(self, envelope: dict[str, Any]) -> dict[str, Any] | None:
        """Send an envelope over the WebSocket and wait for the relay's answer.

        Returns the relay's ack (``{"status": ..., ...}``), or None when none
        came within ACK_TIMEOUT_SECONDS: the message may still have arrived.
        Raises ``SendRefusedError`` when the relay refuses it by message_id
        (relays before 1.1 don't name it, so their refusals end as None).
        A send made from inside an on_message callback returns None at once:
        the loop that would read its answer is the one running the callback.
        """
        if self._ws is None:
            raise RuntimeError("WebSocket not connected")
        message_id = envelope.get("message_id")
        answer: asyncio.Future | None = None
        # The connection loop reads the answers.  A send made from inside it
        # (an on_message callback answering a handshake) can't wait for one.
        reading = asyncio.current_task() is self._listen_task
        if not reading and isinstance(message_id, str) and message_id not in self._waiting:
            # Registered first: the ack can arrive before ws.send returns.
            answer = asyncio.get_running_loop().create_future()
            self._waiting[message_id] = answer
        # Counted first, for the same reason.
        self._unanswered += 1
        self._all_answered.clear()
        try:
            await self._ws.send(json.dumps(envelope))
        except BaseException:
            self._answered()
            if answer is not None:
                self._waiting.pop(message_id, None)
            raise
        if answer is None:
            return None
        try:
            return await asyncio.wait_for(asyncio.shield(answer), ACK_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            logger.warning("No answer from the relay for %s within %.0fs", message_id, ACK_TIMEOUT_SECONDS)
            return None
        finally:
            if self._waiting.get(message_id) is answer:
                del self._waiting[message_id]

    def _resolve(self, message_id: Any, result: Any = None, error: BaseException | None = None) -> None:
        """Hand the relay's answer to the send() waiting for *message_id*."""
        answer = self._waiting.get(message_id) if isinstance(message_id, str) else None
        if answer is None or answer.done():
            return
        if error is not None:
            answer.set_exception(error)
        else:
            answer.set_result(result)

    def _abandon_waiting(self) -> None:
        """The socket went: no answers will come for what it carried."""
        for answer in self._waiting.values():
            if not answer.done():
                answer.set_result(None)

    def _answered(self) -> None:
        self._unanswered = max(0, self._unanswered - 1)
        if self._unanswered == 0:
            self._all_answered.set()

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
                    subprotocols=[f"bearer.{self._token}"],
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
                self._unanswered = 0  # Their answers went with the socket
                self._all_answered.set()
                self._abandon_waiting()
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

        # First: an envelope's type and keys are the sender's to choose.
        if "uam_version" in msg:
            if self._on_message:
                await self._on_message(msg)
            else:
                self._pending.append(msg)

        elif msg_type == "ping":
            # Respond to relay heartbeat
            if self._ws:
                await self._ws.send(json.dumps({"type": "pong"}))

        elif msg_type == "relay.notice":
            # Mail the relay had answered "queued" turned out pending at the
            # recipient's relay: it was not delivered. (The 1.4 outbox acts
            # on this; until then it is logged.)
            logger.warning(
                "Message %s was not delivered (status=%s)",
                msg.get("message_id"), msg.get("status"),
            )

        elif msg_type == "ack":
            logger.debug(
                "ACK for message %s (status=%s)",
                msg.get("message_id"),
                msg.get("status", msg.get("delivered")),
            )
            self._answered()
            self._resolve(msg.get("message_id"), result=msg)

        elif msg_type == "error" or "error" in msg:
            code = msg.get("error") or msg.get("code")
            logger.error("Relay error: [%s] %s", code, msg.get("detail"))
            self._answered()
            message_id = msg.get("message_id")
            if isinstance(message_id, str):
                self._resolve(
                    message_id,
                    error=SendRefusedError(message_id, str(code), msg.get("detail")),
                )
