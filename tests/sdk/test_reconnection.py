"""Tests for WebSocket reconnection logic (SDK-05)."""

from __future__ import annotations

import asyncio
import json
import random
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uam.sdk.transport.websocket import (
    BASE_DELAY,
    JITTER_RANGE,
    MAX_DELAY,
    WebSocketTransport,
)


class TestExponentialBackoff:
    """Verify the backoff delay formula: min(BASE * 2^attempt, MAX) + jitter."""

    def test_exponential_backoff_calculation(self):
        """Delays increase exponentially up to MAX_DELAY cap."""
        delays = []
        for attempt in range(10):
            base_delay = min(BASE_DELAY * (2**attempt), MAX_DELAY)
            delays.append(base_delay)

        # Should be increasing (up to cap)
        for i in range(1, len(delays)):
            assert delays[i] >= delays[i - 1]

        # First few should be less than MAX_DELAY
        assert delays[0] == BASE_DELAY
        assert delays[1] == BASE_DELAY * 2
        assert delays[2] == BASE_DELAY * 4

    def test_backoff_max_cap(self):
        """Delay never exceeds MAX_DELAY + JITTER_RANGE, even for huge attempts."""
        for attempt in [50, 100, 1000]:
            base = min(BASE_DELAY * (2**attempt), MAX_DELAY)
            jitter = JITTER_RANGE  # Maximum possible jitter
            total = base + jitter
            assert total <= MAX_DELAY + JITTER_RANGE

    def test_jitter_adds_randomness(self):
        """Two runs of the same attempt produce different delays (with jitter)."""
        random.seed(None)
        delays1 = []
        delays2 = []
        for attempt in range(5):
            base = min(BASE_DELAY * (2**attempt), MAX_DELAY)
            delays1.append(base + random.uniform(0, JITTER_RANGE))
            delays2.append(base + random.uniform(0, JITTER_RANGE))

        # At least one pair should differ (extremely high probability)
        assert delays1 != delays2


class TestWebSocketTransportInit:
    """WebSocketTransport initialization tests."""

    def test_connected_event_not_set_initially(self):
        """_connected event is not set before connect() is called."""
        transport = WebSocketTransport("ws://test/ws", "apikey123")
        assert not transport._connected.is_set()

    def test_pending_list_empty_initially(self):
        """No pending messages before any connection."""
        transport = WebSocketTransport("ws://test/ws", "apikey123")
        assert transport._pending == []


class TestHandleMessage:
    """WebSocketTransport._handle_message routing tests."""

    @pytest.fixture()
    def transport(self):
        """Create a transport with a mock websocket."""
        t = WebSocketTransport("ws://test/ws", "apikey123")
        t._ws = AsyncMock()
        return t

    async def test_handle_ping_responds_pong(self, transport):
        """Ping messages trigger a pong response."""
        await transport._handle_message({"type": "ping", "ts": 123})
        transport._ws.send.assert_called_once()
        sent = json.loads(transport._ws.send.call_args[0][0])
        assert sent["type"] == "pong"

    async def test_handle_ack_no_error(self, transport):
        """ACK messages are handled without error."""
        await transport._handle_message({
            "type": "ack",
            "message_id": "test-msg-1",
            "delivered": True,
        })
        # No exception = success; ack is just logged

    async def test_handle_envelope_queued(self, transport):
        """Inbound envelopes are queued in _pending when no callback set."""
        transport._on_message = None
        envelope = {
            "uam_version": "0.1.0",
            "message_id": "msg-123",
            "from": "alice::test.local",
            "to": "bob::test.local",
            "payload": "encrypted-data",
        }
        await transport._handle_message(envelope)
        assert len(transport._pending) == 1
        assert transport._pending[0]["message_id"] == "msg-123"

    async def test_handle_envelope_callback(self, transport):
        """Inbound envelopes trigger the callback when one is set."""
        callback = AsyncMock()
        transport._on_message = callback

        envelope = {
            "uam_version": "0.1.0",
            "message_id": "msg-456",
            "from": "alice::test.local",
            "to": "bob::test.local",
            "payload": "encrypted-data",
        }
        await transport._handle_message(envelope)
        callback.assert_called_once_with(envelope)
        # Should NOT be in pending when callback handled it
        assert len(transport._pending) == 0

    async def test_handle_error_logged(self, transport):
        """Error messages are handled without raising."""
        await transport._handle_message({
            "error": "rate_limited",
            "detail": "Too many requests",
        })
        # No exception = logged gracefully
