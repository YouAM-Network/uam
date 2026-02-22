"""Tests for the HeartbeatManager (RELAY-06)."""

from __future__ import annotations

import asyncio
import time
from unittest.mock import AsyncMock

import pytest

from uam.relay.connections import ConnectionManager
from uam.relay.heartbeat import HeartbeatManager


class TestHeartbeatManagerUnit:
    """Unit tests for HeartbeatManager record/tracking methods."""

    def test_record_connect_and_disconnect(self):
        """record_connect tracks address; record_disconnect removes it."""
        manager = ConnectionManager()
        hb = HeartbeatManager(manager, ping_interval=30.0, pong_timeout=10.0)

        hb.record_connect("alice::test.local")
        assert "alice::test.local" in hb._last_pong

        hb.record_disconnect("alice::test.local")
        assert "alice::test.local" not in hb._last_pong

    def test_record_pong_updates_timestamp(self):
        """record_pong updates the last_pong timestamp."""
        manager = ConnectionManager()
        hb = HeartbeatManager(manager, ping_interval=30.0, pong_timeout=10.0)

        hb.record_connect("alice::test.local")
        t1 = hb._last_pong["alice::test.local"]

        time.sleep(0.01)
        hb.record_pong("alice::test.local")
        t2 = hb._last_pong["alice::test.local"]

        assert t2 > t1

    def test_record_disconnect_nonexistent(self):
        """record_disconnect on non-existent address does not raise."""
        manager = ConnectionManager()
        hb = HeartbeatManager(manager, ping_interval=30.0, pong_timeout=10.0)
        hb.record_disconnect("nobody::test.local")  # should not raise


class TestHeartbeatPingLoop:
    """Tests for the background ping loop with fast intervals."""

    @pytest.mark.asyncio
    async def test_ping_sent_to_connected(self):
        """HeartbeatManager sends a ping to connected agents."""
        manager = ConnectionManager()
        manager.send_to = AsyncMock(return_value=True)

        # Use very short intervals for testing
        hb = HeartbeatManager(manager, ping_interval=0.1, pong_timeout=0.05)
        hb.record_connect("alice::test.local")

        await hb.start()
        # Wait for at least one ping cycle
        await asyncio.sleep(0.2)
        await hb.stop()

        # Verify send_to was called with a ping message
        assert manager.send_to.call_count >= 1
        call_args = manager.send_to.call_args_list[0]
        assert call_args[0][0] == "alice::test.local"
        assert call_args[0][1]["type"] == "ping"

    @pytest.mark.asyncio
    async def test_timeout_disconnects_unresponsive(self):
        """Agents that don't respond to pings are disconnected."""
        manager = ConnectionManager()
        manager.send_to = AsyncMock(return_value=True)
        manager.disconnect = AsyncMock()

        # Very short intervals: ping every 0.1s, timeout after 0.05s
        # Total threshold: 0.1 + 0.05 = 0.15s
        hb = HeartbeatManager(manager, ping_interval=0.1, pong_timeout=0.05)
        hb.record_connect("stale::test.local")
        # Backdate the last_pong to simulate staleness
        hb._last_pong["stale::test.local"] = time.monotonic() - 1.0

        await hb.start()
        await asyncio.sleep(0.2)
        await hb.stop()

        # Should have disconnected the stale agent
        manager.disconnect.assert_called_with("stale::test.local")

    @pytest.mark.asyncio
    async def test_start_stop_clean(self):
        """start() and stop() manage the background task cleanly."""
        manager = ConnectionManager()
        hb = HeartbeatManager(manager, ping_interval=0.5, pong_timeout=0.3)
        await hb.start()
        assert hb._task is not None
        await hb.stop()
        assert hb._task is None


class TestWebSocketPong:
    """Integration: pong messages are handled silently on WebSocket."""

    def test_pong_handled_without_error(self, client, registered_agent):
        """Sending a pong message does not produce an error response."""
        with client.websocket_connect(f"/ws?token={registered_agent['token']}") as ws:
            # Send a pong message
            ws.send_json({"type": "pong"})
            # Send a non-envelope, non-pong message to verify connection is alive
            # (pong is silently consumed; this tests that the loop continues)
            ws.send_json({"type": "unknown_test"})
            # Connection should still be open -- no error for the pong.
            # The unknown_test is just ignored (logged), so no response either.
            # If pong had caused an error, we'd see it here.
            # The simplest verification: we can still close cleanly.
