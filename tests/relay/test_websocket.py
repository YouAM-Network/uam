"""Tests for WebSocket /ws endpoint."""

from __future__ import annotations

import threading
import time

import pytest


class TestWebSocket:
    """WebSocket connection and messaging tests."""

    def test_websocket_connect(self, client, registered_agent):
        """Agent can connect via WebSocket with a valid token."""
        token = registered_agent["token"]
        with client.websocket_connect(f"/ws?token={token}"):
            pass  # Connection accepted successfully

    def test_websocket_invalid_token(self, client):
        """Connecting with an invalid token is rejected."""
        with pytest.raises(Exception):
            with client.websocket_connect("/ws?token=bogus-key-12345"):
                pass

    def test_websocket_send_and_ack(self, client, registered_agent_pair, make_envelope):
        """Sender receives ACK after sending via WebSocket (recipient offline)."""
        alice, bob = registered_agent_pair
        wire = make_envelope(alice, bob)

        with client.websocket_connect(f"/ws?token={alice['token']}") as ws:
            ws.send_json(wire)
            ack = ws.receive_json()
            assert ack["type"] == "ack"
            assert ack["delivered"] is False
            assert "message_id" in ack

    def test_websocket_realtime_routing(self, client, registered_agent_pair, make_envelope):
        """Two agents exchange messages in real-time through the relay.

        This is the core RELAY-01 test: A sends, B receives.
        """
        alice, bob = registered_agent_pair
        wire = make_envelope(alice, bob)
        received_messages: list[dict] = []
        bob_ready = threading.Event()

        def bob_listener():
            with client.websocket_connect(f"/ws?token={bob['token']}") as ws_bob:
                bob_ready.set()
                msg = ws_bob.receive_json()
                received_messages.append(msg)

        # Start Bob's listener in a thread
        bob_thread = threading.Thread(target=bob_listener, daemon=True)
        bob_thread.start()
        bob_ready.wait(timeout=5)
        time.sleep(0.1)  # Give Bob time to fully register

        # Alice sends
        with client.websocket_connect(f"/ws?token={alice['token']}") as ws_alice:
            ws_alice.send_json(wire)
            ack = ws_alice.receive_json()
            assert ack["type"] == "ack"
            assert ack["delivered"] is True

        bob_thread.join(timeout=5)

        # Bob should have received the message
        assert len(received_messages) == 1
        assert received_messages[0]["from"] == alice["address"]
        assert received_messages[0]["to"] == bob["address"]

    def test_websocket_sender_mismatch(self, client, registered_agent_pair, make_envelope):
        """Sending an envelope with wrong from address returns error."""
        alice, bob = registered_agent_pair
        # Create an envelope where bob is the "from" but alice is connected
        wire = make_envelope(bob, alice)

        with client.websocket_connect(f"/ws?token={alice['token']}") as ws:
            ws.send_json(wire)
            error = ws.receive_json()
            assert error["error"] == "sender_mismatch"

    def test_websocket_unknown_message_type(self, client, registered_agent):
        """Sending an unrecognized message type returns an error."""
        with client.websocket_connect(f"/ws?token={registered_agent['token']}") as ws:
            ws.send_json({"type": "bogus", "data": "test"})
            error = ws.receive_json()
            assert error["error"] == "unknown_message_type"
            assert "bogus" in error["detail"]

    def test_websocket_error_response_shape(self, client, registered_agent_pair, make_envelope):
        """WebSocket errors have consistent {"error": ..., "detail": ...} shape."""
        alice, bob = registered_agent_pair
        wire = make_envelope(bob, alice)

        with client.websocket_connect(f"/ws?token={alice['token']}") as ws:
            ws.send_json(wire)
            error = ws.receive_json()
            assert "error" in error
            assert "detail" in error
