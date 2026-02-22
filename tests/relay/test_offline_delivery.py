"""Tests for offline message storage and delivery on reconnect (RELAY-03)."""

from __future__ import annotations


class TestOfflineDelivery:
    """Store-and-forward message delivery tests."""

    def test_stored_messages_delivered_on_reconnect(self, client, registered_agent_pair, make_envelope):
        """Messages stored for an offline agent are delivered when they connect via WebSocket.

        This is the core RELAY-03 test.
        """
        alice, bob = registered_agent_pair
        wire = make_envelope(alice, bob)

        # Send while bob is offline
        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 200
        assert resp.json()["delivered"] is False

        # Bob connects via WebSocket and should receive stored message
        with client.websocket_connect(f"/ws?token={bob['token']}") as ws:
            msg = ws.receive_json()
            assert msg["from"] == alice["address"]
            assert msg["to"] == bob["address"]
            assert "uam_version" in msg

    def test_multiple_stored_messages_delivered(self, client, registered_agent_pair, make_envelope):
        """Multiple stored messages are all delivered in order on reconnect."""
        alice, bob = registered_agent_pair

        # Send 3 messages while bob is offline
        for _ in range(3):
            wire = make_envelope(alice, bob)
            resp = client.post(
                "/api/v1/send",
                json={"envelope": wire},
                headers={"Authorization": f"Bearer {alice['token']}"},
            )
            assert resp.status_code == 200

        # Bob connects and receives all 3
        with client.websocket_connect(f"/ws?token={bob['token']}") as ws:
            received = []
            for _ in range(3):
                msg = ws.receive_json()
                received.append(msg)

            assert len(received) == 3
            # All are from alice to bob
            for msg in received:
                assert msg["from"] == alice["address"]
                assert msg["to"] == bob["address"]

            # Order should match send order (by message_id which is UUIDv7, monotonic)
            ids = [m["message_id"] for m in received]
            assert ids == sorted(ids)

    def test_stored_messages_cleared_after_delivery(self, client, registered_agent_pair, make_envelope):
        """Stored messages are not re-delivered on a second WebSocket connection."""
        alice, bob = registered_agent_pair
        wire = make_envelope(alice, bob)

        # Send while bob is offline
        client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )

        # First connection: bob gets the message
        with client.websocket_connect(f"/ws?token={bob['token']}") as ws:
            msg = ws.receive_json()
            assert msg["from"] == alice["address"]

        # Second connection: no messages should be delivered
        # Also verify inbox is empty
        inbox_resp = client.get(
            f"/api/v1/inbox/{bob['address']}",
            headers={"Authorization": f"Bearer {bob['token']}"},
        )
        assert inbox_resp.json()["count"] == 0
