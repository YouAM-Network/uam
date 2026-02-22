"""Tests for GET /api/v1/inbox/{address} endpoint."""

from __future__ import annotations


class TestInbox:
    """Inbox retrieval tests."""

    def test_inbox_empty(self, client, registered_agent):
        """Empty inbox returns count=0 and no messages."""
        address = registered_agent["address"]
        resp = client.get(
            f"/api/v1/inbox/{address}",
            headers={"Authorization": f"Bearer {registered_agent['token']}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["count"] == 0
        assert data["messages"] == []

    def test_inbox_returns_stored_messages(self, client, registered_agent_pair, make_envelope):
        """Inbox contains messages sent to an offline agent."""
        alice, bob = registered_agent_pair
        wire = make_envelope(alice, bob)

        # Send while bob is offline
        send_resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert send_resp.status_code == 200
        assert send_resp.json()["delivered"] is False

        # Check bob's inbox
        inbox_resp = client.get(
            f"/api/v1/inbox/{bob['address']}",
            headers={"Authorization": f"Bearer {bob['token']}"},
        )
        assert inbox_resp.status_code == 200
        data = inbox_resp.json()
        assert data["count"] == 1
        assert len(data["messages"]) == 1
        # Envelope should have the original structure
        assert data["messages"][0]["from"] == alice["address"]

    def test_inbox_marks_delivered(self, client, registered_agent_pair, make_envelope):
        """Fetching inbox marks messages as delivered -- second fetch is empty."""
        alice, bob = registered_agent_pair
        wire = make_envelope(alice, bob)

        client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )

        # First fetch: should have 1 message
        resp1 = client.get(
            f"/api/v1/inbox/{bob['address']}",
            headers={"Authorization": f"Bearer {bob['token']}"},
        )
        assert resp1.json()["count"] == 1

        # Second fetch: should be empty (marked as delivered)
        resp2 = client.get(
            f"/api/v1/inbox/{bob['address']}",
            headers={"Authorization": f"Bearer {bob['token']}"},
        )
        assert resp2.json()["count"] == 0

    def test_inbox_respects_limit(self, client, registered_agent_pair, make_envelope):
        """Limit parameter restricts the number of messages returned."""
        alice, bob = registered_agent_pair

        # Send 3 messages
        for _ in range(3):
            wire = make_envelope(alice, bob)
            client.post(
                "/api/v1/send",
                json={"envelope": wire},
                headers={"Authorization": f"Bearer {alice['token']}"},
            )

        # Fetch with limit=1
        resp = client.get(
            f"/api/v1/inbox/{bob['address']}?limit=1",
            headers={"Authorization": f"Bearer {bob['token']}"},
        )
        assert resp.json()["count"] == 1

    def test_inbox_forbidden_other_agent(self, client, registered_agent_pair):
        """Agent A cannot read agent B's inbox."""
        alice, bob = registered_agent_pair

        resp = client.get(
            f"/api/v1/inbox/{bob['address']}",
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 403
