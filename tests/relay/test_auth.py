"""Tests for authentication enforcement across all relay endpoints (SEC-02)."""

from __future__ import annotations

import pytest


class TestHTTPAuth:
    """HTTP Bearer token authentication tests."""

    def test_send_without_auth(self, client, registered_agent_pair, make_envelope):
        """POST /send with no Authorization header returns 401."""
        alice, bob = registered_agent_pair
        wire = make_envelope(alice, bob)
        resp = client.post("/api/v1/send", json={"envelope": wire})
        assert resp.status_code == 401

    def test_send_with_invalid_bearer(self, client):
        """POST /send with an invalid Bearer token returns 401."""
        resp = client.post(
            "/api/v1/send",
            json={"envelope": {}},
            headers={"Authorization": "Bearer invalid-key-123"},
        )
        assert resp.status_code == 401

    def test_inbox_without_auth(self, client, registered_agent):
        """GET /inbox/{address} without auth returns 401."""
        resp = client.get(f"/api/v1/inbox/{registered_agent['address']}")
        assert resp.status_code == 401

    def test_inbox_with_invalid_bearer(self, client, registered_agent):
        """GET /inbox/{address} with invalid Bearer token returns 401."""
        resp = client.get(
            f"/api/v1/inbox/{registered_agent['address']}",
            headers={"Authorization": "Bearer invalid-key-123"},
        )
        assert resp.status_code == 401

    def test_public_key_no_auth_required(self, client, registered_agent):
        """GET /agents/{address}/public-key works without auth (public endpoint).

        This endpoint is intentionally unauthenticated so agents can look
        up a recipient's public key before the first message (handshake).
        """
        resp = client.get(f"/api/v1/agents/{registered_agent['address']}/public-key")
        assert resp.status_code == 200

    def test_register_no_auth_required(self, client):
        """POST /register works without auth (public endpoint)."""
        from uam.protocol import generate_keypair, serialize_verify_key

        sk, vk = generate_keypair()
        resp = client.post("/api/v1/register", json={
            "agent_name": "noauth",
            "public_key": serialize_verify_key(vk),
        })
        assert resp.status_code == 200

    def test_health_no_auth_required(self, client):
        """GET /health works without auth."""
        resp = client.get("/health")
        assert resp.status_code == 200


class TestWebSocketAuth:
    """WebSocket token authentication tests."""

    def test_websocket_no_token(self, client):
        """Connecting to /ws without ?token= rejects the connection."""
        # FastAPI requires the query param, so this will raise
        with pytest.raises(Exception):
            with client.websocket_connect("/ws"):
                pass

    def test_websocket_invalid_token(self, client):
        """Connecting with an invalid token closes with code 1008."""
        with pytest.raises(Exception):
            with client.websocket_connect("/ws?token=bad-key-12345"):
                pass

    def test_websocket_valid_token(self, client, registered_agent):
        """Connecting with a valid token accepts the connection."""
        with client.websocket_connect(f"/ws?token={registered_agent['token']}"):
            pass  # Connection accepted successfully
