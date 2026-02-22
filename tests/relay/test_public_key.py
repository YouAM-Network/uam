"""Tests for GET /api/v1/agents/{address}/public-key endpoint.

This endpoint is unauthenticated so that any agent can look up
another's public key before the first message (handshake.request).
"""

from __future__ import annotations


class TestPublicKey:
    """Public key lookup tests."""

    def test_get_public_key(self, client, registered_agent):
        """GET returns the correct public key for a registered agent."""
        address = registered_agent["address"]
        resp = client.get(f"/api/v1/agents/{address}/public-key")
        assert resp.status_code == 200
        data = resp.json()
        assert data["address"] == address
        assert data["public_key"] == registered_agent["public_key_str"]

    def test_get_public_key_not_found(self, client, registered_agent):
        """GET for a non-existent address returns 404."""
        resp = client.get("/api/v1/agents/nobody::test.local/public-key")
        assert resp.status_code == 404

    def test_no_auth_required(self, client, registered_agent):
        """Endpoint works without any Authorization header."""
        address = registered_agent["address"]
        resp = client.get(f"/api/v1/agents/{address}/public-key")
        assert resp.status_code == 200
