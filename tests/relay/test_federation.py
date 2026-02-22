"""Tests for POST /api/v1/federation/deliver stub endpoint (RELAY-07)."""

from __future__ import annotations


class TestFederationStub:
    """Federation stub endpoint tests."""

    def test_federation_returns_501(self, client):
        """POST /federation/deliver returns 501 Not Implemented."""
        resp = client.post("/api/v1/federation/deliver")
        assert resp.status_code == 501

    def test_federation_response_body(self, client):
        """Response body contains the expected not_implemented status."""
        resp = client.post("/api/v1/federation/deliver")
        data = resp.json()
        assert data["status"] == "not_implemented"
        assert "Federation" in data["detail"] or "not yet" in data["detail"]

    def test_federation_no_auth_required(self, client):
        """POST without auth returns 501 (not 401/403)."""
        resp = client.post("/api/v1/federation/deliver")
        assert resp.status_code == 501  # not an auth error
