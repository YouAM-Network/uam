"""Tests for POST /api/v1/register endpoint."""

from __future__ import annotations

import pytest

from uam.protocol import generate_keypair, serialize_verify_key


class TestRegistration:
    """Agent registration tests."""

    def test_register_agent(self, client):
        """POST with valid agent_name and public_key succeeds."""
        sk, vk = generate_keypair()
        resp = client.post("/api/v1/register", json={
            "agent_name": "alice",
            "public_key": serialize_verify_key(vk),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "address" in data
        assert "token" in data
        assert "relay" in data
        assert data["address"] == "alice::test.local"

    def test_register_returns_token(self, client):
        """Returned token is a non-empty string of sufficient length."""
        sk, vk = generate_keypair()
        resp = client.post("/api/v1/register", json={
            "agent_name": "keytest",
            "public_key": serialize_verify_key(vk),
        })
        assert resp.status_code == 200
        token = resp.json()["token"]
        assert isinstance(token, str)
        assert len(token) >= 32

    def test_register_duplicate_address(self, client):
        """Registering the same agent name twice returns 409."""
        sk, vk = generate_keypair()
        pk_str = serialize_verify_key(vk)
        resp1 = client.post("/api/v1/register", json={
            "agent_name": "dupetest",
            "public_key": pk_str,
        })
        assert resp1.status_code == 200

        # Second registration with same name (different key is fine, name collision matters)
        sk2, vk2 = generate_keypair()
        resp2 = client.post("/api/v1/register", json={
            "agent_name": "dupetest",
            "public_key": serialize_verify_key(vk2),
        })
        assert resp2.status_code == 409

    def test_register_invalid_public_key(self, client):
        """Invalid base64 as public_key returns 400."""
        resp = client.post("/api/v1/register", json={
            "agent_name": "badkey",
            "public_key": "not-a-valid-key!!!",
        })
        assert resp.status_code == 400

    def test_register_normalizes_name(self, client):
        """Mixed case agent name is normalized to lowercase."""
        sk, vk = generate_keypair()
        resp = client.post("/api/v1/register", json={
            "agent_name": "MyAgent",
            "public_key": serialize_verify_key(vk),
        })
        assert resp.status_code == 200
        assert resp.json()["address"] == "myagent::test.local"

    def test_register_invalid_agent_name(self, client):
        """Agent name with spaces or special chars fails address validation."""
        sk, vk = generate_keypair()
        resp = client.post("/api/v1/register", json={
            "agent_name": "bad agent!",
            "public_key": serialize_verify_key(vk),
        })
        assert resp.status_code == 400

    def test_register_rate_limit(self, client):
        """Registration is rate limited to 5/min per IP."""
        for i in range(5):
            sk, vk = generate_keypair()
            resp = client.post("/api/v1/register", json={
                "agent_name": f"ratelimit{i}",
                "public_key": serialize_verify_key(vk),
            })
            assert resp.status_code == 200, f"Registration {i+1} failed: {resp.status_code}"

        # 6th registration should be rate-limited
        sk, vk = generate_keypair()
        resp = client.post("/api/v1/register", json={
            "agent_name": "ratelimit5",
            "public_key": serialize_verify_key(vk),
        })
        assert resp.status_code == 429
        assert "rate limit" in resp.json()["detail"].lower()

    def test_error_response_shape(self, client):
        """Error responses have consistent {"error": ..., "detail": ...} shape."""
        resp = client.post("/api/v1/register", json={
            "agent_name": "badkey",
            "public_key": "not-a-valid-key!!!",
        })
        assert resp.status_code == 400
        body = resp.json()
        assert "error" in body
        assert "detail" in body
        assert body["error"] == "bad_request"
