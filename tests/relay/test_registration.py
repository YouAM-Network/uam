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
        """Invalid base64 as public_key is rejected.

        T6.2 (Phase 46): Pydantic ``RegisterRequest.public_key`` now enforces
        ``pattern=_PUBKEY_B64_PATTERN`` so the parse layer 422s before the
        ``deserialize_verify_key`` 400 path can fire. Either rejection is
        acceptable — both are pre-handler rejections of the same bad input.
        """
        resp = client.post("/api/v1/register", json={
            "agent_name": "badkey",
            "public_key": "not-a-valid-key!!!",
        })
        assert resp.status_code in (400, 422)

    def test_register_lowercase_name_round_trip(self, client):
        """Lowercase agent name registers and round-trips into address.

        T6.2 (Phase 46): mixed-case names are now rejected by Pydantic
        (``_AGENT_NAME_PATTERN`` is strictly lowercase). The handler-level
        ``.strip().lower()`` is now defense-in-depth for already-lowercase
        input. Callers MUST send lowercase ``agent_name`` going forward.
        """
        sk, vk = generate_keypair()
        resp = client.post("/api/v1/register", json={
            "agent_name": "myagent",
            "public_key": serialize_verify_key(vk),
        })
        assert resp.status_code == 200
        assert resp.json()["address"] == "myagent::test.local"

    def test_register_mixed_case_name_rejected(self, client):
        """T6.2 (Phase 46): mixed-case agent_name is rejected by Pydantic 422."""
        sk, vk = generate_keypair()
        resp = client.post("/api/v1/register", json={
            "agent_name": "MyAgent",
            "public_key": serialize_verify_key(vk),
        })
        assert resp.status_code == 422

    def test_register_invalid_agent_name(self, client):
        """Agent name with spaces or special chars is rejected.

        T6.2 (Phase 46): Pydantic ``RegisterRequest.agent_name`` now enforces
        ``pattern=_AGENT_NAME_PATTERN`` so the parse layer 422s before
        ``parse_address`` can return 400. Either rejection is acceptable.
        """
        sk, vk = generate_keypair()
        resp = client.post("/api/v1/register", json={
            "agent_name": "bad agent!",
            "public_key": serialize_verify_key(vk),
        })
        assert resp.status_code in (400, 422)

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
        """Error responses have consistent {"error": ..., "detail": ...} shape.

        T6.2 (Phase 46): bad pubkey is now caught at the Pydantic parse layer
        (422 ``validation_error``) rather than the handler ``deserialize_verify_key``
        path (400 ``bad_request``). Both envelopes share the {error, detail}
        shape — that's what this test guards.
        """
        resp = client.post("/api/v1/register", json={
            "agent_name": "badkey",
            "public_key": "not-a-valid-key!!!",
        })
        assert resp.status_code in (400, 422)
        body = resp.json()
        assert "error" in body
        assert "detail" in body
        assert body["error"] in ("bad_request", "validation_error")
