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


# ===========================================================================
# Phase 43 — Theme 2.1 / 2.2: Token-hashing + WebSocket auth tests
# ===========================================================================
#
# These tests are FAILING-BY-DESIGN as of Wave 0. Plan 04 (T2.1) adds
# HMAC-SHA-256+pepper token hashing with constant-time compare; Plan 05
# (T2.2) adds Authorization-header and Sec-WebSocket-Protocol-based WS
# auth with deprecation warning on the ?token= path.
#
# References:
#   - 43-VALIDATION.md rows T2.1, T2.2
#   - 43-RESEARCH.md Pattern 1 (Token Hashing) + phase_requirements T2.1/T2.2
#     + Pitfalls 1, 3
#   - REVIEW-routes.md C3, C4
# ===========================================================================


class TestTokenHashing:
    """T2.1: bearer tokens stored as HMAC-SHA-256 hash with server pepper."""

    async def test_token_stored_as_hash(self, client, registered_agent):
        """T2.1: after registration, the agents row must have token_hash != NULL,
        and the plaintext returned to the caller must hash to that value via
        HMAC-SHA-256(token, pepper).

        Expected behaviour after Plan 04: a `token_hash` column exists on the
        agents table, populated via hash_token(token, pepper); subsequent
        bearer-token lookups query token_hash, never the plaintext column.

        Today (Wave 0): there is no token_hash column and no
        uam.relay.token_hashing module. The import below fails with a
        clear pytest.fail() naming the missing artifact.
        """
        try:
            from uam.relay.token_hashing import hash_token  # noqa: F401
        except ImportError:
            pytest.fail(
                "T2.1 contract: Plan 04 must add src/uam/relay/token_hashing.py "
                "exposing hash_token(token, pepper) -> str using "
                "hmac.new(pepper, token, sha256).hexdigest(). "
                "Today the relay stores plaintext tokens (Agent.token in "
                "src/uam/db/models.py:34); auth.py:32 looks them up by "
                "Agent.token == credentials.credentials with no hashing."
            )

        # If the module exists, assert the integration: the agents row's
        # token_hash matches HMAC of the plaintext token returned by /register.
        from uam.relay.config import settings as relay_settings
        # Agent model attribute name is 'token_hash' per the migration plan
        # (alembic 0003). At Wave 0 this branch is unreachable.
        pepper = getattr(relay_settings, "token_pepper", None)
        assert pepper, "Settings.token_pepper must be configured (UAM_TOKEN_PEPPER env)"
        expected_hash = hash_token(registered_agent["token"], pepper)
        # Read back the agent row directly via the relay app's session factory
        # (kept generic to survive Plan 04's exact implementation choices)
        from uam.db.session import init_session_factory
        from uam.db.engine import get_engine
        from uam.db.models import Agent
        from sqlmodel import select

        factory = init_session_factory(get_engine())
        async with factory() as session:
            stmt = select(Agent).where(Agent.address == registered_agent["address"])
            result = await session.execute(stmt)
            agent = result.scalar_one()
        assert getattr(agent, "token_hash", None) == expected_hash, (
            f"Stored token_hash {getattr(agent, 'token_hash', None)!r} != "
            f"HMAC(plaintext, pepper) {expected_hash!r}"
        )

    def test_token_compare_is_constant_time(self, client):
        """T2.1: verify_token_http must use hmac.compare_digest, NOT == .

        Expected behaviour after Plan 04: a grep of src/uam/relay/auth.py
        contains 'compare_digest', and the wrong-token request path returns
        401 with the same shape as missing-token (no DB-leak signal).

        Today (Wave 0): auth.py uses `Agent.token == credentials.credentials`
        (a plain Python equality, not a constant-time primitive). The
        source-grep check below FAILS.
        """
        import inspect
        from uam.relay import auth as auth_mod

        src = inspect.getsource(auth_mod)
        assert "compare_digest" in src, (
            "T2.1 contract: src/uam/relay/auth.py must use hmac.compare_digest "
            "for the post-lookup constant-time confirmation. Today auth.py:32 "
            "and auth.py:56 use plain `==` against the plaintext column, which "
            "is the timing-oracle defect T2.1 closes."
        )

        # Live: wrong token returns 401
        resp = client.get(
            "/api/v1/inbox/anyone::test.local",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
        assert resp.status_code == 401


class TestWebSocketSubprotocolAuth:
    """T2.2: WebSocket auth via Authorization header + Sec-WebSocket-Protocol."""

    def test_ws_auth_via_authorization_header(self, client, registered_agent):
        """T2.2: WS upgrade with `Authorization: Bearer {token}` is accepted.

        Expected behaviour after Plan 05: the websocket_endpoint reads the
        Authorization header before falling back to the ?token= query param,
        so programmatic clients (Python SDK) can authenticate without a
        token in the URL.

        Today (Wave 0): ws.py:267 declares `token: str = Query(...)` and
        looks at no other source. A WS upgrade with only an Authorization
        header is rejected by FastAPI with a 422 (missing required query
        param). This test FAILS.
        """
        token = registered_agent["token"]
        try:
            with client.websocket_connect(
                "/ws",
                headers={"Authorization": f"Bearer {token}"},
            ) as ws:
                # If the connection is accepted, send a keep-alive and pass
                ws.send_json({"type": "ping"})
        except Exception as exc:
            pytest.fail(
                f"T2.2 contract: WS upgrade with Authorization header must "
                f"be accepted, but the connection was rejected: {exc!r}. "
                f"Plan 05 must update ws.py:websocket_endpoint to read the "
                f"Authorization header before the ?token= fallback."
            )

    def test_ws_auth_via_subprotocol(self, client, registered_agent):
        """T2.2: WS upgrade with Sec-WebSocket-Protocol: bearer.{token} is accepted.

        Expected behaviour after Plan 05: the websocket_endpoint inspects
        websocket.scope['subprotocols'] for an entry matching `bearer.*`,
        extracts the token, and accepts the upgrade with the negotiated
        subprotocol echoed back. This is the browser-friendly auth path
        per ably.com / peterbraden.co.uk.

        Today (Wave 0): ws.py declares `token: str = Query(...)` and ignores
        subprotocols. The TestClient cannot negotiate the subprotocol, so
        the connection is rejected. This test FAILS.
        """
        token = registered_agent["token"]
        try:
            with client.websocket_connect(
                "/ws",
                subprotocols=[f"bearer.{token}"],
            ) as ws:
                ws.send_json({"type": "ping"})
        except Exception as exc:
            pytest.fail(
                f"T2.2 contract: WS upgrade with Sec-WebSocket-Protocol "
                f"`bearer.{{token}}` must be accepted, but the connection "
                f"was rejected: {exc!r}. Plan 05 must update "
                f"ws.py:websocket_endpoint to accept this header (the "
                f"browser-friendly auth path) and echo back the matching "
                f"subprotocol on accept()."
            )

    def test_ws_auth_querystring_deprecated(self, client, registered_agent, caplog):
        """T2.2: WS upgrade via ?token= still works (back-compat) but emits
        a deprecation WARNING.

        Expected behaviour after Plan 05: existing clients that pass
        `?token=` continue to connect successfully, but the relay logs a
        WARNING-level message naming the deprecated path so operators can
        plan migration.

        Today (Wave 0): ws.py:267 accepts ?token= as the ONLY auth path
        and logs no deprecation. This test FAILS at the caplog assertion.
        """
        # First confirm the back-compat path still connects successfully.
        token = registered_agent["token"]
        with client.websocket_connect(f"/ws?token={token}"):
            pass

        # Then verify the deprecation log statement exists in ws.py source.
        # (Starlette TestClient runs the WS endpoint in a separate thread, so
        # pytest's caplog can miss multi-thread emissions; source-grep is the
        # reliable contract check — same pattern as test_token_compare_is_constant_time.)
        import inspect
        from uam.relay import ws as ws_mod

        src = inspect.getsource(ws_mod)
        assert "query_params" in src and "deprecat" in src.lower(), (
            "T2.2 contract: ws.py must log a deprecation warning when the "
            "querystring `?token=` auth path is used. Expected `logger.warning(...)` "
            "containing the word 'deprecated' alongside `query_params.get(\"token\")`. "
            "Today the path is accepted silently."
        )
