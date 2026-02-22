"""Integration tests for spam defense in the message pipeline.

Tests verify that spam defense checks actually affect the send and
registration flows:
- Blocked senders are rejected (SPAM-01)
- Allowlisted senders bypass reputation limits (SPAM-01)
- Low reputation senders are rejected (SPAM-06)
- Adaptive rate limiting applies by tier (SPAM-04)
- Domain rate limiting (SPAM-03)
- Relay domain exemption from domain limits (SPAM-03)
- Registration blocklist check (SPAM-01)
- Registration initializes reputation (SPAM-02)
- WebSocket blocked sender rejected (SPAM-01)
"""

from __future__ import annotations

import pytest

from tests.relay.conftest import _make_envelope

from uam.protocol import generate_keypair, serialize_verify_key


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _register(client, name: str = "testbot") -> dict:
    """Register an agent and return {address, token, signing_key, verify_key}."""
    sk, vk = generate_keypair()
    pk_str = serialize_verify_key(vk)
    resp = client.post("/api/v1/register", json={
        "agent_name": name,
        "public_key": pk_str,
    })
    assert resp.status_code == 200, f"Registration failed: {resp.text}"
    data = resp.json()
    return {
        "address": data["address"],
        "token": data["token"],
        "signing_key": sk,
        "verify_key": vk,
        "public_key_str": pk_str,
    }


def _boost(client, address: str, score: int = 80) -> None:
    """Set reputation score via in-memory cache (test-only)."""
    client.app.state.reputation_manager._cache[address] = score


def _send(client, sender: dict, recipient: dict) -> object:
    """Send a message from sender to recipient, return the response."""
    wire = _make_envelope(sender, recipient)
    return client.post(
        "/api/v1/send",
        json={"envelope": wire},
        headers={"Authorization": f"Bearer {sender['token']}"},
    )


# ---------------------------------------------------------------------------
# Blocklist in send pipeline (SPAM-01)
# ---------------------------------------------------------------------------


class TestBlocklistPipeline:
    """Tests for blocklist enforcement in the send and registration flows."""

    def test_send_blocked_sender_rejected(self, client, registered_agent_pair, make_envelope):
        """Blocked sender gets 403 on send."""
        alice, bob = registered_agent_pair
        _boost(client, alice["address"])  # ensure not rate-limited

        # Block alice
        client.app.state.spam_filter._blocked_exact.add(alice["address"])

        wire = make_envelope(alice, bob)
        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 403
        assert "blocked" in resp.json()["detail"].lower()

    def test_send_domain_blocked_sender_rejected(self, client, registered_agent_pair, make_envelope):
        """Sender on a blocked domain gets 403."""
        alice, bob = registered_agent_pair
        _boost(client, alice["address"])

        # Block the entire test.local domain
        client.app.state.spam_filter._blocked_domains.add("test.local")

        wire = make_envelope(alice, bob)
        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 403

    def test_register_blocked_domain_rejected(self, client):
        """Registration with a blocklisted domain is rejected with 403."""
        # Block *::test.local (the relay domain used in tests)
        client.app.state.spam_filter._blocked_domains.add("test.local")

        sk, vk = generate_keypair()
        pk_str = serialize_verify_key(vk)
        resp = client.post("/api/v1/register", json={
            "agent_name": "blockedbot",
            "public_key": pk_str,
        })
        assert resp.status_code == 403
        assert "blocked" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Allowlist bypass (SPAM-01)
# ---------------------------------------------------------------------------


class TestAllowlistPipeline:
    """Tests for allowlist bypass of reputation-based limits."""

    def test_send_allowlisted_sender_bypasses_reputation(self, client):
        """Allowlisted sender with low reputation can still send."""
        alice = _register(client, "allowvip")
        bob = _register(client, "allowrec")

        # Set alice to very low reputation (normally would be blocked)
        _boost(client, alice["address"], score=5)  # blocked tier
        # But add her to allowlist
        client.app.state.spam_filter._allowed_exact.add(alice["address"])

        resp = _send(client, alice, bob)
        # Should succeed because allowlisted senders bypass reputation checks
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Reputation in send pipeline (SPAM-06)
# ---------------------------------------------------------------------------


class TestReputationPipeline:
    """Tests for reputation enforcement in the send flow."""

    def test_send_low_reputation_rejected(self, client):
        """Sender with score <20 gets 403 (reputation too low)."""
        alice = _register(client, "lowrep")
        bob = _register(client, "lowreprec")

        # Set alice to blocked tier
        _boost(client, alice["address"], score=10)

        resp = _send(client, alice, bob)
        assert resp.status_code == 403
        assert "reputation" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Adaptive rate limiting (SPAM-04)
# ---------------------------------------------------------------------------


class TestAdaptiveRateLimit:
    """Tests for reputation-based adaptive rate limits."""

    def test_send_adaptive_rate_limit_by_tier(self, client):
        """Throttled-tier agent (score=25, limit=10) is rate limited after 10 messages."""
        alice = _register(client, "throttled")
        bob = _register(client, "throttlerec")

        # Score 25 = throttled tier, limit=10 msg/min
        _boost(client, alice["address"], score=25)
        _boost(client, bob["address"], score=80)  # ensure bob isn't blocking us

        # First 10 should pass
        for i in range(10):
            resp = _send(client, alice, bob)
            assert resp.status_code == 200, f"Message {i+1} failed: {resp.status_code} {resp.text}"

        # 11th should be rate limited
        resp = _send(client, alice, bob)
        assert resp.status_code == 429
        assert "rate limit" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Domain rate limiting (SPAM-03)
# ---------------------------------------------------------------------------


class TestDomainRateLimit:
    """Tests for per-domain rate limiting."""

    def test_send_relay_domain_exempt_from_domain_limit(self, client):
        """Agents on the relay domain (test.local) are exempt from domain rate limits."""
        alice = _register(client, "relayagent")
        bob = _register(client, "relayrecip")
        _boost(client, alice["address"])

        # Set a very low domain limit
        client.app.state.domain_limiter = __import__(
            "uam.relay.rate_limit", fromlist=["SlidingWindowCounter"]
        ).SlidingWindowCounter(limit=1, window_seconds=60.0)

        # Alice is on test.local (the relay domain) -- should be exempt
        resp = _send(client, alice, bob)
        assert resp.status_code == 200
        resp2 = _send(client, alice, bob)
        assert resp2.status_code == 200  # not 429; relay domain is exempt


# ---------------------------------------------------------------------------
# Registration reputation initialization (SPAM-02)
# ---------------------------------------------------------------------------


class TestRegistrationReputation:
    """Tests for reputation initialization during registration."""

    def test_register_initializes_reputation(self, client):
        """Register agent, verify reputation score is 30 (default)."""
        agent = _register(client, "newreg")
        score = client.app.state.reputation_manager.get_score(agent["address"])
        assert score == 30

    def test_register_reputation_tier_is_throttled(self, client):
        """New agent with default score 30 is in throttled tier."""
        agent = _register(client, "tiered")
        tier = client.app.state.reputation_manager.get_tier(agent["address"])
        assert tier == "throttled"


# ---------------------------------------------------------------------------
# WebSocket blocked sender (SPAM-01)
# ---------------------------------------------------------------------------


class TestWSBlockedSender:
    """Tests for blocklist enforcement on WebSocket connections."""

    def test_ws_blocked_sender_rejected(self, client, registered_agent_pair, make_envelope):
        """Blocked sender's WebSocket message returns error."""
        alice, bob = registered_agent_pair
        _boost(client, alice["address"])

        with client.websocket_connect(f"/ws?token={alice['token']}") as ws:
            # Block alice after she's connected
            client.app.state.spam_filter._blocked_exact.add(alice["address"])

            wire = make_envelope(alice, bob)
            ws.send_json(wire)
            resp = ws.receive_json()
            assert resp["error"] == "blocked"

    def test_ws_blocked_sender_at_connect_time(self, client, registered_agent_pair):
        """Blocked sender is rejected at WebSocket connection time (code 1008)."""
        from starlette.websockets import WebSocketDisconnect

        alice, bob = registered_agent_pair

        # Block alice before connection attempt
        client.app.state.spam_filter._blocked_exact.add(alice["address"])

        # WebSocket connection should be rejected with 1008
        with pytest.raises(WebSocketDisconnect) as exc_info:
            with client.websocket_connect(f"/ws?token={alice['token']}"):
                pass  # should not reach here
        assert exc_info.value.code == 1008
