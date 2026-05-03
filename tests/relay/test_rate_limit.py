"""Tests for rate limiting -- unit tests on SlidingWindowCounter and
integration tests on relay endpoints (RELAY-05).

T4.2 (Phase 44 Plan 02): SlidingWindowCounter.check / .remaining /
.cleanup are now async (per-instance asyncio.Lock for atomicity). Unit
tests use ``@pytest.mark.asyncio`` + ``await`` accordingly.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from uam.relay.rate_limit import SlidingWindowCounter


class TestSlidingWindowCounter:
    """Unit tests for the in-memory sliding-window rate limiter."""

    @pytest.mark.asyncio
    async def test_allows_within_limit(self):
        """Requests within the limit all succeed."""
        counter = SlidingWindowCounter(limit=3, window_seconds=60.0)
        assert await counter.check("key") is True
        assert await counter.check("key") is True
        assert await counter.check("key") is True

    @pytest.mark.asyncio
    async def test_blocks_over_limit(self):
        """Fourth request is blocked when limit is 3."""
        counter = SlidingWindowCounter(limit=3, window_seconds=60.0)
        for _ in range(3):
            assert await counter.check("key") is True
        assert await counter.check("key") is False

    @pytest.mark.asyncio
    async def test_window_expiry(self):
        """After the window expires, requests are allowed again."""
        counter = SlidingWindowCounter(limit=2, window_seconds=0.1)
        assert await counter.check("key") is True
        assert await counter.check("key") is True
        assert await counter.check("key") is False  # at limit
        await asyncio.sleep(0.15)  # wait for window to expire
        assert await counter.check("key") is True  # allowed again

    @pytest.mark.asyncio
    async def test_independent_keys(self):
        """Different keys have independent counters."""
        counter = SlidingWindowCounter(limit=1, window_seconds=60.0)
        assert await counter.check("a") is True
        assert await counter.check("a") is False  # a is at limit
        assert await counter.check("b") is True   # b is independent

    @pytest.mark.asyncio
    async def test_remaining_count(self):
        """remaining() decreases as requests are made."""
        counter = SlidingWindowCounter(limit=5, window_seconds=60.0)
        assert await counter.remaining("key") == 5
        await counter.check("key")
        assert await counter.remaining("key") == 4
        await counter.check("key")
        await counter.check("key")
        assert await counter.remaining("key") == 2

    @pytest.mark.asyncio
    async def test_cleanup_removes_expired(self):
        """cleanup() removes keys with no recent events."""
        counter = SlidingWindowCounter(limit=5, window_seconds=0.1)
        await counter.check("old_key")
        await asyncio.sleep(0.15)
        await counter.cleanup()
        assert "old_key" not in counter._buckets

    @pytest.mark.asyncio
    async def test_len_tracks_keys(self):
        """len(counter) returns the number of tracked keys."""
        counter = SlidingWindowCounter(limit=5, window_seconds=60.0)
        assert len(counter) == 0
        await counter.check("a")
        assert len(counter) == 1
        await counter.check("b")
        assert len(counter) == 2

    @pytest.mark.asyncio
    async def test_total_keys_matches_len(self):
        """total_keys() is an alias for len()."""
        counter = SlidingWindowCounter(limit=5, window_seconds=60.0)
        await counter.check("x")
        await counter.check("y")
        assert counter.total_keys() == len(counter) == 2


class TestSenderRateLimitREST:
    """Integration tests for sender rate limiting via REST.

    Note: Adaptive rate limiting (SPAM-04) means new agents at score 30
    get throttled tier (10 msg/min).  We boost reputation to 80+ ("full"
    tier, 60 msg/min) so these tests exercise the base sender limit.
    """

    def _boost_reputation(self, client, address: str, score: int = 80) -> None:
        """Set reputation score directly in the in-memory cache (test-only)."""
        client.app.state.reputation_manager._cache[address] = score

    def test_sender_rate_limit_rest(self, client, registered_agent_pair, make_envelope):
        """Sender is blocked after 60 messages per minute (full-tier agent)."""
        alice, bob = registered_agent_pair
        self._boost_reputation(client, alice["address"])

        for i in range(60):
            wire = make_envelope(alice, bob)
            resp = client.post(
                "/api/v1/send",
                json={"envelope": wire},
                headers={"Authorization": f"Bearer {alice['token']}"},
            )
            assert resp.status_code == 200, f"Message {i+1} failed with {resp.status_code}"

        # 61st message should be rate-limited
        wire = make_envelope(alice, bob)
        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 429
        assert "Sender rate limit" in resp.json()["detail"]


class TestRecipientRateLimitREST:
    """Integration tests for recipient rate limiting via REST.

    Agents are boosted to full-tier reputation so per-sender limits don't
    interfere with the recipient rate limit test.
    """

    def _boost_reputation(self, client, address: str, score: int = 80) -> None:
        """Set reputation score directly in the in-memory cache (test-only)."""
        client.app.state.reputation_manager._cache[address] = score

    def test_recipient_rate_limit_rest(self, client, make_envelope):
        """Recipient is blocked after 100 messages per minute from multiple senders."""
        from uam.protocol import generate_keypair, serialize_verify_key

        # Register 3 agents: alice, bob, charlie. Target = charlie.
        agents = []
        for name in ("alice", "bob", "charlie"):
            sk, vk = generate_keypair()
            pk_str = serialize_verify_key(vk)
            resp = client.post("/api/v1/register", json={
                "agent_name": name,
                "public_key": pk_str,
            })
            assert resp.status_code == 200
            data = resp.json()
            agents.append({
                "address": data["address"],
                "token": data["token"],
                "signing_key": sk,
                "verify_key": vk,
                "public_key_str": pk_str,
            })

        alice, bob, charlie = agents
        # Boost senders to full tier (60 msg/min) so per-sender limits don't block first
        self._boost_reputation(client, alice["address"])
        self._boost_reputation(client, bob["address"])

        # Alice sends 55 messages to charlie
        for i in range(55):
            wire = make_envelope(alice, charlie)
            resp = client.post(
                "/api/v1/send",
                json={"envelope": wire},
                headers={"Authorization": f"Bearer {alice['token']}"},
            )
            assert resp.status_code == 200, f"Alice msg {i+1} failed: {resp.status_code}"

        # Bob sends 45 messages to charlie (total=100 for charlie)
        for i in range(45):
            wire = make_envelope(bob, charlie)
            resp = client.post(
                "/api/v1/send",
                json={"envelope": wire},
                headers={"Authorization": f"Bearer {bob['token']}"},
            )
            assert resp.status_code == 200, f"Bob msg {i+1} failed: {resp.status_code}"

        # 101st message to charlie should be rate-limited
        wire = make_envelope(alice, charlie)
        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 429
        assert "Recipient rate limit" in resp.json()["detail"]


class TestSenderRateLimitWebSocket:
    """Integration tests for sender rate limiting via WebSocket.

    Agents are boosted to full-tier reputation (60 msg/min) so the test
    exercises the base sender limit rather than the throttled tier limit.
    """

    def _boost_reputation(self, client, address: str, score: int = 80) -> None:
        """Set reputation score directly in the in-memory cache (test-only)."""
        client.app.state.reputation_manager._cache[address] = score

    def test_sender_rate_limit_websocket(self, client, registered_agent_pair, make_envelope):
        """Sender is blocked after 60 messages via WebSocket (full-tier agent)."""
        alice, bob = registered_agent_pair
        self._boost_reputation(client, alice["address"])

        with client.websocket_connect(f"/ws?token={alice['token']}") as ws:
            for i in range(60):
                wire = make_envelope(alice, bob)
                ws.send_json(wire)
                resp = ws.receive_json()
                assert resp["type"] == "ack", f"Message {i+1}: expected ack, got {resp}"

            # 61st message should be rate-limited
            wire = make_envelope(alice, bob)
            ws.send_json(wire)
            resp = ws.receive_json()
            assert resp["error"] == "rate_limited"
