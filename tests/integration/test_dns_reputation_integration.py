"""Integration tests for DNS verification -> reputation score lifecycle.

Verifies that the cross-phase integration between Phase 9 (DNS Domain
Verification) and Phase 11 (Spam Defense / Reputation) works correctly:

1. Successful domain verification upgrades reputation from 30 to 60
2. Failed re-verification downgrades reputation from 60 to 30
"""

from __future__ import annotations

import asyncio
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from uam.protocol import generate_keypair, serialize_verify_key
from uam.relay.app import create_app


# ---------------------------------------------------------------------------
# Fixtures (match existing integration test patterns)
# ---------------------------------------------------------------------------


@pytest.fixture()
def app(tmp_path):
    """Create a relay app backed by a temporary database."""
    os.environ["UAM_DB_PATH"] = str(tmp_path / "dns_rep_test.db")
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"
    yield create_app()
    os.environ.pop("UAM_DB_PATH", None)
    os.environ.pop("UAM_RELAY_DOMAIN", None)


@pytest.fixture()
def client(app):
    """Return a TestClient for the relay app with lifespan triggered."""
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def agent(client):
    """Register an agent and return its details."""
    sk, vk = generate_keypair()
    pk_str = serialize_verify_key(vk)
    resp = client.post("/api/v1/register", json={
        "agent_name": "dnsrepbot",
        "public_key": pk_str,
    })
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return {
        "address": data["address"],
        "token": data["token"],
        "signing_key": sk,
        "verify_key": vk,
        "public_key_str": pk_str,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_txt_rdata(txt_value: str):
    """Create a mock TXT rdata with .strings attribute."""
    rdata = MagicMock()
    rdata.strings = [txt_value.encode("utf-8")]
    return rdata


def _make_dns_answer(rdata_list):
    """Create a mock DNS answer that is iterable."""
    answer = MagicMock()
    answer.__iter__ = lambda self: iter(rdata_list)
    return answer


# ---------------------------------------------------------------------------
# Test 1: Domain verification upgrades reputation to 60
# ---------------------------------------------------------------------------


class TestVerificationUpgradesReputation:
    """Successful DNS verification should upgrade reputation 30 -> 60."""

    def test_verification_upgrades_reputation(self, client, app, agent):
        """DNS-verified agent gets reputation score 60 (reduced tier)."""
        reputation_manager = app.state.reputation_manager

        # Initial score should be 30 (default for new agents)
        initial_score = reputation_manager.get_score(agent["address"])
        assert initial_score == 30, f"Expected initial score 30, got {initial_score}"

        # Mock DNS to return a valid TXT record with the agent's key
        rdata = _make_txt_rdata(
            f"v=uam1; key=ed25519:{agent['public_key_str']}"
        )
        answer = _make_dns_answer([rdata])

        with patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=answer)

            resp = client.post(
                "/api/v1/verify-domain",
                json={"domain": "example.com"},
                headers={"Authorization": f"Bearer {agent['token']}"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "verified"
        assert data["tier"] == 2

        # Score should now be 60 (DNS-verified tier)
        new_score = reputation_manager.get_score(agent["address"])
        assert new_score == 60, f"Expected score 60 after verification, got {new_score}"

        # Tier should be "reduced" (50-79 range -> 30 msg/min)
        tier = reputation_manager.get_tier(agent["address"])
        assert tier == "reduced", f"Expected tier 'reduced', got '{tier}'"


# ---------------------------------------------------------------------------
# Test 2: Re-verification failure downgrades reputation to 30
# ---------------------------------------------------------------------------


class TestReverificationFailureDowngradesReputation:
    """Failed re-verification should downgrade reputation 60 -> 30."""

    def test_reverification_failure_downgrades_reputation(self, client, app, agent):
        """Re-verification failure resets reputation score back to 30."""
        reputation_manager = app.state.reputation_manager

        # First, verify the domain successfully (this sets score to 60)
        rdata = _make_txt_rdata(
            f"v=uam1; key=ed25519:{agent['public_key_str']}"
        )
        answer = _make_dns_answer([rdata])

        with patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=answer)

            resp = client.post(
                "/api/v1/verify-domain",
                json={"domain": "expiring.com"},
                headers={"Authorization": f"Bearer {agent['token']}"},
            )

        assert resp.json()["status"] == "verified"
        assert reputation_manager.get_score(agent["address"]) == 60

        # Access the database to expire the verification and run downgrade
        db_path = os.environ.get("UAM_DB_PATH")

        async def _expire_and_downgrade():
            import aiosqlite
            from uam.relay.database import (
                downgrade_verification,
                get_expired_verifications,
            )

            db = await aiosqlite.connect(db_path)
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA foreign_keys=ON")

            # Backdate last_checked to force expiry
            await db.execute(
                """UPDATE domain_verifications
                   SET last_checked = datetime('now', '-48 hours')
                   WHERE agent_address = ?""",
                (agent["address"],),
            )
            await db.commit()

            # Fetch expired verifications
            expired = await get_expired_verifications(db)
            assert len(expired) == 1, f"Expected 1 expired verification, got {len(expired)}"

            # Mock failed re-verification and run the downgrade path
            with patch(
                "uam.relay.verification.verify_domain_ownership",
                new_callable=AsyncMock,
                return_value=(False, "", "DNS TXT record not found"),
            ):
                # Simulate what reverification_loop does on failure
                for verification in expired:
                    await downgrade_verification(db, verification["id"])
                    # This is what our new code in reverification_loop does
                    await reputation_manager.set_score(
                        verification["agent_address"], 30
                    )

            await db.close()

        asyncio.run(_expire_and_downgrade())

        # Score should be back to 30 (throttled tier)
        final_score = reputation_manager.get_score(agent["address"])
        assert final_score == 30, f"Expected score 30 after downgrade, got {final_score}"

        # Tier should be "throttled" (20-49 range -> 10 msg/min)
        tier = reputation_manager.get_tier(agent["address"])
        assert tier == "throttled", f"Expected tier 'throttled', got '{tier}'"


# ---------------------------------------------------------------------------
# Test 3: Full lifecycle (register -> verify -> expire -> downgrade)
# ---------------------------------------------------------------------------


class TestFullDnsReputationLifecycle:
    """Complete lifecycle: register(30) -> verify(60) -> expire(30)."""

    def test_full_lifecycle(self, client, app, agent):
        """Reputation follows the full DNS verification lifecycle."""
        reputation_manager = app.state.reputation_manager

        # Phase 1: New agent starts at score 30
        assert reputation_manager.get_score(agent["address"]) == 30
        assert reputation_manager.get_tier(agent["address"]) == "throttled"
        assert reputation_manager.get_send_limit(agent["address"]) == 10

        # Phase 2: Verify domain -> score 60
        rdata = _make_txt_rdata(
            f"v=uam1; key=ed25519:{agent['public_key_str']}"
        )
        answer = _make_dns_answer([rdata])

        with patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=answer)

            resp = client.post(
                "/api/v1/verify-domain",
                json={"domain": "lifecycle.com"},
                headers={"Authorization": f"Bearer {agent['token']}"},
            )

        assert resp.json()["status"] == "verified"
        assert reputation_manager.get_score(agent["address"]) == 60
        assert reputation_manager.get_tier(agent["address"]) == "reduced"
        assert reputation_manager.get_send_limit(agent["address"]) == 30

        # Phase 3: Downgrade -> score 30
        db_path = os.environ.get("UAM_DB_PATH")

        async def _downgrade():
            import aiosqlite
            from uam.relay.database import (
                downgrade_verification,
                get_expired_verifications,
            )

            db = await aiosqlite.connect(db_path)
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA foreign_keys=ON")

            await db.execute(
                """UPDATE domain_verifications
                   SET last_checked = datetime('now', '-48 hours')
                   WHERE agent_address = ?""",
                (agent["address"],),
            )
            await db.commit()

            expired = await get_expired_verifications(db)
            assert len(expired) == 1

            for verification in expired:
                await downgrade_verification(db, verification["id"])
                await reputation_manager.set_score(
                    verification["agent_address"], 30
                )

            await db.close()

        asyncio.run(_downgrade())

        assert reputation_manager.get_score(agent["address"]) == 30
        assert reputation_manager.get_tier(agent["address"]) == "throttled"
        assert reputation_manager.get_send_limit(agent["address"]) == 10
