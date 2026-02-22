"""End-to-end integration tests for the domain verification flow.

Tests the complete pipeline: register agent -> verify domain via relay
endpoint -> check tier status, using the FastAPI TestClient with mocked
DNS/HTTPS resolution but real relay app, database, and endpoint code.

Covers:
- Full DNS TXT verification flow (register -> verify -> tier 2)
- HTTPS .well-known fallback verification flow
- Key mismatch rejection
- No records rejection
- Re-verification downgrade after TTL expiry
- Bidirectional verification (domain TXT + contact card)
- Unauthenticated verify request rejection
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from uam.protocol import generate_keypair, serialize_verify_key
from uam.relay.app import create_app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def app(tmp_path):
    """Create a relay app backed by a temporary database."""
    os.environ["UAM_DB_PATH"] = str(tmp_path / "integration_test.db")
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
        "agent_name": "testbot",
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
# Test 1: Full DNS TXT verification flow
# ---------------------------------------------------------------------------


class TestFullDnsVerificationFlow:
    """Complete pipeline: register -> DNS TXT verify -> tier 2 status."""

    def test_dns_verification_grants_tier2(self, client, agent):
        """DNS TXT record with matching key upgrades agent to Tier 2."""
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
        assert data["domain"] == "example.com"

        # Verify via public-key endpoint -- should now show tier 2
        pk_resp = client.get(
            f"/api/v1/agents/{agent['address']}/public-key"
        )
        assert pk_resp.status_code == 200
        pk_data = pk_resp.json()
        assert pk_data["tier"] == 2
        assert pk_data["verified_domain"] == "example.com"
        assert pk_data["public_key"] == agent["public_key_str"]


# ---------------------------------------------------------------------------
# Test 2: HTTPS fallback verification flow
# ---------------------------------------------------------------------------


class TestHttpsFallbackVerificationFlow:
    """DNS fails, HTTPS .well-known/uam.json fallback succeeds."""

    def test_https_fallback_grants_tier2(self, client, agent):
        """HTTPS .well-known with matching key upgrades to Tier 2 when DNS fails."""
        import dns.resolver

        with (
            patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver,
            patch("uam.relay.verification.is_public_ip", return_value=True),
            patch("uam.relay.verification.httpx.AsyncClient") as MockClient,
        ):
            # DNS fails with NXDOMAIN
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

            # HTTPS returns valid .well-known/uam.json
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "v": "uam1",
                "agents": {
                    "testbot": {
                        "key": f"ed25519:{agent['public_key_str']}",
                    }
                },
            }
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_resp)
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_client_instance

            resp = client.post(
                "/api/v1/verify-domain",
                json={"domain": "example.com"},
                headers={"Authorization": f"Bearer {agent['token']}"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "verified"
        assert data["tier"] == 2

        # Verify via verification status endpoint
        ver_resp = client.get(
            f"/api/v1/agents/{agent['address']}/verification"
        )
        assert ver_resp.status_code == 200
        ver_data = ver_resp.json()
        assert ver_data["tier"] == 2
        assert ver_data["domain"] == "example.com"


# ---------------------------------------------------------------------------
# Test 3: Verification fails on key mismatch
# ---------------------------------------------------------------------------


class TestVerificationFailsKeyMismatch:
    """DNS TXT record has wrong public key -- verification must fail."""

    def test_key_mismatch_stays_tier1(self, client, agent):
        """Wrong key in DNS TXT record means status=failed, tier=1."""
        rdata = _make_txt_rdata("v=uam1; key=ed25519:COMPLETELYWRONGKEY")
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
        assert data["status"] == "failed"
        assert data["tier"] == 1
        assert data["detail"] is not None
        assert "does not match" in data["detail"]

        # Public-key endpoint should still show tier 1
        pk_resp = client.get(
            f"/api/v1/agents/{agent['address']}/public-key"
        )
        pk_data = pk_resp.json()
        assert pk_data["tier"] == 1
        assert pk_data["verified_domain"] is None


# ---------------------------------------------------------------------------
# Test 4: Verification fails with no records
# ---------------------------------------------------------------------------


class TestVerificationFailsNoRecords:
    """DNS NXDOMAIN and HTTPS 404 -- no verification method succeeds."""

    def test_no_records_stays_tier1(self, client, agent):
        """No DNS or HTTPS records means status=failed."""
        import dns.resolver

        with (
            patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver,
            patch("uam.relay.verification.is_public_ip", return_value=True),
            patch("uam.relay.verification.httpx.AsyncClient") as MockClient,
        ):
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_resp)
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_client_instance

            resp = client.post(
                "/api/v1/verify-domain",
                json={"domain": "nobody.example.com"},
                headers={"Authorization": f"Bearer {agent['token']}"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "failed"
        assert data["tier"] == 1


# ---------------------------------------------------------------------------
# Test 5: Re-verification downgrade
# ---------------------------------------------------------------------------


class TestReverificationDowngrade:
    """Verified domain expires when re-verification fails."""

    def test_expired_verification_downgrades_to_tier1(self, client, agent):
        """Manually expire a verification, then check downgrade logic."""
        from uam.relay.database import (
            downgrade_verification,
            get_expired_verifications,
        )
        import aiosqlite
        import asyncio

        # First, verify the domain successfully
        rdata = _make_txt_rdata(
            f"v=uam1; key=ed25519:{agent['public_key_str']}"
        )
        answer = _make_dns_answer([rdata])

        with patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=answer)

            resp = client.post(
                "/api/v1/verify-domain",
                json={"domain": "verified.com"},
                headers={"Authorization": f"Bearer {agent['token']}"},
            )

        assert resp.json()["status"] == "verified"

        # Confirm tier 2
        pk_resp = client.get(
            f"/api/v1/agents/{agent['address']}/public-key"
        )
        assert pk_resp.json()["tier"] == 2

        # Access the database directly to expire the verification
        db_path = os.environ.get("UAM_DB_PATH")

        async def _expire_and_downgrade():
            db = await aiosqlite.connect(db_path)
            db.row_factory = aiosqlite.Row
            await db.execute("PRAGMA foreign_keys=ON")

            # Set last_checked to 48 hours ago (past the 24h TTL)
            await db.execute(
                """UPDATE domain_verifications
                   SET last_checked = datetime('now', '-48 hours')
                   WHERE agent_address = ?""",
                (agent["address"],),
            )
            await db.commit()

            # get_expired_verifications should find it
            expired = await get_expired_verifications(db)
            assert len(expired) == 1
            assert expired[0]["domain"] == "verified.com"
            assert expired[0]["agent_address"] == agent["address"]

            # Downgrade it
            await downgrade_verification(db, expired[0]["id"])

            await db.close()

        asyncio.run(_expire_and_downgrade())

        # Public-key endpoint should now show tier 1 (downgraded)
        pk_resp2 = client.get(
            f"/api/v1/agents/{agent['address']}/public-key"
        )
        pk_data = pk_resp2.json()
        assert pk_data["tier"] == 1
        assert pk_data["verified_domain"] is None

        # Verification status endpoint should also reflect downgrade
        ver_resp = client.get(
            f"/api/v1/agents/{agent['address']}/verification"
        )
        ver_data = ver_resp.json()
        assert ver_data["tier"] == 1


# ---------------------------------------------------------------------------
# Test 6: Bidirectional verification
# ---------------------------------------------------------------------------


class TestBidirectionalVerification:
    """DNS TXT references key AND contact card declares domain.

    For Phase 9, DNS TXT check is the hard requirement. The contact card
    verified_domain field exists for advisory bidirectional verification
    but is not enforced at the relay level yet. This test verifies that
    DNS verification works independently (the minimum requirement).
    """

    def test_dns_verification_without_contact_card_domain(self, client, agent):
        """DNS TXT matching key succeeds even without contact card domain claim.

        This confirms the Phase 9 minimum: DNS TXT is sufficient for Tier 2.
        Bidirectional enforcement (contact card must also declare domain)
        is advisory for Phase 9.
        """
        rdata = _make_txt_rdata(
            f"v=uam1; key=ed25519:{agent['public_key_str']}"
        )
        answer = _make_dns_answer([rdata])

        with patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=answer)

            resp = client.post(
                "/api/v1/verify-domain",
                json={"domain": "mysite.org"},
                headers={"Authorization": f"Bearer {agent['token']}"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "verified"
        assert data["tier"] == 2


# ---------------------------------------------------------------------------
# Test 7: Unauthenticated verify request rejected
# ---------------------------------------------------------------------------


class TestUnauthenticatedVerifyRejected:
    """POST /verify-domain without Bearer token must be rejected."""

    def test_no_auth_returns_401_or_403(self, client):
        """Request without authentication header is rejected."""
        resp = client.post(
            "/api/v1/verify-domain",
            json={"domain": "example.com"},
        )
        assert resp.status_code in (401, 403)

    def test_invalid_bearer_returns_401(self, client):
        """Request with invalid Bearer token is rejected."""
        resp = client.post(
            "/api/v1/verify-domain",
            json={"domain": "example.com"},
            headers={"Authorization": "Bearer completely-invalid-key"},
        )
        assert resp.status_code == 401
