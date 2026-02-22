"""Tests for domain verification endpoint and relay-side verification logic.

Covers:
- parse_uam_txt() and extract_public_key() unit tests
- verify_domain_ownership() with mocked DNS and HTTP
- POST /api/v1/verify-domain endpoint
- GET /api/v1/agents/{address}/verification endpoint
- GET /api/v1/agents/{address}/public-key tier integration
- Database helper functions
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uam.relay.verification import (
    extract_public_key,
    parse_uam_txt,
    verify_domain_ownership,
)


# ---------------------------------------------------------------------------
# Unit tests: TXT record parsing
# ---------------------------------------------------------------------------


class TestParseUamTxt:
    """parse_uam_txt() unit tests."""

    def test_valid_record(self):
        tags = parse_uam_txt("v=uam1; key=ed25519:ABC123; relay=https://relay.test")
        assert tags["v"] == "uam1"
        assert tags["key"] == "ed25519:ABC123"
        assert tags["relay"] == "https://relay.test"

    def test_empty_string(self):
        assert parse_uam_txt("") == {}

    def test_no_equals(self):
        tags = parse_uam_txt("no-equals-here")
        assert tags == {}

    def test_case_insensitive_tags(self):
        tags = parse_uam_txt("V=uam1; KEY=ed25519:abc")
        assert tags["v"] == "uam1"
        assert tags["key"] == "ed25519:abc"

    def test_extra_whitespace(self):
        tags = parse_uam_txt("  v = uam1 ;  key = ed25519:XYZ  ")
        assert tags["v"] == "uam1"
        assert tags["key"] == "ed25519:XYZ"

    def test_unknown_tags_preserved(self):
        tags = parse_uam_txt("v=uam1; key=ed25519:abc; custom=value")
        assert tags["custom"] == "value"

    def test_multiple_semicolons(self):
        tags = parse_uam_txt("v=uam1;; key=ed25519:abc;;")
        assert tags["v"] == "uam1"
        assert tags["key"] == "ed25519:abc"


class TestExtractPublicKey:
    """extract_public_key() unit tests."""

    def test_valid_key(self):
        tags = {"v": "uam1", "key": "ed25519:ABC123DEF"}
        assert extract_public_key(tags) == "ABC123DEF"

    def test_missing_prefix(self):
        tags = {"v": "uam1", "key": "ABC123DEF"}
        assert extract_public_key(tags) is None

    def test_missing_key_tag(self):
        tags = {"v": "uam1"}
        assert extract_public_key(tags) is None

    def test_empty_key(self):
        tags = {"key": ""}
        assert extract_public_key(tags) is None


# ---------------------------------------------------------------------------
# Unit tests: verify_domain_ownership() with mocks
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


class TestVerifyDomainOwnership:
    """verify_domain_ownership() with mocked DNS and HTTP."""

    @pytest.mark.asyncio
    async def test_dns_success(self):
        """DNS TXT record with matching key succeeds."""
        rdata = _make_txt_rdata("v=uam1; key=ed25519:TESTKEY123")
        answer = _make_dns_answer([rdata])

        with patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=answer)

            success, method, detail = await verify_domain_ownership(
                "example.com", "TESTKEY123", "bot::example.com"
            )

        assert success is True
        assert method == "dns"
        assert "DNS TXT" in detail

    @pytest.mark.asyncio
    async def test_dns_key_mismatch(self):
        """DNS TXT record with wrong key fails."""
        rdata = _make_txt_rdata("v=uam1; key=ed25519:WRONGKEY")
        answer = _make_dns_answer([rdata])

        with patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=answer)

            success, method, detail = await verify_domain_ownership(
                "example.com", "RIGHTKEY", "bot::example.com"
            )

        assert success is False
        assert "does not match" in detail

    @pytest.mark.asyncio
    async def test_dns_fail_https_success(self):
        """DNS fails, HTTPS .well-known fallback succeeds."""
        import dns.resolver

        with (
            patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver,
            patch("uam.relay.verification.is_public_ip", return_value=True),
            patch("uam.relay.verification.httpx.AsyncClient") as MockClient,
        ):
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

            # Mock HTTPS response
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "v": "uam1",
                "agents": {
                    "bot": {
                        "key": "ed25519:TESTKEY123",
                    }
                },
            }
            mock_client_instance = AsyncMock()
            mock_client_instance.get = AsyncMock(return_value=mock_resp)
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_client_instance

            success, method, detail = await verify_domain_ownership(
                "example.com", "TESTKEY123", "bot::example.com"
            )

        assert success is True
        assert method == "https"
        assert "HTTPS" in detail

    @pytest.mark.asyncio
    async def test_both_fail(self):
        """DNS and HTTPS both fail."""
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

            success, method, detail = await verify_domain_ownership(
                "example.com", "TESTKEY123", "bot::example.com"
            )

        assert success is False

    @pytest.mark.asyncio
    async def test_key_normalization(self):
        """Keys with ed25519: prefix are normalized before comparison."""
        rdata = _make_txt_rdata("v=uam1; key=ed25519:MYKEY")
        answer = _make_dns_answer([rdata])

        with patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=answer)

            # Pass key WITH prefix -- should still match
            success, method, _ = await verify_domain_ownership(
                "example.com", "ed25519:MYKEY", "bot::example.com"
            )

        assert success is True
        assert method == "dns"

    @pytest.mark.asyncio
    async def test_ssrf_blocks_https(self):
        """SSRF check blocks HTTPS fallback for private IPs."""
        import dns.resolver

        with (
            patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver,
            patch("uam.relay.verification.is_public_ip", return_value=False),
        ):
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())

            success, method, detail = await verify_domain_ownership(
                "internal.local", "TESTKEY", "bot::internal.local"
            )

        assert success is False
        assert "No valid verification" in detail


# ---------------------------------------------------------------------------
# Endpoint tests via FastAPI TestClient
# ---------------------------------------------------------------------------


class TestVerifyDomainEndpoint:
    """POST /api/v1/verify-domain endpoint tests."""

    def test_verify_domain_success(self, client, registered_agent):
        """Authenticated agent with mocked DNS success gets verified."""
        rdata = _make_txt_rdata(f"v=uam1; key=ed25519:{registered_agent['public_key_str']}")
        answer = _make_dns_answer([rdata])

        with patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=answer)

            resp = client.post(
                "/api/v1/verify-domain",
                json={"domain": "example.com"},
                headers={"Authorization": f"Bearer {registered_agent['token']}"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "verified"
        assert data["domain"] == "example.com"
        assert data["tier"] == 2

    def test_verify_domain_failure(self, client, registered_agent):
        """Verification failure returns status=failed with detail."""
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
                json={"domain": "nobody.com"},
                headers={"Authorization": f"Bearer {registered_agent['token']}"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "failed"
        assert data["tier"] == 1
        assert data["detail"] is not None

    def test_verify_domain_no_auth(self, client):
        """Unauthenticated request returns 401/403."""
        resp = client.post(
            "/api/v1/verify-domain",
            json={"domain": "example.com"},
        )
        assert resp.status_code in (401, 403)

    def test_verify_domain_bad_token(self, client):
        """Invalid token returns 401."""
        resp = client.post(
            "/api/v1/verify-domain",
            json={"domain": "example.com"},
            headers={"Authorization": "Bearer invalid-key-here"},
        )
        assert resp.status_code == 401


class TestVerificationStatusEndpoint:
    """GET /api/v1/agents/{address}/verification endpoint tests."""

    def test_unverified_agent(self, client, registered_agent):
        """Agent without verification returns tier 1."""
        address = registered_agent["address"]
        resp = client.get(f"/api/v1/agents/{address}/verification")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tier"] == 1
        assert data["domain"] is None

    def test_verified_agent(self, client, registered_agent):
        """Agent with verification returns tier 2 with domain."""
        rdata = _make_txt_rdata(f"v=uam1; key=ed25519:{registered_agent['public_key_str']}")
        answer = _make_dns_answer([rdata])

        # First verify the domain
        with patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=answer)

            client.post(
                "/api/v1/verify-domain",
                json={"domain": "verified.com"},
                headers={"Authorization": f"Bearer {registered_agent['token']}"},
            )

        # Then check status
        address = registered_agent["address"]
        resp = client.get(f"/api/v1/agents/{address}/verification")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tier"] == 2
        assert data["domain"] == "verified.com"

    def test_unknown_agent(self, client):
        """Non-existent agent returns 404."""
        resp = client.get("/api/v1/agents/nobody::test.local/verification")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Enhanced public-key endpoint tests
# ---------------------------------------------------------------------------


class TestPublicKeyTier:
    """GET /api/v1/agents/{address}/public-key now includes tier info."""

    def test_default_tier_1(self, client, registered_agent):
        """Unverified agent has tier=1 and no verified_domain."""
        address = registered_agent["address"]
        resp = client.get(f"/api/v1/agents/{address}/public-key")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tier"] == 1
        assert data["verified_domain"] is None

    def test_tier_2_after_verification(self, client, registered_agent):
        """Verified agent has tier=2 and verified_domain in public-key response."""
        rdata = _make_txt_rdata(f"v=uam1; key=ed25519:{registered_agent['public_key_str']}")
        answer = _make_dns_answer([rdata])

        with patch("uam.relay.verification.dns.asyncresolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve = AsyncMock(return_value=answer)

            client.post(
                "/api/v1/verify-domain",
                json={"domain": "mysite.org"},
                headers={"Authorization": f"Bearer {registered_agent['token']}"},
            )

        address = registered_agent["address"]
        resp = client.get(f"/api/v1/agents/{address}/public-key")
        assert resp.status_code == 200
        data = resp.json()
        assert data["tier"] == 2
        assert data["verified_domain"] == "mysite.org"


# ---------------------------------------------------------------------------
# Database helper tests
# ---------------------------------------------------------------------------


class TestDatabaseHelpers:
    """Domain verification database helpers."""

    @pytest.mark.asyncio
    async def test_upsert_and_get(self, app):
        """Upsert creates a record, get retrieves it."""
        from uam.relay.database import (
            get_domain_verification,
            init_db,
            register_agent,
            upsert_domain_verification,
        )
        import os

        db = await init_db(os.environ.get("UAM_DB_PATH", ":memory:"))
        try:
            # Register agent first (foreign key constraint)
            await register_agent(db, "bot::test.local", "PUBKEY", "token123")

            await upsert_domain_verification(
                db, "bot::test.local", "test.local", "PUBKEY", "dns", 24
            )

            result = await get_domain_verification(db, "bot::test.local")
            assert result is not None
            assert result["domain"] == "test.local"
            assert result["method"] == "dns"
            assert result["status"] == "verified"
        finally:
            await db.close()

    @pytest.mark.asyncio
    async def test_upsert_update(self, app):
        """Second upsert updates existing record."""
        from uam.relay.database import (
            get_domain_verification,
            init_db,
            register_agent,
            upsert_domain_verification,
        )
        import os

        db = await init_db(os.environ.get("UAM_DB_PATH", ":memory:"))
        try:
            await register_agent(db, "bot::test.local", "PUBKEY", "token123")

            await upsert_domain_verification(
                db, "bot::test.local", "test.local", "PUBKEY", "dns", 24
            )
            # Update with different method
            await upsert_domain_verification(
                db, "bot::test.local", "test.local", "PUBKEY", "https", 48
            )

            result = await get_domain_verification(db, "bot::test.local")
            assert result is not None
            assert result["method"] == "https"
        finally:
            await db.close()

    @pytest.mark.asyncio
    async def test_get_expired(self, app):
        """get_expired_verifications returns only expired entries."""
        from uam.relay.database import (
            get_expired_verifications,
            init_db,
            register_agent,
        )
        import os

        db = await init_db(os.environ.get("UAM_DB_PATH", ":memory:"))
        try:
            await register_agent(db, "bot::test.local", "PUBKEY", "token123")

            # Insert a verification that's already expired (last_checked far in the past)
            await db.execute(
                """INSERT INTO domain_verifications
                   (agent_address, domain, public_key, method, ttl_hours,
                    verified_at, last_checked, status)
                   VALUES (?, ?, ?, ?, ?, datetime('now', '-48 hours'),
                           datetime('now', '-48 hours'), 'verified')""",
                ("bot::test.local", "old.com", "PUBKEY", "dns", 24),
            )
            await db.commit()

            expired = await get_expired_verifications(db)
            assert len(expired) == 1
            assert expired[0]["domain"] == "old.com"
        finally:
            await db.close()

    @pytest.mark.asyncio
    async def test_downgrade(self, app):
        """downgrade_verification changes status to expired."""
        from uam.relay.database import (
            downgrade_verification,
            init_db,
            register_agent,
            upsert_domain_verification,
        )
        import os

        db = await init_db(os.environ.get("UAM_DB_PATH", ":memory:"))
        try:
            await register_agent(db, "bot::test.local", "PUBKEY", "token123")
            await upsert_domain_verification(
                db, "bot::test.local", "test.local", "PUBKEY", "dns", 24
            )

            # Get the ID
            cursor = await db.execute(
                "SELECT id FROM domain_verifications WHERE agent_address = ?",
                ("bot::test.local",),
            )
            row = await cursor.fetchone()
            assert row is not None

            await downgrade_verification(db, row["id"])

            # Verify it's expired
            cursor = await db.execute(
                "SELECT status FROM domain_verifications WHERE id = ?",
                (row["id"],),
            )
            row = await cursor.fetchone()
            assert row["status"] == "expired"
        finally:
            await db.close()
