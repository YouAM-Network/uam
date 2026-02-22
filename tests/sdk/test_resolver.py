"""Tests for AddressResolver (Tier 1 relay lookup, Tier 2/3 stubs, SmartResolver)."""

from __future__ import annotations

import pytest
import httpx as httpx_lib

from uam.protocol import UAMError, generate_keypair, serialize_verify_key
from uam.sdk.resolver import Tier1Resolver, Tier2Resolver, Tier3Resolver, SmartResolver


async def _register_agent_async(relay_app, name: str) -> dict:
    """Register an agent using async ASGI transport."""
    sk, vk = generate_keypair()
    pk_str = serialize_verify_key(vk)
    async with httpx_lib.AsyncClient(
        transport=httpx_lib.ASGITransport(app=relay_app),
        base_url="http://testserver",
    ) as client:
        resp = await client.post(
            "/api/v1/register",
            json={"agent_name": name, "public_key": pk_str},
        )
        assert resp.status_code == 200
        data = resp.json()
    data["public_key_str"] = pk_str
    return data


class TestTier1Resolver:
    """Tier 1: relay HTTP API lookup."""

    async def test_resolve_public_key(self, relay_app):
        """Resolve a registered agent's public key via relay API."""
        agent = await _register_agent_async(relay_app, "resolvee")

        # Use ASGI transport to call the relay directly (in-process)
        async with httpx_lib.AsyncClient(
            transport=httpx_lib.ASGITransport(app=relay_app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get(
                f"/api/v1/agents/{agent['address']}/public-key",
                headers={"Authorization": f"Bearer {agent['token']}"},
            )
            assert resp.status_code == 200
            resolved_pk = resp.json()["public_key"]

        assert resolved_pk == agent["public_key_str"]

    async def test_resolve_not_found(self, relay_app):
        """Resolving a non-existent address should return 404."""
        agent = await _register_agent_async(relay_app, "lookup_user")

        async with httpx_lib.AsyncClient(
            transport=httpx_lib.ASGITransport(app=relay_app),
            base_url="http://testserver",
        ) as client:
            resp = await client.get(
                "/api/v1/agents/nonexistent::test.local/public-key",
                headers={"Authorization": f"Bearer {agent['token']}"},
            )
            assert resp.status_code == 404


class TestTier2Resolver:
    """Tier 2: DNS TXT record resolution (DNS-07)."""

    async def test_resolve_via_dns(self):
        """Resolve a public key via mocked DNS TXT record."""
        from unittest.mock import AsyncMock, MagicMock, patch

        mock_rdata = MagicMock()
        mock_rdata.strings = [b"v=uam1; key=ed25519:TESTKEY123"]

        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter([mock_rdata]))

        with patch("uam.sdk.dns_verifier.dns.asyncresolver.Resolver") as MockResolver:
            resolver_instance = MockResolver.return_value
            resolver_instance.resolve = AsyncMock(return_value=mock_answer)

            resolver = Tier2Resolver()
            key = await resolver.resolve_public_key(
                "alice::example.com", "key", "url"
            )

        assert key == "TESTKEY123"

    async def test_resolve_via_https_fallback(self):
        """Falls back to HTTPS .well-known when DNS has no results."""
        from unittest.mock import AsyncMock, patch
        import dns.resolver

        with (
            patch("uam.sdk.dns_verifier.dns.asyncresolver.Resolver") as MockResolver,
            patch("uam.sdk.dns_verifier.resolve_key_via_https", new_callable=AsyncMock) as mock_https,
        ):
            resolver_instance = MockResolver.return_value
            resolver_instance.resolve = AsyncMock(
                side_effect=dns.resolver.NXDOMAIN()
            )
            mock_https.return_value = "HTTPSKEY456"

            resolver = Tier2Resolver()
            key = await resolver.resolve_public_key(
                "alice::example.com", "key", "url"
            )

        assert key == "HTTPSKEY456"

    async def test_raises_uam_error_when_both_fail(self):
        """Raises UAMError when both DNS and HTTPS fail."""
        from unittest.mock import AsyncMock, patch
        import dns.resolver

        with (
            patch("uam.sdk.dns_verifier.dns.asyncresolver.Resolver") as MockResolver,
            patch("uam.sdk.dns_verifier.resolve_key_via_https", new_callable=AsyncMock) as mock_https,
        ):
            resolver_instance = MockResolver.return_value
            resolver_instance.resolve = AsyncMock(
                side_effect=dns.resolver.NXDOMAIN()
            )
            mock_https.return_value = None

            resolver = Tier2Resolver()
            with pytest.raises(UAMError, match="Cannot resolve Tier 2"):
                await resolver.resolve_public_key(
                    "alice::example.com", "key", "url"
                )


class TestTierStubs:
    """Tier 3 raises NotImplementedError."""

    async def test_tier3_raises_not_implemented(self):
        with pytest.raises(NotImplementedError, match="Tier 3"):
            await Tier3Resolver().resolve_public_key("addr", "key", "url")


class TestSmartResolver:
    """SmartResolver routes to Tier 1/2/3 by domain format (RESOLVE-01)."""

    async def test_relay_domain_routes_to_tier1(self):
        """address with domain == relay_domain routes to Tier 1."""
        from unittest.mock import AsyncMock, patch

        resolver = SmartResolver("uam.network")
        with patch.object(resolver._tier1, "resolve_public_key", new_callable=AsyncMock) as mock_t1:
            mock_t1.return_value = "TIER1KEY"
            key = await resolver.resolve_public_key(
                "alice::uam.network", "tok", "http://relay"
            )
        assert key == "TIER1KEY"
        mock_t1.assert_awaited_once_with("alice::uam.network", "tok", "http://relay")

    async def test_dotted_domain_routes_to_tier2(self):
        """address with a dotted domain (not relay) routes to Tier 2."""
        from unittest.mock import AsyncMock, patch

        resolver = SmartResolver("uam.network")
        with patch.object(resolver._tier2, "resolve_public_key", new_callable=AsyncMock) as mock_t2:
            mock_t2.return_value = "TIER2KEY"
            key = await resolver.resolve_public_key(
                "alice::example.com", "tok", "http://relay"
            )
        assert key == "TIER2KEY"
        mock_t2.assert_awaited_once_with("alice::example.com", "tok", "http://relay")

    async def test_dot_free_domain_raises_uam_error(self):
        """address with a dot-free domain (Tier 3) raises UAMError."""
        resolver = SmartResolver("uam.network")
        with pytest.raises(UAMError, match="Tier 3 resolution is not yet implemented"):
            await resolver.resolve_public_key("alice::somename", "tok", "http://relay")

    async def test_exact_domain_match_not_substring(self):
        """Domain comparison is exact equality, not endswith/startswith."""
        from unittest.mock import AsyncMock, patch

        resolver = SmartResolver("uam.network")
        # 'notuam.network' is NOT the relay domain -- should route to Tier 2
        with patch.object(resolver._tier2, "resolve_public_key", new_callable=AsyncMock) as mock_t2:
            mock_t2.return_value = "TIER2KEY"
            key = await resolver.resolve_public_key(
                "alice::notuam.network", "tok", "http://relay"
            )
        assert key == "TIER2KEY"
        mock_t2.assert_awaited_once()
