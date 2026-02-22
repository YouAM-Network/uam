"""Tests for Tier3Resolver (on-chain namespace lookup via UAMNameRegistry)."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from uam.protocol import UAMError
from uam.sdk.resolver import SmartResolver, AddressResolver


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class MockTier3Resolver(AddressResolver):
    """Mock Tier3Resolver for SmartResolver routing tests."""

    def __init__(self, return_value: str = "TIER3KEY"):
        self._return_value = return_value
        self.called_with: list[tuple] = []

    async def resolve_public_key(
        self, address: str, token: str, relay_url: str
    ) -> str:
        self.called_with.append((address, token, relay_url))
        return self._return_value


def _make_tier3(contract_address="0x1234567890abcdef1234567890abcdef12345678", **kwargs):
    """Create a Tier3Resolver with a mocked ABI load."""
    from uam.sdk.tier3 import Tier3Resolver

    with patch.object(Tier3Resolver, "_load_abi", return_value=[{"fake": "abi"}]):
        return Tier3Resolver(contract_address=contract_address, **kwargs)


def _mock_contract_result(public_key="ed25519:TESTKEY123"):
    """Return a tuple matching the resolve() output format."""
    return (
        "0x0000000000000000000000000000000000000001",  # owner
        public_key,  # publicKey
        "https://relay.example.com",  # relayUrl
        9999999999,  # expiry
    )


# ---------------------------------------------------------------------------
# Tier3Resolver unit tests
# ---------------------------------------------------------------------------


class TestTier3Resolver:
    """On-chain Tier 3 resolution via web3.py."""

    async def test_resolve_public_key_from_contract(self):
        """resolve_public_key returns the public key from the contract."""
        resolver = _make_tier3()
        mock_call = AsyncMock(return_value=_mock_contract_result())

        with patch.object(resolver, "_get_contract") as mock_get:
            mock_contract = MagicMock()
            mock_contract.functions.resolve.return_value.call = mock_call
            mock_get.return_value = mock_contract

            key = await resolver.resolve_public_key(
                "scout::acme", "tok", "http://relay"
            )

        assert key == "ed25519:TESTKEY123"
        mock_contract.functions.resolve.assert_called_once_with("acme")

    async def test_cache_hit_skips_rpc_call(self):
        """Second resolve for the same name returns cached result, no RPC."""
        resolver = _make_tier3()
        mock_call = AsyncMock(return_value=_mock_contract_result())

        with patch.object(resolver, "_get_contract") as mock_get:
            mock_contract = MagicMock()
            mock_contract.functions.resolve.return_value.call = mock_call
            mock_get.return_value = mock_contract

            key1 = await resolver.resolve_public_key(
                "scout::acme", "tok", "http://relay"
            )
            key2 = await resolver.resolve_public_key(
                "scout::acme", "tok", "http://relay"
            )

        assert key1 == key2 == "ed25519:TESTKEY123"
        # Contract call should happen only once
        assert mock_call.await_count == 1

    async def test_expired_cache_triggers_fresh_rpc(self):
        """Expired cache entry triggers a new RPC call."""
        resolver = _make_tier3(cache_ttl=0)  # TTL of 0 seconds = always expired
        mock_call = AsyncMock(return_value=_mock_contract_result())

        with patch.object(resolver, "_get_contract") as mock_get:
            mock_contract = MagicMock()
            mock_contract.functions.resolve.return_value.call = mock_call
            mock_get.return_value = mock_contract

            await resolver.resolve_public_key(
                "scout::acme", "tok", "http://relay"
            )
            # With TTL=0, cache is immediately expired
            time.sleep(0.01)  # tiny sleep to ensure monotonic time advances
            await resolver.resolve_public_key(
                "scout::acme", "tok", "http://relay"
            )

        assert mock_call.await_count == 2

    async def test_name_not_found_revert(self):
        """NameNotFound revert from contract raises UAMError."""
        resolver = _make_tier3()

        with patch.object(resolver, "_get_contract") as mock_get:
            mock_contract = MagicMock()
            mock_contract.functions.resolve.return_value.call = AsyncMock(
                side_effect=Exception("execution reverted: NameNotFound")
            )
            mock_get.return_value = mock_contract

            with pytest.raises(UAMError, match="Tier 3 name not found on-chain"):
                await resolver.resolve_public_key(
                    "scout::unknown", "tok", "http://relay"
                )

    async def test_rpc_connection_error(self):
        """RPC connection error raises UAMError."""
        resolver = _make_tier3()

        with patch.object(resolver, "_get_contract") as mock_get:
            mock_contract = MagicMock()
            mock_contract.functions.resolve.return_value.call = AsyncMock(
                side_effect=ConnectionError("Failed to connect to RPC")
            )
            mock_get.return_value = mock_contract

            with pytest.raises(UAMError, match="Tier 3 resolution failed"):
                await resolver.resolve_public_key(
                    "scout::acme", "tok", "http://relay"
                )

    async def test_empty_public_key_raises(self):
        """Contract returning empty public key raises UAMError."""
        resolver = _make_tier3()
        mock_call = AsyncMock(return_value=_mock_contract_result(public_key=""))

        with patch.object(resolver, "_get_contract") as mock_get:
            mock_contract = MagicMock()
            mock_contract.functions.resolve.return_value.call = mock_call
            mock_get.return_value = mock_contract

            with pytest.raises(UAMError, match="has no public key registered"):
                await resolver.resolve_public_key(
                    "scout::acme", "tok", "http://relay"
                )

    async def test_invalidate_cache_specific_name(self):
        """invalidate_cache(name) clears only that name."""
        resolver = _make_tier3()
        mock_call = AsyncMock(return_value=_mock_contract_result())

        with patch.object(resolver, "_get_contract") as mock_get:
            mock_contract = MagicMock()
            mock_contract.functions.resolve.return_value.call = mock_call
            mock_get.return_value = mock_contract

            # Populate cache
            await resolver.resolve_public_key(
                "scout::acme", "tok", "http://relay"
            )
            assert "acme" in resolver._cache

            # Invalidate
            resolver.invalidate_cache("acme")
            assert "acme" not in resolver._cache

    async def test_invalidate_cache_all(self):
        """invalidate_cache() with no args clears all cache entries."""
        resolver = _make_tier3()
        # Manually populate cache
        resolver._cache["name1"] = ("key1", time.monotonic() + 3600)
        resolver._cache["name2"] = ("key2", time.monotonic() + 3600)

        resolver.invalidate_cache()
        assert len(resolver._cache) == 0

    async def test_no_contract_address_raises(self):
        """Missing contract_address raises UAMError on resolve."""
        from uam.sdk.tier3 import Tier3Resolver

        with patch.object(Tier3Resolver, "_load_abi", return_value=[{"fake": "abi"}]):
            resolver = Tier3Resolver(contract_address=None)

        with pytest.raises(UAMError, match="contract address not configured"):
            await resolver.resolve_public_key(
                "scout::acme", "tok", "http://relay"
            )


# ---------------------------------------------------------------------------
# SmartResolver routing tests
# ---------------------------------------------------------------------------


class TestSmartResolverTier3Routing:
    """SmartResolver routes dot-free domains to Tier3Resolver."""

    async def test_dot_free_domain_routes_to_tier3(self):
        """Dot-free domain is routed to Tier3Resolver."""
        mock_t3 = MockTier3Resolver(return_value="ONCHAINKEY")
        resolver = SmartResolver("youam.network", tier3_resolver=mock_t3)

        key = await resolver.resolve_public_key(
            "scout::acme", "tok", "http://relay"
        )

        assert key == "ONCHAINKEY"
        assert len(mock_t3.called_with) == 1
        assert mock_t3.called_with[0] == ("scout::acme", "tok", "http://relay")

    async def test_dotted_domain_still_routes_to_tier2(self):
        """Dotted domains still route to Tier2, not Tier3."""
        from unittest.mock import AsyncMock, patch

        mock_t3 = MockTier3Resolver()
        resolver = SmartResolver("youam.network", tier3_resolver=mock_t3)

        with patch.object(
            resolver._tier2, "resolve_public_key", new_callable=AsyncMock
        ) as mock_t2:
            mock_t2.return_value = "TIER2KEY"
            key = await resolver.resolve_public_key(
                "alice::example.com", "tok", "http://relay"
            )

        assert key == "TIER2KEY"
        assert len(mock_t3.called_with) == 0  # Tier3 not called

    async def test_relay_domain_still_routes_to_tier1(self):
        """Relay domain still routes to Tier1, not Tier3."""
        from unittest.mock import AsyncMock, patch

        mock_t3 = MockTier3Resolver()
        resolver = SmartResolver("youam.network", tier3_resolver=mock_t3)

        with patch.object(
            resolver._tier1, "resolve_public_key", new_callable=AsyncMock
        ) as mock_t1:
            mock_t1.return_value = "TIER1KEY"
            key = await resolver.resolve_public_key(
                "alice::youam.network", "tok", "http://relay"
            )

        assert key == "TIER1KEY"
        assert len(mock_t3.called_with) == 0  # Tier3 not called
