"""Tier 3 resolver: on-chain namespace lookup via UAMNameRegistry (CHAIN-06)."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from uam.protocol import UAMError
from uam.protocol.address import parse_address
from uam.sdk.resolver import AddressResolver

logger = logging.getLogger(__name__)

# Default contract config -- overridable via constructor
DEFAULT_RPC_URL = "https://sepolia.base.org"
DEFAULT_CHAIN_ID = 84532  # Base Sepolia

# ABI path relative to this file: ../../contracts/deployments/UAMNameRegistry.abi.json
_ABI_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "contracts"
    / "deployments"
    / "UAMNameRegistry.abi.json"
)

# Cache TTL: 1 hour
_CACHE_TTL = 3600


class Tier3Resolver(AddressResolver):
    """Resolve agent addresses via on-chain UAMNameRegistry contract.

    Uses web3.py AsyncHTTPProvider to call resolve() on the contract.
    Caches results for 1 hour to minimize RPC calls.
    """

    def __init__(
        self,
        contract_address: str | None = None,
        rpc_url: str = DEFAULT_RPC_URL,
        chain_id: int = DEFAULT_CHAIN_ID,
        abi_path: Path | str | None = None,
        cache_ttl: int = _CACHE_TTL,
    ) -> None:
        self._contract_address = contract_address
        self._rpc_url = rpc_url
        self._chain_id = chain_id
        self._abi = self._load_abi(Path(abi_path) if abi_path else _ABI_PATH)
        self._cache_ttl = cache_ttl
        self._cache: dict[str, tuple[str, float]] = {}  # name -> (pubkey, expiry_time)
        self._w3 = None  # Lazy init
        self._contract = None

    @staticmethod
    def _load_abi(path: Path) -> list:
        if not path.exists():
            raise UAMError(f"ABI file not found: {path}")
        with open(path) as f:
            return json.load(f)

    async def _get_contract(self):
        """Lazy-initialize web3 and contract instance."""
        if self._contract is None:
            if not self._contract_address:
                raise UAMError(
                    "Tier 3 contract address not configured. "
                    "Pass contract_address to Tier3Resolver()."
                )
            try:
                from web3 import AsyncWeb3
                from web3.providers import AsyncHTTPProvider
            except ImportError:
                raise UAMError(
                    "web3 package required for Tier 3 resolution. "
                    "Install with: pip install 'youam[chain]'"
                )
            self._w3 = AsyncWeb3(AsyncHTTPProvider(self._rpc_url))
            self._contract = self._w3.eth.contract(
                address=self._w3.to_checksum_address(self._contract_address),
                abi=self._abi,
            )
        return self._contract

    async def resolve_public_key(
        self, address: str, token: str, relay_url: str
    ) -> str:
        parsed = parse_address(address)
        name = parsed.domain  # For Tier 3, the domain IS the namespace name

        # Check cache
        cached = self._cache.get(name)
        if cached and cached[1] > time.monotonic():
            logger.debug("Tier 3 cache hit for %s", name)
            return cached[0]

        # Call contract
        try:
            contract = await self._get_contract()
            result = await contract.functions.resolve(name).call()
            # result is a tuple: (owner, publicKey, relayUrl, expiry)
            _owner, public_key, _relay_url, _expiry = result
        except UAMError:
            raise
        except Exception as exc:
            error_str = str(exc)
            if "NameNotFound" in error_str or "revert" in error_str.lower():
                raise UAMError(f"Tier 3 name not found on-chain: {name}")
            raise UAMError(f"Tier 3 resolution failed for {name}: {exc}")

        if not public_key:
            raise UAMError(f"Tier 3 name {name} has no public key registered")

        # Cache result
        self._cache[name] = (public_key, time.monotonic() + self._cache_ttl)
        logger.debug(
            "Resolved %s via on-chain Tier 3 (cached for %ds)",
            address,
            self._cache_ttl,
        )
        return public_key

    def invalidate_cache(self, name: str | None = None) -> None:
        """Clear cache for a specific name or all names."""
        if name:
            self._cache.pop(name, None)
        else:
            self._cache.clear()
