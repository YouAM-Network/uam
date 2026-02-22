"""Pluggable address resolver with Tier 1 relay lookup (SDK-08)."""

from __future__ import annotations

import abc
import logging

import httpx

from uam.protocol import UAMError
from uam.protocol.address import parse_address

logger = logging.getLogger(__name__)


class AddressResolver(abc.ABC):
    """Pluggable address resolver interface (SDK-08).

    Tier 1 (implemented): relay lookup via HTTP API
    Tier 2 (implemented): DNS TXT record resolution (DNS-07)
    Tier 3 (stub): On-chain namespace lookup
    """

    @abc.abstractmethod
    async def resolve_public_key(
        self, address: str, token: str, relay_url: str
    ) -> str:
        """Resolve an agent address to its public key (base64).

        Raises:
            UAMError: If the address cannot be resolved.
        """


class Tier1Resolver(AddressResolver):
    """Tier 1: resolve via relay HTTP API.

    Calls ``GET /api/v1/agents/{address}/public-key`` (unauthenticated --
    the public-key endpoint is open so agents can discover recipients
    before their first handshake).
    """

    async def resolve_public_key(
        self, address: str, token: str, relay_url: str
    ) -> str:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{relay_url}/api/v1/agents/{address}/public-key",
            )
            if resp.status_code == 404:
                raise UAMError(f"Agent not found: {address}")
            resp.raise_for_status()
            return resp.json()["public_key"]


class Tier2Resolver(AddressResolver):
    """Tier 2: resolve via DNS TXT record at ``_uam.{domain}`` (DNS-07).

    Queries the ``_uam.{domain}`` TXT record for a ``v=uam1`` entry
    containing the agent's Ed25519 public key.  Falls back to HTTPS
    ``.well-known/uam.json`` if DNS lookup yields no results.
    """

    async def resolve_public_key(
        self, address: str, token: str, relay_url: str
    ) -> str:
        from uam.protocol.address import parse_address
        from uam.sdk.dns_verifier import (
            extract_public_key,
            parse_uam_txt,
            query_uam_txt,
            resolve_key_via_https,
        )

        parsed = parse_address(address)

        # 1. Try DNS TXT record at _uam.{domain}
        txt_records = await query_uam_txt(parsed.domain)
        for record in txt_records:
            tags = parse_uam_txt(record)
            if tags.get("v") == "uam1":
                key = extract_public_key(tags)
                if key:
                    logger.debug(
                        "Resolved %s via DNS TXT record", address
                    )
                    return key

        # 2. Fallback: HTTPS .well-known/uam.json
        key = await resolve_key_via_https(parsed.agent, parsed.domain)
        if key:
            logger.debug(
                "Resolved %s via HTTPS .well-known fallback", address
            )
            return key

        raise UAMError(f"Cannot resolve Tier 2 address: {address}")


class Tier3Resolver(AddressResolver):
    """Tier 3 stub: On-chain namespace lookup.

    See ROADMAP Phase 2 -- will resolve agent addresses via on-chain
    namespace registries for decentralised identity verification.
    """

    async def resolve_public_key(
        self, address: str, token: str, relay_url: str
    ) -> str:
        raise NotImplementedError(
            "On-chain resolution is not yet implemented (Tier 3)"
        )


class SmartResolver(AddressResolver):
    """Automatic tier-based resolver that routes by domain format (RESOLVE-01).

    Routing rules:
      - domain == relay_domain  -> Tier 1 (relay HTTP API lookup)
      - domain contains a '.'  -> Tier 2 (DNS TXT / HTTPS fallback)
      - domain has no dots     -> Tier 3 (not yet implemented, raises UAMError)
    """

    def __init__(self, relay_domain: str) -> None:
        self._relay_domain = relay_domain
        self._tier1 = Tier1Resolver()
        self._tier2 = Tier2Resolver()

    async def resolve_public_key(
        self, address: str, token: str, relay_url: str
    ) -> str:
        parsed = parse_address(address)
        domain = parsed.domain

        if domain == self._relay_domain:
            return await self._tier1.resolve_public_key(address, token, relay_url)

        if "." in domain:
            return await self._tier2.resolve_public_key(address, token, relay_url)

        raise UAMError(
            f"Tier 3 resolution is not yet implemented. "
            f"Cannot resolve dot-free domain: {domain!r}"
        )
