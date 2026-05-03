"""Relay-side DNS and HTTPS domain verification logic (DNS-04, DNS-08).

The relay independently verifies domain ownership before granting Tier 2
status.  This module intentionally duplicates some logic from
``sdk/dns_verifier.py`` because the relay MUST NOT trust SDK claims --
it must perform its own validation.
"""

from __future__ import annotations

import asyncio
import logging

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import httpx

from uam.protocol.address import parse_address

from uam.db.crud.domain_verification import (
    list_expired,
    downgrade_verification,
    update_verification_timestamp,
)
from uam.db.session import async_session_factory
from uam.db.engine import get_engine
# T5.1/T5.2 (Phase 45): is_public_ip promoted to uam.relay.ssrf with widened
# rejection set (also rejects is_reserved/is_multicast/is_unspecified).  This
# re-export preserves every existing import path
# (`from uam.relay.verification import is_public_ip` — used by
# uam.relay.webhook_validator and several test files).
from uam.relay.ssrf import is_public_ip  # noqa: F401  — back-compat re-export

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TXT record parsing helpers
# ---------------------------------------------------------------------------


def parse_uam_txt(txt_value: str) -> dict[str, str]:
    """Parse a UAM TXT record value into tag-value pairs.

    Format: ``v=uam1; key=ed25519:<base64>; relay=https://...``

    Tag names are lowercased for case-insensitive matching.
    Unknown tags are preserved (forward compatibility).
    """
    tags: dict[str, str] = {}
    for part in txt_value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            tag, _, value = part.partition("=")
            tags[tag.strip().lower()] = value.strip()
    return tags


def extract_public_key(tags: dict[str, str]) -> str | None:
    """Extract the base64 public key from parsed UAM TXT tags.

    Strips the ``ed25519:`` prefix.  Returns ``None`` if the key
    tag is missing or does not have the expected prefix.
    """
    key_value = tags.get("key", "")
    if key_value.startswith("ed25519:"):
        return key_value[len("ed25519:"):]
    return None


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------
# Note: is_public_ip is now imported from uam.relay.ssrf (see imports above).
# The body that used to live here was promoted in Phase 45 Plan 04 (T5.1) and
# now also rejects is_reserved/is_multicast/is_unspecified per RESEARCH A10.


# ---------------------------------------------------------------------------
# Core verification
# ---------------------------------------------------------------------------


def _normalize_key(key: str) -> str:
    """Strip the ``ed25519:`` prefix if present for comparison."""
    if key.startswith("ed25519:"):
        return key[len("ed25519:"):]
    return key


async def verify_domain_ownership(
    domain: str,
    expected_public_key: str,
    agent_address: str,
) -> tuple[bool, str, str]:
    """Verify that *domain* is owned by the agent at *agent_address*.

    Tries DNS TXT at ``_uam.{domain}`` first.  Falls back to HTTPS
    ``.well-known/uam.json`` if DNS fails.

    Returns ``(success, method, detail)`` where *method* is ``"dns"``
    or ``"https"`` and *detail* is a human-readable status message.
    """
    normalized_expected = _normalize_key(expected_public_key)
    parsed = parse_address(agent_address)

    # --- Try DNS first ---
    try:
        resolver = dns.asyncresolver.Resolver()
        answer = await resolver.resolve(
            f"_uam.{domain}",
            rdtype=dns.rdatatype.TXT,
            lifetime=10.0,
        )
        for rdata in answer:
            txt_value = "".join(
                s.decode("utf-8", errors="replace") for s in rdata.strings
            )
            tags = parse_uam_txt(txt_value)
            if tags.get("v") != "uam1":
                continue
            found_key = extract_public_key(tags)
            if found_key is None:
                continue
            if _normalize_key(found_key) == normalized_expected:
                return (True, "dns", "DNS TXT verification successful")
            else:
                return (
                    False,
                    "dns",
                    "DNS TXT record found but public key does not match",
                )
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.DNSException,
    ):
        logger.debug("DNS TXT lookup failed for _uam.%s, trying HTTPS fallback", domain)

    # --- Fallback to HTTPS .well-known ---
    if not is_public_ip(domain):
        logger.warning("SSRF check failed for domain %s, skipping HTTPS fallback", domain)
        return (False, "", "No valid verification found at DNS TXT or HTTPS .well-known")

    url = f"https://{domain}/.well-known/uam.json"
    try:
        # T5.2 (Phase 45): follow_redirects=False — RFC 8615 .well-known does
        # NOT require redirect support, and an attacker-controlled 30x to a
        # private IP would bypass the public-IP check above. Refuse 3xx
        # explicitly with an SSRF-specific reason for operator clarity.
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            resp = await client.get(url)
            if resp.status_code in (301, 302, 303, 307, 308):
                logger.info(
                    "T5.2: refusing to follow redirect from %s "
                    "(.well-known should not redirect)",
                    url,
                )
                return (
                    False,
                    "",
                    "HTTPS .well-known returned redirect; refused for SSRF",
                )
            if resp.status_code != 200:
                return (
                    False,
                    "",
                    "No valid verification found at DNS TXT or HTTPS .well-known",
                )
    except httpx.HTTPError:
        return (False, "", "No valid verification found at DNS TXT or HTTPS .well-known")

    try:
        data = resp.json()
    except (ValueError, KeyError):
        return (False, "", "HTTPS .well-known/uam.json returned invalid JSON")

    if data.get("v") != "uam1":
        return (False, "", "HTTPS .well-known/uam.json missing v=uam1")

    agents = data.get("agents", {})
    agent_entry = agents.get(parsed.agent)
    if agent_entry is None:
        return (False, "", f"Agent '{parsed.agent}' not found in .well-known/uam.json")

    key_value = agent_entry.get("key", "")
    if _normalize_key(key_value) == normalized_expected:
        return (True, "https", "HTTPS .well-known verification successful")

    return (False, "https", "HTTPS .well-known found but public key does not match")


# ---------------------------------------------------------------------------
# Re-verification background task (DNS-08)
# ---------------------------------------------------------------------------


async def reverification_loop(app: object) -> None:
    """Periodically re-verify domains that have exceeded their TTL.

    Runs every hour.  On failure, downgrades the verification to
    ``expired`` status (Tier 1).
    """
    try:
        while True:
            await asyncio.sleep(3600)  # check every hour
            factory = async_session_factory(get_engine())
            async with factory() as session:
                expired = await list_expired(session)
            for v in expired:
                success, _method, detail = await verify_domain_ownership(
                    v.domain,
                    v.public_key,
                    v.agent_address,
                )
                if success:
                    async with factory() as session:
                        await update_verification_timestamp(session, v.id)
                    logger.info(
                        "Re-verification succeeded for %s on %s",
                        v.agent_address,
                        v.domain,
                    )
                else:
                    async with factory() as session:
                        await downgrade_verification(session, v.id)
                    # Downgrade reputation back to default (SPAM-02)
                    reputation_manager = app.state.reputation_manager  # type: ignore[union-attr]
                    await reputation_manager.set_score(
                        v.agent_address, 30
                    )
                    logger.warning(
                        "Re-verification failed for %s on %s (%s), downgraded to Tier 1",
                        v.agent_address,
                        v.domain,
                        detail,
                    )
    except asyncio.CancelledError:
        logger.debug("Reverification loop cancelled")
