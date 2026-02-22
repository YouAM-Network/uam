"""Relay-side DNS and HTTPS domain verification logic (DNS-04, DNS-08).

The relay independently verifies domain ownership before granting Tier 2
status.  This module intentionally duplicates some logic from
``sdk/dns_verifier.py`` because the relay MUST NOT trust SDK claims --
it must perform its own validation.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import httpx

from uam.protocol.address import parse_address

from uam.relay.database import (
    downgrade_verification,
    get_expired_verifications,
    update_verification_timestamp,
)

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


def is_public_ip(hostname: str) -> bool:
    """Check whether *hostname* resolves exclusively to public IP addresses.

    Returns ``False`` if any resolved address is private, loopback,
    link-local, or if DNS resolution fails (fail-closed for SSRF
    protection, DNS-03).
    """
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return False

    if not results:
        return False

    for _family, _, _, _, sockaddr in results:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return False

    return True


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
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(url)
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
            db = app.state.db  # type: ignore[union-attr]
            expired = await get_expired_verifications(db)
            for verification in expired:
                success, _method, detail = await verify_domain_ownership(
                    verification["domain"],
                    verification["public_key"],
                    verification["agent_address"],
                )
                if success:
                    await update_verification_timestamp(db, verification["id"])
                    logger.info(
                        "Re-verification succeeded for %s on %s",
                        verification["agent_address"],
                        verification["domain"],
                    )
                else:
                    await downgrade_verification(db, verification["id"])
                    # Downgrade reputation back to default (SPAM-02)
                    reputation_manager = app.state.reputation_manager  # type: ignore[union-attr]
                    await reputation_manager.set_score(
                        verification["agent_address"], 30
                    )
                    logger.warning(
                        "Re-verification failed for %s on %s (%s), downgraded to Tier 1",
                        verification["agent_address"],
                        verification["domain"],
                        detail,
                    )
    except asyncio.CancelledError:
        logger.debug("Reverification loop cancelled")
