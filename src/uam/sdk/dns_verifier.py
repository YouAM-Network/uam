"""DNS domain verification for UAM Tier 2 addresses (DNS-01, DNS-03).

Provides TXT record parsing, HTTPS .well-known fallback verification,
public IP validation (SSRF protection), and helper functions for
domain ownership verification.

TXT record format (at ``_uam.{domain}``):

    v=uam1; key=ed25519:<base64-pubkey>; relay=<relay-url>
"""

from __future__ import annotations

import ipaddress
import logging
import socket

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver
import httpx

logger = logging.getLogger(__name__)


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

    for family, _, _, _, sockaddr in results:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return False

    return True


async def query_uam_txt(domain: str, timeout: float = 10.0) -> list[str]:
    """Query ``_uam.{domain}`` for UAM TXT records.

    Returns a list of TXT record values that start with ``v=uam1``.
    Returns an empty list if no matching records are found or on any
    DNS error.
    """
    resolver = dns.asyncresolver.Resolver()
    try:
        answer = await resolver.resolve(
            f"_uam.{domain}",
            rdtype=dns.rdatatype.TXT,
            lifetime=timeout,
        )
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.DNSException,
    ):
        return []

    results: list[str] = []
    for rdata in answer:
        # Concatenate multi-string TXT records (handles >255 byte values)
        txt_value = "".join(
            s.decode("utf-8", errors="replace") for s in rdata.strings
        )
        if txt_value.strip().startswith("v=uam1"):
            results.append(txt_value)
    return results


async def verify_via_https(
    agent_name: str,
    domain: str,
    expected_public_key: str,
    timeout: float = 10.0,
) -> bool:
    """Verify domain ownership via ``.well-known/uam.json`` HTTPS fallback.

    Returns ``True`` if the well-known file contains an entry for
    *agent_name* with a public key matching *expected_public_key*.

    Performs SSRF validation before fetching (DNS-03).
    """
    if not is_public_ip(domain):
        logger.warning("SSRF check failed for domain %s, skipping HTTPS fallback", domain)
        return False

    url = f"https://{domain}/.well-known/uam.json"
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return False
        except httpx.HTTPError:
            return False

    try:
        data = resp.json()
    except (ValueError, KeyError):
        return False

    if data.get("v") != "uam1":
        return False

    agents = data.get("agents", {})
    agent_entry = agents.get(agent_name)
    if agent_entry is None:
        return False

    key_value = agent_entry.get("key", "")
    if key_value.startswith("ed25519:"):
        key_value = key_value[len("ed25519:"):]

    return key_value == expected_public_key


async def resolve_key_via_https(
    agent_name: str,
    domain: str,
    timeout: float = 10.0,
) -> str | None:
    """Resolve an agent's public key from ``.well-known/uam.json``.

    Returns the base64 public key string, or ``None`` if the agent
    is not found or the request fails.

    Performs SSRF validation before fetching (DNS-03).
    """
    if not is_public_ip(domain):
        logger.warning("SSRF check failed for domain %s, skipping HTTPS resolution", domain)
        return None

    url = f"https://{domain}/.well-known/uam.json"
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return None
        except httpx.HTTPError:
            return None

    try:
        data = resp.json()
    except (ValueError, KeyError):
        return None

    if data.get("v") != "uam1":
        return None

    agents = data.get("agents", {})
    agent_entry = agents.get(agent_name)
    if agent_entry is None:
        return None

    key_value = agent_entry.get("key", "")
    if key_value.startswith("ed25519:"):
        key_value = key_value[len("ed25519:"):]

    return key_value if key_value else None


def generate_txt_record(public_key: str, relay_url: str) -> str:
    """Generate the TXT record value an agent should publish at ``_uam.{domain}``.

    Returns a formatted string like:
    ``v=uam1; key=ed25519:<public_key>; relay=<relay_url>``
    """
    return f"v=uam1; key=ed25519:{public_key}; relay={relay_url}"
