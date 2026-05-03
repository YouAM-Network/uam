"""Centralized SSRF guards for outbound HTTP (T5.1, T5.2 — Phase 45).

Promoted from src/uam/relay/verification.py:76-100. Widened to also reject
is_reserved / is_multicast / is_unspecified per REVIEW-routes.md H3.

Used by:
  - src/uam/relay/federation.py (_fetch_well_known_key, _discover_via_well_known, forward)
  - src/uam/relay/verification.py (initial-host check before HTTPS fallback)
  - src/uam/relay/routes/federation.py::_resolve_remote_sender_key
  - src/uam/relay/webhook_validator.py (via back-compat re-export through verification)

Anti-pattern (do NOT do):
  - is_public_ip(host); httpx.get(host)  # TOCTOU between resolve calls — DNS rebind risk
  - per-callsite substring "localhost" check  # misses 127.0.0.1, [::1], 0.0.0.0, IPv4-mapped IPv6
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class SSRFBlockedError(Exception):
    """Raised when an outbound target fails SSRF validation."""


def is_public_ip(hostname: str) -> bool:
    """Resolve hostname; True iff every result is non-private/loopback/link-local/etc.

    Fail-closed on resolution error.  Identical semantics to the previous
    is_public_ip in verification.py except now also rejects is_reserved /
    is_multicast / is_unspecified (per REVIEW-routes.md H3 / RESEARCH A10).
    """
    try:
        results = socket.getaddrinfo(
            hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except (socket.gaierror, OSError):
        return False
    if not results:
        return False
    for _family, _type, _proto, _canon, sockaddr in results:
        try:
            addr = ipaddress.ip_address(sockaddr[0])
        except ValueError:
            return False
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        ):
            return False
    return True


def validate_outbound_target(
    url_or_host: str,
    *,
    allowed_ports: tuple[int, ...] = (443, 8443),
    allowed_schemes: tuple[str, ...] = ("https",),
) -> None:
    """Reject the target if scheme/port/IP are not safe for outbound HTTP.

    Accepts either a full URL ("https://x.com:443/path") or a bare host.
    Raises SSRFBlockedError on any failure.
    """
    if "://" in url_or_host:
        parsed = urlparse(url_or_host)
        if parsed.scheme not in allowed_schemes:
            raise SSRFBlockedError(
                f"scheme {parsed.scheme!r} not in {allowed_schemes}"
            )
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    else:
        host = url_or_host
        port = 443
    if host is None:
        raise SSRFBlockedError(f"no host in {url_or_host!r}")
    if port not in allowed_ports:
        raise SSRFBlockedError(f"port {port} not in allowed {allowed_ports}")
    if not is_public_ip(host):
        raise SSRFBlockedError(
            f"host {host!r} resolves to private/loopback/link-local IP"
        )
