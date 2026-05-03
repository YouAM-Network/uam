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
from urllib.parse import urlparse, urlunparse


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


# ---------------------------------------------------------------------------
# R-46-01 (Phase 46): Resolve-once-pin DNS for federation outbound.
#
# validate_outbound_target() above resolves the host ONCE at validate-time,
# but the actual HTTP client (httpx) does ANOTHER getaddrinfo at request-
# time.  An attacker controlling DNS for ``peer.example.com`` (TTL=0) can
# return 8.8.8.8 to validate-time and 169.254.169.254 to request-time --
# bypass.
#
# Mitigation: ``resolve_pinned()`` returns ``(host, ip)``; the caller uses
# ``build_pinned_url()`` to rewrite the URL host to the validated IP, and
# preserves cert validation by passing ``Host: original_host`` header and
# ``extensions={"sni_hostname": original_host}`` to httpx.
#
# NO global state. NO monkey-patching. NO contextvars.  Each call carries
# its own pin in arguments -- asyncio-safe by construction.  Concurrent
# outbound calls to DIFFERENT hosts have ZERO cross-coroutine interference.
# ---------------------------------------------------------------------------


def resolve_pinned(
    host: str,
    *,
    allowed_ports: tuple[int, ...] = (443, 8443),  # noqa: ARG001 — caller validates
    scheme: str = "https",  # noqa: ARG001 — caller validates
) -> tuple[str, str]:
    """R-46-01 Phase 46: resolve-once-pin DNS for outbound HTTP. Asyncio-safe.

    Resolves *host* via getaddrinfo ONCE.  Validates the resolved IP is
    public (rejects private/loopback/link-local/reserved/multicast/
    unspecified per the same widened set ``is_public_ip`` uses).  Returns
    ``(host, pinned_ip)``.

    Caller MUST pin the IP into the URL via :func:`build_pinned_url` and
    pass ``Host: host`` header + ``extensions={"sni_hostname": host}`` to
    httpx so cert validation still chains against the original hostname.

    The ``allowed_ports`` and ``scheme`` parameters are accepted for caller
    intent / forward-compat but are not enforced here -- the caller is
    expected to have already invoked :func:`validate_outbound_target` which
    enforces both.

    Raises :class:`SSRFBlockedError` on resolution failure or non-public IP.

    NO global state. NO monkey-patching.  Pure function -- safe to invoke
    concurrently from multiple coroutines targeting DIFFERENT hosts.

    Uses a SINGLE ``getaddrinfo`` call per invocation -- validates every
    record returned (rejecting if ANY is private/loopback/etc) AND pins
    the first record.  This collapses the validate-then-pick window into
    one DNS lookup, eliminating the rebind hole that ``is_public_ip()``
    would have between its lookup and a separate ``getaddrinfo`` call.
    """
    try:
        results = socket.getaddrinfo(
            host, None, socket.AF_UNSPEC, socket.SOCK_STREAM
        )
    except (socket.gaierror, OSError) as exc:
        raise SSRFBlockedError(f"DNS resolution failed for {host!r}: {exc}") from exc

    if not results:
        raise SSRFBlockedError(f"no DNS results for {host!r}")

    # Validate EVERY record (rejects DNS round-robin where any record is
    # private -- per T-46-05-03 threat).  Then pin the first record.
    for _family, _type, _proto, _canon, sockaddr in results:
        try:
            addr = ipaddress.ip_address(sockaddr[0])
        except ValueError as exc:
            raise SSRFBlockedError(
                f"invalid IP {sockaddr[0]!r} for host {host!r}"
            ) from exc
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        ):
            raise SSRFBlockedError(
                f"host {host!r} has non-public IP {sockaddr[0]!r} in record set"
            )

    pinned_ip = results[0][4][0]
    return (host, pinned_ip)


def build_pinned_url(original_url: str, pinned_ip: str) -> str:
    """R-46-01 Phase 46: rewrite *original_url* to use *pinned_ip* as the host.

    Preserves scheme, port, path, query, fragment.  IPv6 addresses are
    bracketed per RFC 3986 (``[::1]``).

    Use with::

        host, ip = resolve_pinned(original_host)
        url = build_pinned_url(original_url, ip)
        resp = await client.get(
            url,
            headers={"Host": host},
            extensions={"sni_hostname": host},
        )

    The ``Host`` header preserves the original virtual host on the wire
    (many production deployments serve multiple sites per IP).  The
    ``sni_hostname`` extension preserves TLS SNI so cert validation chains
    against the original hostname, NOT the IP literal.
    """
    parsed = urlparse(original_url)
    # IPv6 addresses must be bracketed in URL netloc per RFC 3986.
    ip_host = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    new_netloc = f"{ip_host}:{parsed.port}" if parsed.port else ip_host
    return urlunparse(
        (
            parsed.scheme,
            new_netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )
