"""Trusted-proxy header middleware (Phase 32 Task 5).

Problem
-------
When the relay is deployed behind a reverse proxy / load balancer (Railway,
Fly.io, nginx, Cloudflare, etc.) every inbound request arrives from the
proxy's IP.  Any code path that uses ``request.client.host`` as a rate-limit
or abuse-tracking key (``/register``, ``/demo/*``) therefore sees the SAME
IP for every attacker, collapsing per-client limits into one shared bucket.

Fix
---
When the peer IP is inside a configured trusted-proxy CIDR, take the
right-most ``X-Forwarded-For`` entry that is not itself a trusted proxy and
rewrite the ASGI ``scope["client"]`` tuple.  Proxies (Cloudflare, Caddy,
nginx) append to whatever header the client sent, so the left-most entry is
the client's own claim and must never be believed.  Requests whose peer is NOT in a trusted
CIDR are passed through unchanged -- this is critical: honoring XFF from
arbitrary peers would let any attacker spoof their source IP by setting the
header themselves.

Safety properties
-----------------
* Default configuration (``UAM_TRUSTED_PROXIES`` empty) is a no-op: XFF is
  ignored for every request.  Dev / test environments behave as before.
* Malformed XFF values fall back to the peer IP -- never crash the request.
* Only entries added by trusted proxies are believed: the client is the
  right-most hop that isn't one.  List EVERY proxy hop in
  ``UAM_TRUSTED_PROXIES`` (e.g. Cloudflare's published ranges plus the local
  reverse proxy), or the relay will see the outer proxy as the client.
* Rewritten scope is applied BEFORE any downstream middleware or route
  sees it, so all ``request.client.host`` lookups benefit automatically.

Usage
-----
``UAM_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12,fd00::/8`` is a typical
Railway/Fly.io setup.  Individual hosts may be given as ``/32`` or
``/128`` (``::1/128`` in tests).
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Awaitable, Callable, Iterable

logger = logging.getLogger(__name__)

_Send = Callable[[dict], Awaitable[None]]
_Receive = Callable[[], Awaitable[dict]]
_ASGIApp = Callable[[dict, _Receive, _Send], Awaitable[None]]


def _parse_cidrs(
    raw: Iterable[str],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse CIDR strings into network objects, skipping invalid entries."""
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in raw:
        s = (item or "").strip()
        if not s:
            continue
        try:
            networks.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid trusted_proxies CIDR: %r", s)
    return networks


def _peer_in_trusted(
    peer_ip: str,
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    """Return True if the peer IP belongs to any trusted CIDR."""
    try:
        addr = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    for net in networks:
        # ip_network / ip_address of different families can't be compared
        # directly -- skip mismatches.
        if isinstance(addr, ipaddress.IPv4Address) and isinstance(
            net, ipaddress.IPv4Network
        ):
            if addr in net:
                return True
        elif isinstance(addr, ipaddress.IPv6Address) and isinstance(
            net, ipaddress.IPv6Network
        ):
            if addr in net:
                return True
    return False


def _normalize_ip(candidate: str) -> str | None:
    """One X-Forwarded-For entry as a plain IP string, or None if it isn't one.

    Strips whitespace and brackets (``[::1]``) and turns IPv4-mapped IPv6
    (``::ffff:1.2.3.4``) into ``1.2.3.4`` so CIDR tests and rate-limit keys
    behave the same on mixed-stack deployments.
    """
    candidate = candidate.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if not candidate:
        return None
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def _client_from_xff(
    xff_value: str,
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> str | None:
    """The client IP in an X-Forwarded-For value: the right-most untrusted hop.

    Proxies append the address they received the request from, so only the
    entries our trusted proxies added are facts; everything to their left is
    whatever the client chose to send.  Walk from the right past trusted
    proxies and take the first hop that isn't one.

    Returns ``None`` (keep the peer IP) when the header is empty or a hop on
    that walk isn't an IP.  If every hop is a trusted proxy, the first entry
    is the client (an internal caller).
    """
    hops = [h for h in (xff_value or "").split(",")]
    if not any(h.strip() for h in hops):
        return None
    first: str | None = None
    for raw in reversed(hops):
        ip = _normalize_ip(raw)
        if ip is None:
            return None
        if not _peer_in_trusted(ip, networks):
            return ip
        first = ip
    return first


class TrustedProxyMiddleware:
    """ASGI middleware that rewrites scope['client'] based on X-Forwarded-For.

    Only active when the peer is in one of the configured trusted CIDRs.
    Any other request -- including one that ships a forged XFF header --
    is passed through untouched.
    """

    def __init__(
        self,
        app: _ASGIApp,
        trusted_cidrs: Iterable[str] | None = None,
    ) -> None:
        self.app = app
        self._networks = _parse_cidrs(trusted_cidrs or [])
        if self._networks:
            logger.info(
                "TrustedProxyMiddleware active with %d CIDR(s): %s",
                len(self._networks),
                ",".join(str(n) for n in self._networks),
            )

    async def __call__(self, scope: dict, receive: _Receive, send: _Send) -> None:
        # Only HTTP and WebSocket scopes carry client info; lifespan has no
        # client and no headers -- pass through untouched.
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        # Short-circuit if no trusted proxies configured.
        if not self._networks:
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        if not client:
            await self.app(scope, receive, send)
            return

        peer_ip = client[0]
        if not _peer_in_trusted(peer_ip, self._networks):
            # Peer is not a trusted proxy -- ignore XFF entirely (spoof guard).
            await self.app(scope, receive, send)
            return

        # Pull XFF header (case-insensitive, bytes per ASGI spec).
        xff_value: str | None = None
        for name, value in scope.get("headers", []):
            if name == b"x-forwarded-for":
                try:
                    xff_value = value.decode("latin-1")
                except Exception:
                    xff_value = None
                break

        rewritten_ip = _client_from_xff(xff_value or "", self._networks)
        if rewritten_ip is None:
            # Malformed / missing XFF: keep peer IP (safe fallback).
            await self.app(scope, receive, send)
            return

        # Build a new scope with rewritten client tuple so downstream code
        # (rate limiters, loggers, etc.) sees the real client IP.  We leave
        # the port at 0 because XFF does not carry port information.
        new_scope = dict(scope)
        new_scope["client"] = (rewritten_ip, 0)
        await self.app(new_scope, receive, send)
