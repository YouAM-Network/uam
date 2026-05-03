"""Phase 32 Task 5 -- Trusted-proxy X-Forwarded-For rewriting."""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from uam.protocol import generate_keypair, serialize_verify_key
from uam.relay.app import create_app
from uam.relay.middleware.proxy_headers import TrustedProxyMiddleware


class _FakePeerMiddleware:
    """Outer ASGI middleware that rewrites scope['client'] to a real IP.

    Starlette's TestClient sets scope['client'] = ('testclient', 50000), which
    is not a valid IP.  Production deployments always have a real TCP peer
    (reverse proxy LAN IP, loopback, etc.), so we simulate that here by
    rewriting the peer to 127.0.0.1 BEFORE TrustedProxyMiddleware runs.
    """

    def __init__(self, app, peer_ip: str = "127.0.0.1") -> None:
        self.app = app
        self.peer_ip = peer_ip

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            new_scope = dict(scope)
            new_scope["client"] = (self.peer_ip, 50000)
            await self.app(new_scope, receive, send)
        else:
            await self.app(scope, receive, send)


def _probe_app(trusted: list[str], peer_ip: str = "127.0.0.1") -> FastAPI:
    """Build a tiny FastAPI app wrapped in TrustedProxyMiddleware.

    Layers (outermost first): _FakePeerMiddleware (synthesizes a real TCP
    peer) -> TrustedProxyMiddleware (rewrites based on XFF if trusted) ->
    route.
    """
    app = FastAPI()

    @app.get("/whoami")
    async def whoami(request: Request) -> dict:
        host = request.client.host if request.client else None
        return {"host": host}

    # Starlette applies middleware in reverse order of add_middleware:
    # the LAST add is the OUTERMOST layer.  We want the fake-peer layer to
    # run FIRST (outermost) so TrustedProxyMiddleware sees a real peer IP.
    app.add_middleware(TrustedProxyMiddleware, trusted_cidrs=trusted)
    app.add_middleware(_FakePeerMiddleware, peer_ip=peer_ip)

    return app


def test_xff_honored_when_peer_in_trusted_cidr():
    """Peer in trusted CIDR => leftmost XFF IP replaces request.client.host."""
    app = _probe_app(["127.0.0.0/8"])
    with TestClient(app) as c:
        resp = c.get("/whoami", headers={"X-Forwarded-For": "203.0.113.7"})
    assert resp.status_code == 200
    assert resp.json()["host"] == "203.0.113.7"


def test_xff_ignored_when_peer_not_trusted():
    """Peer NOT in trusted CIDR => XFF ignored, peer IP preserved."""
    # Peer is 127.0.0.1 but trusted list is empty -- XFF must be ignored.
    app = _probe_app([])
    with TestClient(app) as c:
        resp = c.get("/whoami", headers={"X-Forwarded-For": "203.0.113.7"})
    assert resp.status_code == 200
    assert resp.json()["host"] == "127.0.0.1"


def test_xff_ignored_when_peer_outside_cidr():
    """Peer outside the trusted CIDR => XFF ignored even if XFF looks real."""
    app = _probe_app(["10.0.0.0/8"], peer_ip="127.0.0.1")
    with TestClient(app) as c:
        resp = c.get("/whoami", headers={"X-Forwarded-For": "203.0.113.7"})
    assert resp.status_code == 200
    assert resp.json()["host"] == "127.0.0.1"


def test_xff_leftmost_ip_chosen():
    """Multi-hop XFF => leftmost IP wins (original client)."""
    app = _probe_app(["127.0.0.0/8"])
    with TestClient(app) as c:
        resp = c.get(
            "/whoami",
            headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.1, 192.168.1.1"},
        )
    assert resp.status_code == 200
    assert resp.json()["host"] == "203.0.113.7"


def test_malformed_xff_falls_back_to_peer():
    """Malformed XFF => middleware bails out safely, peer IP preserved."""
    app = _probe_app(["127.0.0.0/8"])
    with TestClient(app) as c:
        resp = c.get("/whoami", headers={"X-Forwarded-For": "not-an-ip"})
    assert resp.status_code == 200
    assert resp.json()["host"] == "127.0.0.1"


def test_xff_ipv4_mapped_ipv6_normalized():
    """IPv4-mapped IPv6 => normalized to plain IPv4 for rate-limit stability."""
    app = _probe_app(["127.0.0.0/8"])
    with TestClient(app) as c:
        resp = c.get(
            "/whoami",
            headers={"X-Forwarded-For": "::ffff:203.0.113.7"},
        )
    assert resp.status_code == 200
    assert resp.json()["host"] == "203.0.113.7"


def _relay_app_with_fake_peer(peer_ip: str = "127.0.0.1") -> FastAPI:
    """Build the real relay app with the fake-peer outer layer for tests."""
    app = create_app()
    # The real app already adds TrustedProxyMiddleware inside create_app();
    # we wrap with _FakePeerMiddleware as the OUTERMOST layer by adding it
    # here.  Starlette builds the stack lazily on first request, so adding
    # after create_app() but before any request goes through is fine.
    app.add_middleware(_FakePeerMiddleware, peer_ip=peer_ip)
    return app


def test_register_rate_limits_per_real_ip(tmp_path):
    """/register rate limit buckets by the rewritten (real) client IP.

    With a trusted-proxy configuration, 6 register requests from spoofed
    XFF IP A hit the 5/min bucket, but IP B's first request is still fresh.
    """
    os.environ["UAM_DB_PATH"] = str(tmp_path / "px.db")
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"
    # Simulated peer is 127.0.0.1 -- trust loopback as a "reverse proxy".
    os.environ["UAM_TRUSTED_PROXIES"] = "127.0.0.0/8"
    try:
        app = _relay_app_with_fake_peer(peer_ip="127.0.0.1")
        with TestClient(app) as c:
            # IP A: fire up to 10 registration attempts; expect a 429.
            got_429_from_a = False
            for i in range(10):
                _, vk = generate_keypair()
                r = c.post(
                    "/api/v1/register",
                    json={
                        "agent_name": f"ipa_{i}",
                        "public_key": serialize_verify_key(vk),
                    },
                    headers={"X-Forwarded-For": "198.51.100.1"},
                )
                if r.status_code == 429:
                    got_429_from_a = True
                    break
            assert got_429_from_a, "Expected /register to throttle IP A at limit"

            # IP B: should start fresh -- first request must succeed.
            _, vk_b = generate_keypair()
            r_b = c.post(
                "/api/v1/register",
                json={
                    "agent_name": "ipb_0",
                    "public_key": serialize_verify_key(vk_b),
                },
                headers={"X-Forwarded-For": "198.51.100.2"},
            )
            assert r_b.status_code == 200, (
                f"Expected IP B's first request to succeed, got {r_b.status_code}: {r_b.text}"
            )
    finally:
        for k in ("UAM_DB_PATH", "UAM_RELAY_DOMAIN", "UAM_TRUSTED_PROXIES"):
            os.environ.pop(k, None)


def test_register_rate_limits_per_proxy_ip_when_untrusted(tmp_path):
    """Without trusted proxies, all XFF-spoofed requests share one bucket."""
    os.environ["UAM_DB_PATH"] = str(tmp_path / "px2.db")
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"
    os.environ["UAM_TRUSTED_PROXIES"] = ""  # nothing trusted
    try:
        app = _relay_app_with_fake_peer(peer_ip="127.0.0.1")
        with TestClient(app) as c:
            # Spoofed XFFs are ignored -- peer IP is the bucket key for all.
            statuses = []
            for i in range(10):
                _, vk = generate_keypair()
                r = c.post(
                    "/api/v1/register",
                    json={
                        "agent_name": f"spoof_{i}",
                        "public_key": serialize_verify_key(vk),
                    },
                    headers={"X-Forwarded-For": f"198.51.100.{i + 1}"},
                )
                statuses.append(r.status_code)
                if r.status_code == 429:
                    break
            assert 429 in statuses, (
                f"Expected XFF-spoofed requests to share one bucket, got {statuses}"
            )
    finally:
        for k in ("UAM_DB_PATH", "UAM_RELAY_DOMAIN", "UAM_TRUSTED_PROXIES"):
            os.environ.pop(k, None)
