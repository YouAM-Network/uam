"""The relay as the pressure test runs it: the real app, with test-only limits.

``uvicorn tests.pressure.relay_app:create --factory``.  Nothing here ships.

PRESSURE_REAL_LIMITS=1 keeps the relay's own rate limits.  Otherwise they are
raised, so a run measures delivery rather than the limiter.

PRESSURE_PEERS="domain=http://127.0.0.1:port,..." lets relays on one machine
federate: discovery answers from this list and the SSRF guard is off for them,
because every address here is loopback.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

import httpx

import uam.relay.app as relay_app
import uam.relay.federation as federation
import uam.relay.routes.federation as federation_routes
from uam.relay.rate_limit import SlidingWindowCounter

HIGH = 10_000_000


def _peers() -> dict[str, str]:
    pairs = [p for p in os.environ.get("PRESSURE_PEERS", "").split(",") if p]
    return dict(pair.split("=", 1) for pair in pairs)


def _allow_loopback_peers() -> None:
    peers = _peers()
    if not peers:
        return

    def no_check(*_args, **_kwargs):
        return None

    federation.validate_outbound_target = no_check
    federation_routes.validate_outbound_target = no_check
    federation.resolve_pinned = lambda host, **_kwargs: (host, "127.0.0.1")

    async def well_known(domain: str) -> dict | None:
        if domain not in peers:
            return None
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{peers[domain]}/.well-known/uam-relay.json")
        return resp.json() if resp.status_code == 200 else None

    async def discover_relay(_self, domain: str) -> dict | None:
        if domain not in peers:
            return None
        try:
            known = await well_known(domain)
        except httpx.HTTPError:
            return None
        return {
            "domain": domain,
            "federation_url": f"{peers[domain]}/api/v1/federation/deliver",
            "public_key": known["public_key"],
        }

    async def relay_key(_session, from_relay: str) -> str | None:
        return (await well_known(from_relay) or {}).get("public_key")

    async def sender_key(_session, address, _service, _settings) -> str | None:
        domain = address.split("::", 1)[1]
        if domain not in peers:
            return None
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{peers[domain]}/api/v1/agents/{address}/public-key")
        return resp.json()["public_key"] if resp.status_code == 200 else None

    federation.FederationService.discover_relay = discover_relay
    federation_routes._get_relay_public_key = relay_key
    federation_routes._resolve_remote_sender_key = sender_key


def _lift_limits(app) -> None:
    state = app.state
    for name in ("sender_limiter", "recipient_limiter", "register_limiter", "domain_limiter"):
        setattr(state, name, SlidingWindowCounter(limit=HIGH, window_seconds=60.0))
    state.reputation_manager.get_send_limit = lambda _sender: HIGH


def create():
    _allow_loopback_peers()
    relay_app._FEDERATION_RETRY_INTERVAL = 1
    app = relay_app.create_app()
    inner = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(a):
        async with inner(a) as state:
            if os.environ.get("PRESSURE_REAL_LIMITS") != "1":
                _lift_limits(a)
            yield state

    app.router.lifespan_context = lifespan
    return app

