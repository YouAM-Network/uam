"""Concurrent-pinning test for R-46-01 (per checker I-4 in 46-00-PLAN).

The R-46-01 implementation MUST be asyncio-safe: two concurrent coroutines
pinning DIFFERENT hosts via ``asyncio.gather`` must each connect to their
OWN correctly-pinned IP — no cross-coroutine interference.

Why this is a separate test from ``test_dns_rebinding_pin.py``:
  Some asyncio-unsafe implementations PASS the single-host pin test (because
  the global state is consistent within one coroutine) but FAIL under
  concurrent gather because the global state gets torn down by coroutine A
  while coroutine B still depends on it. Examples:

    - ``contextvars.ContextVar`` set/reset per call -- safe IF the impl uses
      ``ContextVar.set(..., reset=...)`` correctly. UNSAFE if it uses module-
      level ``socket.getaddrinfo = patched`` and restores in a finally block.
    - ``threading.local()`` -- safe inside one event loop thread BUT not safe
      across asyncio task boundaries unless task_factory is set.
    - Module-global ``_pinned_ips: dict[host, ip]`` mutated mid-flight.

The asyncio-safe approaches PASS this test:
    - URL rewrite (replace hostname with IP literal in the URL string + set
      Host header + sni_hostname) -- pure-functional per request, no shared state
    - httpx ``transport=ResolvedTransport(ip)`` constructed per request
    - ``contextvars.ContextVar`` with proper reset

Today this test RED at HEAD because no pin exists. After 46-05 it must GREEN
under both single-host AND concurrent-host conditions.
"""

from __future__ import annotations

import asyncio
import socket
from collections import defaultdict
from collections.abc import Callable

import pytest

pytest.importorskip("uam.relay.federation")


def _make_per_host_getaddrinfo_mock(
    host_to_ip_sequence: dict[str, list[str]],
) -> Callable:
    """Per-host stateful getaddrinfo mock.

    Each call to getaddrinfo for *host* advances that host's iterator into
    its IP sequence (last value sticks). Different hosts have independent
    iterators -- no cross-host interference at the mock layer.
    """
    state: dict[str, int] = defaultdict(int)

    def _mock(host, port, *args, **kwargs):
        seq = host_to_ip_sequence.get(host)
        if not seq:
            raise socket.gaierror(f"unknown host {host!r} in test")
        ip = seq[min(state[host], len(seq) - 1)]
        state[host] += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, port or 443))]

    return _mock


class _FakeSettings:
    """Minimal Settings shim for FederationService.__init__."""

    def __init__(self):
        self.relay_domain = "self.example.com"
        self.federation_discovery_ttl_hours = 24


@pytest.mark.asyncio
async def test_concurrent_pinning_no_cross_host_interference(monkeypatch):
    """Two coroutines pin DIFFERENT hosts simultaneously; each connects only to its own validated IP.

    The setup:
      - Host A: validate-time -> 8.8.8.8 ; request-time -> 169.254.169.254 (rebind)
      - Host B: validate-time -> 1.1.1.1 ; request-time -> 169.254.169.255 (rebind)

    Asyncio.gather schedules both ``_fetch_well_known_key`` coroutines. The
    interleaving creates the canonical race window: between A's validate-time
    and request-time getaddrinfo calls, B's validate-time call may run AND
    set globals. A pinning impl that mutates globals will fail; an impl that
    threads the resolved IP through pure-functional state will pass.
    """
    host_a, valid_a, rebind_a = "peer-a.example.com", "8.8.8.8", "169.254.169.254"
    host_b, valid_b, rebind_b = "peer-b.example.com", "1.1.1.1", "169.254.169.255"

    # Track per-host getaddrinfo invocations so we can prove BOTH coroutines
    # actually exercised the resolver (positive assertion -- prevents the
    # negative "rebind not observed" assertions from trivially passing if
    # neither coroutine ever reached the lookup step).
    #
    # Mock returns valid (public) IP for the FIRST lookup per host, and the
    # rebind IP for subsequent lookups.  A SECURE impl that does
    # resolve-once-pin into the URL literal does only ONE per-host hostname
    # lookup -- after that, httpx parses the IP literal and never asks DNS
    # for the hostname again.
    getaddrinfo_per_host: dict[str, int] = defaultdict(int)
    base_resolver = _make_per_host_getaddrinfo_mock(
        {
            host_a: [valid_a, valid_a, rebind_a, rebind_a],
            host_b: [valid_b, valid_b, rebind_b, rebind_b],
        }
    )

    def _counting_resolver(host, port, *args, **kwargs):
        getaddrinfo_per_host[host] += 1
        return base_resolver(host, port, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", _counting_resolver)

    # Spy create_connection AND loop.create_connection: record connect
    # destinations.  httpx 0.28+anyio routes through loop.create_connection
    # so that's the right surface for the URL-rewrite pin (the IP literal
    # lands as ``host`` in loop.create_connection's args).
    ip_to_host = {
        valid_a: host_a,
        rebind_a: host_a,
        valid_b: host_b,
        rebind_b: host_b,
    }
    connected_per_host: dict[str, list[str]] = defaultdict(list)

    def _record(ip_or_host: str) -> None:
        host = ip_to_host.get(ip_or_host)
        if host is None:
            # Could be hostname (no rewrite) -- map back if it matches a host
            if ip_or_host in (host_a, host_b):
                host = ip_or_host
            else:
                host = "unknown"
        connected_per_host[host].append(ip_or_host)

    def _spy_create_connection(addr, *args, **kwargs):
        ip = addr[0] if isinstance(addr, tuple) else str(addr)
        _record(ip)
        raise OSError("test-shortcircuit")

    monkeypatch.setattr(socket, "create_connection", _spy_create_connection)

    # Patch the asyncio loop's create_connection (used by httpx 0.28+anyio).
    import asyncio
    loop = asyncio.get_event_loop()

    async def _spy_loop_create_connection(*args, **kwargs):
        host = kwargs.get("host")
        port = kwargs.get("port")
        if host is None and len(args) >= 2:
            host = args[1]
        if port is None and len(args) >= 3:
            port = args[2]
        if host is not None:
            _record(str(host))
        raise OSError(f"test-shortcircuit (would connect to {host}:{port})")

    monkeypatch.setattr(loop, "create_connection", _spy_loop_create_connection)

    from nacl.signing import SigningKey

    from uam.relay.federation import FederationService

    sk = SigningKey.generate()
    svc_a = FederationService(_FakeSettings(), sk, sk.verify_key)
    svc_b = FederationService(_FakeSettings(), sk, sk.verify_key)

    async def _do(svc, host):
        try:
            await svc._fetch_well_known_key(host, port=443)
        except Exception:
            pass

    # Concurrent gather — the critical race window for global-state impls.
    await asyncio.gather(_do(svc_a, host_a), _do(svc_b, host_b))

    # ---- Positive assertions (per checker I-4 + I-5) ----------------
    # If neither coroutine actually exercised the resolver/connect step,
    # the negative assertions below would all trivially pass without
    # proving anything (e.g. an early return at validate_outbound_target,
    # or an httpx transport that never calls socket-layer hooks). Pin
    # the observation surface so the test cannot lie to itself.
    assert getaddrinfo_per_host[host_a] >= 1, (
        f"Coroutine A never invoked getaddrinfo for {host_a}. "
        f"per_host_calls={dict(getaddrinfo_per_host)}. "
        f"The rebind window was never opened for A; test is not exercising R-46-01."
    )
    assert getaddrinfo_per_host[host_b] >= 1, (
        f"Coroutine B never invoked getaddrinfo for {host_b}. "
        f"per_host_calls={dict(getaddrinfo_per_host)}. "
        f"The rebind window was never opened for B; test is not exercising R-46-01."
    )
    # Together at least 2 calls (one per host minimum). Most secure impls
    # will produce >= 4 (validate + request per host).
    total_calls = sum(getaddrinfo_per_host.values())
    assert total_calls >= 2, (
        f"Combined getaddrinfo calls = {total_calls} (<2). "
        f"per_host_calls={dict(getaddrinfo_per_host)}. "
        f"At least one call per coroutine is required."
    )

    # At least one connect attempt must have been observed. If
    # connected_per_host is empty, the implementation never reached the
    # connect step (e.g. early SSRF refusal because validate_outbound_target
    # rejected the host). That's acceptable behavior for SECURE impls but
    # it makes the negative cross-host assertions vacuous. To prove the
    # test actually drives traffic, require >= 1 observed connect across
    # both coroutines.
    total_connects = sum(len(v) for v in connected_per_host.values())
    assert total_connects >= 1, (
        f"socket.create_connection was never called by either coroutine. "
        f"connected_per_host={dict(connected_per_host)}. "
        f"per_host_getaddrinfo={dict(getaddrinfo_per_host)}. "
        f"Test cannot prove asyncio-safe pinning -- inspect _fetch_well_known_key "
        f"to confirm it reaches the connect step under attack conditions, OR "
        f"refactor the test to use httpx MockTransport per 46-05's chosen approach."
    )

    # ---- Negative assertions ----------------------------------------
    # Each host must NOT have connected to its rebind IP.
    assert rebind_a not in connected_per_host[host_a], (
        f"Host A connected to its rebind IP {rebind_a}. "
        f"Connections={dict(connected_per_host)}"
    )
    assert rebind_b not in connected_per_host[host_b], (
        f"Host B connected to its rebind IP {rebind_b}. "
        f"Connections={dict(connected_per_host)}"
    )
    # Each host must NOT have connected to the OTHER host's IP.
    assert valid_b not in connected_per_host[host_a], (
        f"Cross-coroutine interference: host A connected to host B's validated IP. "
        f"Connections={dict(connected_per_host)}"
    )
    assert valid_a not in connected_per_host[host_b], (
        f"Cross-coroutine interference: host B connected to host A's validated IP. "
        f"Connections={dict(connected_per_host)}"
    )
    # Cross-rebind: host A must not connect to host B's rebind IP either.
    assert rebind_b not in connected_per_host[host_a], (
        f"Cross-coroutine bleed: host A connected to host B's rebind IP. "
        f"Connections={dict(connected_per_host)}"
    )
    assert rebind_a not in connected_per_host[host_b], (
        f"Cross-coroutine bleed: host B connected to host A's rebind IP. "
        f"Connections={dict(connected_per_host)}"
    )
