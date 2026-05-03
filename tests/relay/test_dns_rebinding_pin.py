"""DNS-rebinding test for federation outbound (R-46-01).

Validates the **resolve-once-pin** pattern. ``validate_outbound_target`` resolves
the host once and confirms the IP is public, but today nothing prevents a
DIFFERENT IP from being returned the second time httpx itself resolves the
hostname for the actual TCP connect. An attacker controlling DNS for
``attacker.example.com`` can:

  - Return ``8.8.8.8`` (public) when validate_outbound_target queries getaddrinfo
  - Return ``169.254.169.254`` (AWS metadata IP) when httpx queries getaddrinfo

Plan 46-05 picks pattern (1) — URL rewrite. ``resolve_pinned()`` resolves once
and pins the IP into the URL via ``build_pinned_url()``; httpx connects directly
to the IP literal with the original Host header + ``sni_hostname`` extension to
preserve TLS validation against the original hostname.

Observation surface (per the plan's invitation to refactor): we patch BOTH
``socket.create_connection`` (legacy, may be reached on some httpx codepaths)
AND the asyncio event-loop's ``create_connection`` (httpx 0.28+anyio path) so
we can observe the actual connect target regardless of the underlying transport.
Per checker I-5, positive assertions prove the test isn't trivially passing.
"""

from __future__ import annotations

import asyncio
import socket
from collections.abc import Callable

import pytest

# Federation module exists; the resolve-once-pin guard does not. The test
# itself does NOT depend on a new-module import — it exercises the existing
# ``_fetch_well_known_key`` path and observes which IP httpx tries to connect
# to. After Plan 46-05 lands the pin, this test will GREEN.
pytest.importorskip("uam.relay.federation")


def _make_getaddrinfo_mock(
    ips_in_order: list[str],
    counter: dict[str, int] | None = None,
) -> Callable:
    """Each call returns the next IP in *ips_in_order* (last value sticks).

    If *counter* is provided, increments ``counter['n']`` on every call so the
    test can assert getaddrinfo was actually invoked.
    """
    state = {"i": 0}

    def _mock(host, port, *args, **kwargs):
        ip = ips_in_order[min(state["i"], len(ips_in_order) - 1)]
        state["i"] += 1
        if counter is not None:
            counter["n"] += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, port or 443))]

    return _mock


class _FakeSettings:
    """Minimal Settings shim for FederationService.__init__.

    FederationService only reads ``settings.relay_domain`` and
    ``settings.federation_discovery_ttl_hours`` from settings during the
    code paths exercised by this test.
    """

    def __init__(self):
        self.relay_domain = "test.example.com"
        self.federation_discovery_ttl_hours = 24


def _patch_loop_create_connection(monkeypatch, connected_to: list[str]) -> None:
    """Patch the running asyncio loop's create_connection to record (host, port)
    of every connect attempt and short-circuit with OSError.

    httpx 0.28 + anyio routes connects through ``loop.create_connection`` (NOT
    ``socket.create_connection``), so this is the right observation surface for
    the resolve-once-pin pattern -- after URL rewrite, the IP literal lands
    here as ``host``.
    """
    loop = asyncio.get_event_loop()
    orig_create_connection = loop.create_connection

    async def _spy(*args, **kwargs):
        # asyncio loop.create_connection signature:
        #   create_connection(protocol_factory, host=None, port=None, *, ssl=None, ...)
        # Positional or keyword.
        host = kwargs.get("host")
        port = kwargs.get("port")
        if host is None and len(args) >= 2:
            host = args[1]
        if port is None and len(args) >= 3:
            port = args[2]
        if host is not None:
            connected_to.append(str(host))
        raise OSError(f"test-shortcircuit (would connect to {host}:{port})")

    monkeypatch.setattr(loop, "create_connection", _spy)
    # Also patch socket.create_connection for any legacy code paths.
    def _legacy_spy(addr, *args, **kwargs):
        ip = addr[0] if isinstance(addr, tuple) else str(addr)
        connected_to.append(ip)
        raise OSError("test-shortcircuit")
    monkeypatch.setattr(socket, "create_connection", _legacy_spy)
    # Suppress the "expected" used variable warning
    _ = orig_create_connection


@pytest.mark.asyncio
async def test_federation_outbound_pins_validated_ip(monkeypatch):
    """validate-time IP=8.8.8.8 + httpx-time IP=169.254.169.254 -> never connect to private IP.

    The mock returns ``public_ip`` for the validate-time + resolve-pin
    lookups (which collectively call getaddrinfo on the hostname), then
    ``metadata_ip`` for any subsequent lookups.  After URL rewrite, the
    URL contains the IP literal so httpx does NOT do another DNS lookup
    on the hostname -- it parses the IP literal directly.  We assert that
    the actual connect target is the public IP, not the metadata IP.
    """
    public_ip = "8.8.8.8"
    metadata_ip = "169.254.169.254"

    # Mock returns public_ip for the first two lookups (validate_outbound_target
    # + resolve_pinned both run is_public_ip / getaddrinfo on the original
    # hostname).  After that, simulate the rebind: subsequent lookups (if the
    # implementation re-resolved) would get the metadata IP.  A SECURE impl
    # never makes that subsequent lookup because it pinned the IP into the URL.
    getaddrinfo_calls = {"n": 0}
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        _make_getaddrinfo_mock(
            [public_ip, public_ip, metadata_ip, metadata_ip], getaddrinfo_calls
        ),
    )

    # Capture every (host) the asyncio loop tries to connect to.  This is
    # the right observation surface for httpx 0.28+anyio.
    connected_to: list[str] = []
    _patch_loop_create_connection(monkeypatch, connected_to)

    # Build a real FederationService and fire the federation outbound path.
    from nacl.signing import SigningKey

    from uam.relay.federation import FederationService

    sk = SigningKey.generate()
    svc = FederationService(_FakeSettings(), sk, sk.verify_key)

    try:
        await svc._fetch_well_known_key("attacker.example.com", port=443)
    except Exception:
        pass  # We assert on which IP was attempted, not on the return value.

    # ---- Positive assertions (per checker I-5) -----------------------
    # Prove the test actually exercised the resolver AND reached the connect
    # step -- otherwise the negative assertions below trivially pass.

    assert getaddrinfo_calls["n"] >= 1, (
        f"getaddrinfo was called only {getaddrinfo_calls['n']} time(s). "
        f"DNS-rebind test requires at least the validate-time lookup -- "
        f"otherwise the rebind window was never opened."
    )

    assert len(connected_to) >= 1, (
        f"loop.create_connection was never called -- the test cannot prove "
        f"DNS-rebind mitigation. Implementation may have early-returned at "
        f"validate_outbound_target. connected_to={connected_to}, "
        f"getaddrinfo_calls={getaddrinfo_calls['n']}. Inspect "
        f"FederationService._fetch_well_known_key to confirm it's reaching "
        f"the connect step under attack conditions."
    )

    # ---- Negative assertion ------------------------------------------
    # Under DNS rebind, the implementation MUST NOT have connected to the
    # metadata IP. The pinned URL literal must be the public IP.
    assert metadata_ip not in connected_to, (
        f"DNS rebind succeeded! Connected to {connected_to}, which includes "
        f"{metadata_ip}. R-46-01 is unmitigated -- there is no resolve-once-pin "
        f"between validate_outbound_target and httpx.AsyncClient.get()."
    )

    # ---- Positive correctness assertion ------------------------------
    # The pinned IP MUST be the public_ip (the one validate-time saw).
    assert public_ip in connected_to, (
        f"Expected to connect to validated public IP {public_ip}, but "
        f"connected_to={connected_to}. The URL rewrite + IP-literal connect "
        f"is the asyncio-safe pin per the plan."
    )
