"""T5.1 — federation outbound SSRF guards (Wave 0, failing-by-design).

Tests will RED until Plan 45-04 lands:
  - ``src/uam/relay/ssrf.py`` with:
      * ``validate_outbound_target(url: str) -> None`` raises
        ``SSRFBlockedError`` if the URL resolves to a private/loopback/
        link-local IP, uses a disallowed port, or is non-https.
      * ``SSRFBlockedError`` exception class
  - ``src/uam/relay/federation.py``:
      * ``FederationService._fetch_well_known_key`` calls
        ``validate_outbound_target`` before the HTTP fetch.
      * ``FederationService._client`` constructed with
        ``follow_redirects=False``.
  - ``src/uam/relay/routes/federation.py``:
      * ``_resolve_remote_sender_key`` calls ``validate_outbound_target`` on
        the home-relay URL before fetching the sender's key.

Per RESEARCH § Pattern 3 the SSRF check resolves DNS once (cached) and
inspects the resulting IP ranges; ``ipaddress.ip_address(ip).is_private`` /
``is_loopback`` / ``is_link_local`` / ``is_reserved`` cover all the major
metadata-server escape routes.
"""

from __future__ import annotations

import inspect
import socket

import pytest


# ---------------------------------------------------------------------------
# Helper: monkeypatch DNS to return a controlled IP
# ---------------------------------------------------------------------------


def _stub_dns(monkeypatch, host_to_ip):
    """Make ``socket.getaddrinfo`` return ``host_to_ip[host]`` for known hosts."""
    real_getaddrinfo = socket.getaddrinfo

    def fake(host, *a, **kw):
        if host in host_to_ip:
            ip = host_to_ip[host]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
        return real_getaddrinfo(host, *a, **kw)

    monkeypatch.setattr("socket.getaddrinfo", fake)


# ---------------------------------------------------------------------------
# validate_outbound_target — direct unit tests (RED on ImportError today)
# ---------------------------------------------------------------------------


def test_validate_outbound_target_refuses_loopback(monkeypatch):
    """``validate_outbound_target`` raises ``SSRFBlockedError`` for 127.0.0.1."""
    from uam.relay.ssrf import validate_outbound_target, SSRFBlockedError  # type: ignore[import-not-found]
    _stub_dns(monkeypatch, {"evil.example.com": "127.0.0.1"})
    with pytest.raises(SSRFBlockedError):
        validate_outbound_target("https://evil.example.com:443/path")


def test_validate_outbound_target_refuses_aws_metadata(monkeypatch):
    """``validate_outbound_target`` raises ``SSRFBlockedError`` for 169.254.169.254.

    AWS / GCP / Azure metadata servers all live in 169.254.0.0/16 (link-local).
    A federation peer pointing its well-known endpoint at this IP could exfil
    cloud-instance credentials via the relay.
    """
    from uam.relay.ssrf import validate_outbound_target, SSRFBlockedError  # type: ignore[import-not-found]
    _stub_dns(monkeypatch, {"evil.example.com": "169.254.169.254"})
    with pytest.raises(SSRFBlockedError):
        validate_outbound_target("https://evil.example.com:443/path")


def test_validate_outbound_target_refuses_rfc1918(monkeypatch):
    """``validate_outbound_target`` raises ``SSRFBlockedError`` for RFC1918 ranges.

    Covers 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 — internal-only addresses
    a SaaS-deployed relay must never reach.
    """
    from uam.relay.ssrf import validate_outbound_target, SSRFBlockedError  # type: ignore[import-not-found]
    for private_ip in ("10.0.0.1", "192.168.1.100", "172.16.0.5"):
        _stub_dns(monkeypatch, {"evil.example.com": private_ip})
        with pytest.raises(SSRFBlockedError):
            validate_outbound_target("https://evil.example.com:443/path")


def test_validate_outbound_target_refuses_disallowed_port(monkeypatch):
    """``validate_outbound_target`` raises for ports outside the allowlist."""
    from uam.relay.ssrf import validate_outbound_target, SSRFBlockedError  # type: ignore[import-not-found]
    _stub_dns(monkeypatch, {"good.example.com": "8.8.8.8"})  # public IP
    with pytest.raises(SSRFBlockedError):
        validate_outbound_target("https://good.example.com:9999/path")


def test_validate_outbound_target_refuses_non_https(monkeypatch):
    """``validate_outbound_target`` raises for ``http://`` scheme.

    Federation MUST be HTTPS — plaintext federation lets a network
    eavesdropper inject envelopes / read peer-key responses.
    """
    from uam.relay.ssrf import validate_outbound_target, SSRFBlockedError  # type: ignore[import-not-found]
    _stub_dns(monkeypatch, {"good.example.com": "8.8.8.8"})
    with pytest.raises(SSRFBlockedError):
        validate_outbound_target("http://good.example.com:80/path")


def test_validate_outbound_target_accepts_public_https(monkeypatch):
    """``validate_outbound_target`` succeeds for public IP + https + 443."""
    from uam.relay.ssrf import validate_outbound_target  # type: ignore[import-not-found]
    _stub_dns(monkeypatch, {"good.example.com": "8.8.8.8"})
    # Should not raise
    validate_outbound_target("https://good.example.com:443/path")


# ---------------------------------------------------------------------------
# Federation route integration — xfail until Plan 45-04 wires the helper
# ---------------------------------------------------------------------------


def test_well_known_refuses_loopback():
    """``FederationService._fetch_well_known_key`` returns None for 127.0.0.1.

    Wave-0 stub: the integration test requires a live ``FederationService``
    instance + DNS monkeypatch + httpx stub.  Plan 45-04 will replace this
    xfail with a concrete test when it adds the validate_outbound_target
    wrapper around the fetch.
    """
    pytest.xfail(
        "Plan 45-04 wraps _fetch_well_known_key with validate_outbound_target"
    )


def test_well_known_refuses_aws_metadata():
    """``FederationService._fetch_well_known_key`` returns None for AWS metadata IP."""
    pytest.xfail(
        "Plan 45-04 wraps _fetch_well_known_key with validate_outbound_target"
    )


def test_well_known_refuses_rfc1918():
    """``FederationService._fetch_well_known_key`` returns None for RFC1918."""
    pytest.xfail(
        "Plan 45-04 wraps _fetch_well_known_key with validate_outbound_target"
    )


def test_client_no_redirects():
    """``FederationService.__init__`` constructs ``httpx.AsyncClient`` with
    ``follow_redirects=False``.

    Defense in depth: even if validate_outbound_target passes for the
    initial URL, an attacker-controlled 302 to an internal IP would re-leak.
    httpx defaults to follow_redirects=True; we MUST explicitly set False.
    """
    from uam.relay.federation import FederationService

    src = inspect.getsource(FederationService.__init__)
    assert "follow_redirects=False" in src, (
        "FederationService.__init__ must construct httpx.AsyncClient(follow_redirects=False) — "
        "Plan 45-04 not yet applied"
    )


def test_resolve_remote_refuses_private():
    """``routes/federation.py::_resolve_remote_sender_key`` refuses private home-relay URL.

    Inherited from Phase 43 T1.7 (resolve remote sender key) — that fix
    introduced the function but did not add SSRF guards on the home-relay URL
    before fetching the sender's key.  An attacker crafting an envelope with
    ``home_relay = "http://169.254.169.254/sensitive"`` could exfil cloud
    metadata.
    """
    pytest.xfail(
        "Plan 45-04 wires validate_outbound_target into _resolve_remote_sender_key"
    )


def test_srv_private_target_refused():
    """DNS-mocked SRV pointing at private IP causes federation discovery to refuse.

    Belt-and-braces: even if the user-supplied domain is public, the SRV
    record at ``_uam._tcp.<domain>`` could resolve to a private target.
    Plan 45-04 must validate the SRV target before fetching its
    .well-known/uam-relay.json.
    """
    pytest.xfail(
        "Plan 45-04 wires validate_outbound_target into discover_relay path"
    )
