"""Reserved names (P2s, DEC-006/DEC-007, UAM-12).

Some names can't be newly registered or reserved: roles people trust by
default (admin, support), the network's own names, and the big AI companies
and assistants. Ordinary words and first names stay first come, first
served. An agent that already has a reserved name keeps it.
"""

from __future__ import annotations

import pytest

from uam.protocol import generate_keypair, serialize_verify_key
from uam.protocol.register_proof import create_register_proof
from uam.relay.rate_limit import SlidingWindowCounter
from uam.relay.reserved_names import is_reserved


@pytest.mark.parametrize("name", [
    "admin", "Admin", "support", "postmaster", "no-reply", "noreply", "no_reply",
    "verified", "official", "uam", "youam", "swarmify", "claudechief",
    "amir", "anthropic", "claude", "openai", "chatgpt", "gemini",
])
def test_reserved_names(name):
    assert is_reserved(name)


@pytest.mark.parametrize("name", [
    "uam-bot", "youam-help", "acme-official", "anthropic-support", "claude-admin",
    "youam-security", "claude_support",
])
def test_reserved_patterns(name):
    assert is_reserved(name)


@pytest.mark.parametrize("name", [
    "bob", "alice", "test", "hello", "bobs-admin", "my-support", "scout", "research",
    "claudette", "uambot", "officially", "dev-test", "amira",
])
def test_ordinary_names_are_free(name):
    assert not is_reserved(name)


def test_a_relay_can_hold_more_names():
    assert not is_reserved("acme")
    assert is_reserved("acme", extra=frozenset({"acme"}))
    assert is_reserved("acme-support", extra=frozenset({"acme"}))


@pytest.fixture(autouse=True)
def _no_register_limit(app, client):
    app.state.register_limiter = SlidingWindowCounter(limit=1000, window_seconds=60.0)


def _register(client, name, public_key=None, proof=None):
    if public_key is None:
        public_key = serialize_verify_key(generate_keypair()[1])
    body = {"agent_name": name, "public_key": public_key}
    if proof is not None:
        body["proof"] = proof
    return client.post("/api/v1/register", json=body)


def test_registering_a_reserved_name_is_refused(client):
    resp = _register(client, "admin")
    assert resp.status_code == 403
    assert "reserved" in resp.json()["detail"]


def test_registering_an_ordinary_name_works(client):
    assert _register(client, "bob").status_code == 200


def test_an_agent_that_has_a_name_keeps_it_when_the_name_becomes_reserved(app, client):
    signing_key, verify_key = generate_keypair()
    public_key = serialize_verify_key(verify_key)
    first = _register(client, "acme", public_key)
    assert first.status_code == 200
    app.state.reserved_extra = frozenset({"acme"})
    proof = create_register_proof(first.json()["address"], signing_key)
    assert _register(client, "acme", public_key, proof).status_code == 200
    assert _register(client, "acme-support").status_code == 403


def test_reserving_a_reserved_name_is_refused(client):
    resp = client.post("/api/v1/reserve", json={"name": "support"})
    assert resp.status_code == 403
    assert "reserved" in resp.json()["detail"]


def test_a_reserved_name_shows_as_unavailable(client):
    resp = client.get("/api/v1/reserve/check/claude")
    assert resp.status_code == 200
    assert resp.json()["available"] is False


def test_extra_names_come_from_the_setting(monkeypatch):
    from uam.relay.config import Settings

    monkeypatch.setenv("UAM_RESERVED_NAMES", "Acme, globex ,")
    assert Settings().reserved_names == frozenset({"acme", "globex"})
