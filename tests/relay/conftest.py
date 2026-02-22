"""Shared fixtures for UAM relay tests."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
)
from uam.relay.app import create_app


@pytest.fixture()
def app(tmp_path):
    """Create a relay app backed by a temporary database."""
    os.environ["UAM_DB_PATH"] = str(tmp_path / "test.db")
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"
    yield create_app()
    # Cleanup env
    os.environ.pop("UAM_DB_PATH", None)
    os.environ.pop("UAM_RELAY_DOMAIN", None)


@pytest.fixture()
def client(app):
    """Return a TestClient for the relay app with lifespan triggered."""
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def registered_agent(client):
    """Register a single agent and return its details.

    Returns dict with keys: address, token, signing_key, verify_key, public_key_str.
    """
    sk, vk = generate_keypair()
    pk_str = serialize_verify_key(vk)
    resp = client.post("/api/v1/register", json={
        "agent_name": "testbot",
        "public_key": pk_str,
    })
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return {
        "address": data["address"],
        "token": data["token"],
        "signing_key": sk,
        "verify_key": vk,
        "public_key_str": pk_str,
    }


@pytest.fixture()
def registered_agent_pair(client):
    """Register two agents (alice and bob) and return their details.

    Returns tuple of two agent dicts.
    """
    agents = []
    for name in ("alice", "bob"):
        sk, vk = generate_keypair()
        pk_str = serialize_verify_key(vk)
        resp = client.post("/api/v1/register", json={
            "agent_name": name,
            "public_key": pk_str,
        })
        assert resp.status_code == 200, resp.text
        data = resp.json()
        agents.append({
            "address": data["address"],
            "token": data["token"],
            "signing_key": sk,
            "verify_key": vk,
            "public_key_str": pk_str,
        })
    return agents[0], agents[1]


def _make_envelope(from_agent: dict, to_agent: dict) -> dict:
    """Create a signed envelope as a wire dict using the protocol library.

    Takes two agent dicts (from registered_agent fixtures).
    """
    envelope = create_envelope(
        from_address=from_agent["address"],
        to_address=to_agent["address"],
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"Hello from tests!",
        signing_key=from_agent["signing_key"],
        recipient_verify_key=to_agent["verify_key"],
    )
    return to_wire_dict(envelope)


@pytest.fixture()
def make_envelope():
    """Fixture that returns the make_envelope helper function."""
    return _make_envelope
