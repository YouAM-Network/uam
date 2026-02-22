"""Shared fixtures for cross-SDK and cross-relay interop tests.

Provides:
- relay_app / relay_client: a live relay app with TestClient (federation disabled)
- register_agent: helper to register agents via the relay API
- make_signed_envelope: helper to create signed+encrypted envelopes
- federated_relay_pair: two relay apps with federation enabled and mutual trust
- three_relay_triangle: three relay apps with circular federation topology
"""

from __future__ import annotations

import json
import os
from typing import Any

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
from uam.relay.relay_auth import (
    load_or_generate_relay_keypair,
    sign_federation_request,
)
from uam.protocol.crypto import serialize_signing_key
from uam.protocol.types import utc_timestamp


# ---------------------------------------------------------------------------
# Single-relay fixtures (for cross-SDK tests)
# ---------------------------------------------------------------------------


@pytest.fixture()
def relay_app(tmp_path):
    """Create a relay app backed by a temp database with federation disabled."""
    os.environ["UAM_DB_PATH"] = str(tmp_path / "relay.db")
    os.environ["UAM_RELAY_DOMAIN"] = "interop.test"
    os.environ["UAM_FEDERATION_ENABLED"] = "false"
    os.environ["UAM_RELAY_KEY_PATH"] = str(tmp_path / "relay_key.pem")
    app = create_app()
    yield app
    os.environ.pop("UAM_DB_PATH", None)
    os.environ.pop("UAM_RELAY_DOMAIN", None)
    os.environ.pop("UAM_FEDERATION_ENABLED", None)
    os.environ.pop("UAM_RELAY_KEY_PATH", None)


@pytest.fixture()
def relay_client(relay_app):
    """Return a TestClient for the relay app with lifespan triggered."""
    with TestClient(relay_app) as c:
        yield c


def _register_agent(client: TestClient, name: str) -> dict[str, Any]:
    """Register an agent on the relay and return its details.

    Returns dict with: address, token, signing_key, verify_key, public_key_str.
    """
    sk, vk = generate_keypair()
    pk_str = serialize_verify_key(vk)
    resp = client.post("/api/v1/register", json={
        "agent_name": name,
        "public_key": pk_str,
    })
    assert resp.status_code == 200, f"Registration failed for {name}: {resp.text}"
    data = resp.json()
    return {
        "address": data["address"],
        "token": data["token"],
        "signing_key": sk,
        "verify_key": vk,
        "public_key_str": pk_str,
    }


@pytest.fixture()
def register_agent():
    """Fixture returning the register_agent helper function."""
    return _register_agent


def _make_signed_envelope(
    from_agent: dict, to_agent: dict, message: str = "Hello!"
) -> dict:
    """Create a signed+encrypted envelope as a wire dict.

    Takes two agent dicts (from _register_agent).
    """
    envelope = create_envelope(
        from_address=from_agent["address"],
        to_address=to_agent["address"],
        message_type=MessageType.MESSAGE,
        payload_plaintext=message.encode("utf-8"),
        signing_key=from_agent["signing_key"],
        recipient_verify_key=to_agent["verify_key"],
    )
    return to_wire_dict(envelope)


@pytest.fixture()
def make_signed_envelope():
    """Fixture returning the make_signed_envelope helper function."""
    return _make_signed_envelope


# ---------------------------------------------------------------------------
# Federation relay fixtures (for cross-relay tests)
# ---------------------------------------------------------------------------


def _create_federation_relay(tmp_path, domain: str, suffix: str):
    """Create a relay app with federation enabled and its own keypair.

    Returns (app, relay_sk, relay_vk, relay_pk_str, db_path, key_path).
    """
    db_path = str(tmp_path / f"{suffix}_relay.db")
    key_path = str(tmp_path / f"{suffix}_relay_key.pem")

    os.environ["UAM_DB_PATH"] = db_path
    os.environ["UAM_RELAY_DOMAIN"] = domain
    os.environ["UAM_FEDERATION_ENABLED"] = "true"
    os.environ["UAM_RELAY_KEY_PATH"] = key_path
    os.environ["UAM_RELAY_HTTP_URL"] = f"http://{suffix}.local"
    os.environ["UAM_RELAY_WS_URL"] = f"ws://{suffix}.local/ws"

    app = create_app()
    relay_sk, relay_vk = load_or_generate_relay_keypair(key_path)
    relay_pk_str = serialize_verify_key(relay_vk)

    return app, relay_sk, relay_vk, relay_pk_str, db_path, key_path


def _cleanup_relay_env():
    """Remove relay-related environment variables."""
    for key in (
        "UAM_DB_PATH", "UAM_RELAY_DOMAIN", "UAM_FEDERATION_ENABLED",
        "UAM_RELAY_KEY_PATH", "UAM_RELAY_HTTP_URL", "UAM_RELAY_WS_URL",
    ):
        os.environ.pop(key, None)


@pytest.fixture()
def federated_relay_pair(tmp_path):
    """Create two relay apps with mutual federation trust.

    Returns a dict with:
    - alpha_client, beta_client: TestClient instances
    - alpha_agent, beta_agent: registered agent dicts
    - alpha_relay_sk, beta_relay_sk: relay signing keys
    - alpha_pk, beta_pk: relay public key strings
    """
    # Create alpha relay
    alpha_app, alpha_sk, alpha_vk, alpha_pk, _, _ = _create_federation_relay(
        tmp_path, "alpha.test", "alpha"
    )
    _cleanup_relay_env()

    # Create beta relay
    beta_app, beta_sk, beta_vk, beta_pk, _, _ = _create_federation_relay(
        tmp_path, "beta.test", "beta"
    )
    _cleanup_relay_env()

    with TestClient(alpha_app) as alpha_client, TestClient(beta_app) as beta_client:
        alpha_db = alpha_app.state.db
        beta_db = beta_app.state.db

        # Seed known_relays: alpha knows beta, beta knows alpha
        import asyncio

        async def _seed():
            from uam.relay.database import upsert_known_relay

            await upsert_known_relay(
                alpha_db, "beta.test",
                f"{beta_client.base_url}/api/v1/federation/deliver",
                beta_pk, "manual", ttl_hours=24,
            )
            await upsert_known_relay(
                beta_db, "alpha.test",
                f"{alpha_client.base_url}/api/v1/federation/deliver",
                alpha_pk, "manual", ttl_hours=24,
            )

        loop = asyncio.new_event_loop()
        loop.run_until_complete(_seed())
        loop.close()

        # Register agents
        alice = _register_agent(alpha_client, "alice")
        bob = _register_agent(beta_client, "bob")

        yield {
            "alpha_client": alpha_client,
            "beta_client": beta_client,
            "alpha_agent": alice,
            "beta_agent": bob,
            "alpha_relay_sk": alpha_sk,
            "beta_relay_sk": beta_sk,
            "alpha_pk": alpha_pk,
            "beta_pk": beta_pk,
            "alpha_app": alpha_app,
            "beta_app": beta_app,
        }


@pytest.fixture()
def three_relay_triangle(tmp_path):
    """Create three relay apps in a triangle topology.

    alpha knows beta, beta knows gamma, gamma knows alpha.
    One agent on each relay.
    """
    alpha_app, alpha_sk, alpha_vk, alpha_pk, _, _ = _create_federation_relay(
        tmp_path, "alpha.test", "alpha"
    )
    _cleanup_relay_env()

    beta_app, beta_sk, beta_vk, beta_pk, _, _ = _create_federation_relay(
        tmp_path, "beta.test", "beta"
    )
    _cleanup_relay_env()

    gamma_app, gamma_sk, gamma_vk, gamma_pk, _, _ = _create_federation_relay(
        tmp_path, "gamma.test", "gamma"
    )
    _cleanup_relay_env()

    with (
        TestClient(alpha_app) as alpha_client,
        TestClient(beta_app) as beta_client,
        TestClient(gamma_app) as gamma_client,
    ):
        import asyncio
        from uam.relay.database import upsert_known_relay

        async def _seed():
            # Full mesh: every relay knows every other relay's public key
            # alpha knows beta and gamma
            await upsert_known_relay(
                alpha_app.state.db, "beta.test",
                f"{beta_client.base_url}/api/v1/federation/deliver",
                beta_pk, "manual", ttl_hours=24,
            )
            await upsert_known_relay(
                alpha_app.state.db, "gamma.test",
                f"{gamma_client.base_url}/api/v1/federation/deliver",
                gamma_pk, "manual", ttl_hours=24,
            )
            # beta knows alpha and gamma
            await upsert_known_relay(
                beta_app.state.db, "alpha.test",
                f"{alpha_client.base_url}/api/v1/federation/deliver",
                alpha_pk, "manual", ttl_hours=24,
            )
            await upsert_known_relay(
                beta_app.state.db, "gamma.test",
                f"{gamma_client.base_url}/api/v1/federation/deliver",
                gamma_pk, "manual", ttl_hours=24,
            )
            # gamma knows alpha and beta
            await upsert_known_relay(
                gamma_app.state.db, "alpha.test",
                f"{alpha_client.base_url}/api/v1/federation/deliver",
                alpha_pk, "manual", ttl_hours=24,
            )
            await upsert_known_relay(
                gamma_app.state.db, "beta.test",
                f"{beta_client.base_url}/api/v1/federation/deliver",
                beta_pk, "manual", ttl_hours=24,
            )

        loop = asyncio.new_event_loop()
        loop.run_until_complete(_seed())
        loop.close()

        alice = _register_agent(alpha_client, "alice")
        bob = _register_agent(beta_client, "bob")
        charlie = _register_agent(gamma_client, "charlie")

        yield {
            "alpha_client": alpha_client,
            "beta_client": beta_client,
            "gamma_client": gamma_client,
            "alpha_agent": alice,
            "beta_agent": bob,
            "gamma_agent": charlie,
            "alpha_relay_sk": alpha_sk,
            "beta_relay_sk": beta_sk,
            "gamma_relay_sk": gamma_sk,
            "alpha_pk": alpha_pk,
            "beta_pk": beta_pk,
            "gamma_pk": gamma_pk,
            "alpha_app": alpha_app,
            "beta_app": beta_app,
            "gamma_app": gamma_app,
        }
