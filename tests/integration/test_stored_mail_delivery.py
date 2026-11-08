"""Stored mail through a real relay and a real SDK agent.

The relay's domain and the hostname in its URL differ here, as they do in
production: youam.network is served from relay.youam.network.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

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
from uam.sdk.agent import Agent


@pytest.fixture()
def relay(tmp_path, monkeypatch):
    monkeypatch.setenv("UAM_DB_PATH", str(tmp_path / "relay.db"))
    monkeypatch.setenv("UAM_RELAY_DOMAIN", "test.local")
    with TestClient(create_app()) as client:
        # The relay reads this; an SDK on another machine would not have it.
        monkeypatch.delenv("UAM_RELAY_DOMAIN")
        yield client


def _a_day_later():
    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + timedelta(days=1)

    return patch("uam.sdk.agent.datetime", Later)


async def test_a_message_stored_for_a_day_is_delivered(relay, tmp_path):
    alice_sk, alice_vk = generate_keypair()
    alice = relay.post("/api/v1/register", json={
        "agent_name": "alice", "public_key": serialize_verify_key(alice_vk),
    }).json()

    bob = Agent(
        "bob",
        relay="http://testserver",
        key_dir=str(tmp_path / "keys"),
        auto_register=False,
        transport="http",
    )
    assert bob._config.relay_domain != "test.local"
    bob._key_manager.load_or_generate("bob")
    registered = relay.post("/api/v1/register", json={
        "agent_name": "bob", "public_key": bob.public_key,
    }).json()
    bob._address = registered["address"]
    await bob._contact_book.open()
    await bob._contact_book.add_contact(alice["address"], serialize_verify_key(alice_vk))

    async def features():
        return set(relay.get("/api/v1/versions").json()["features"])

    bob._fetch_relay_features = features
    await bob._replay_cache.created_at()
    bob._replay_cache._created_at = (
        datetime.now(timezone.utc) - timedelta(days=30)
    ).timestamp()

    try:
        wire = to_wire_dict(create_envelope(
            from_address=alice["address"],
            to_address=bob._address,
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"hello from yesterday",
            signing_key=alice_sk,
            recipient_verify_key=bob._key_manager.verify_key,
        ))
        sent = relay.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert sent.status_code == 200, sent.text

        [stored] = relay.get(
            f"/api/v1/inbox/{bob._address}",
            headers={"Authorization": f"Bearer {registered['token']}"},
        ).json()["messages"]

        with _a_day_later():
            received = await bob._process_inbound(stored)

        assert received is not None
        assert received.content == "hello from yesterday"
    finally:
        await bob.close()
