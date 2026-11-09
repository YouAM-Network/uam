"""A webhook delivery joins the transaction of the message it belongs to.

The three ingress paths (HTTP send, WebSocket send, federation) each hold a
write transaction while choosing how to deliver.  The delivery row must be
written in that same transaction: on SQLite a second session cannot write
until the first commits, so a separate session stalls for the busy timeout
and then fails.  The POST goes out only once the transaction has committed.
"""

from __future__ import annotations

import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import uam.relay.routes.federation as federation_routes
from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
)
from uam.relay.app import create_app
from uam.relay.relay_auth import sign_federation_request

WEBHOOK_URL = "https://hooks.example.com/uam"
REMOTE_RELAY = "remote.example"
REMOTE_SENDER = "carol::remote.example"


async def _committed_rows(table: str) -> int:
    """Rows another connection can see: only what has been committed."""
    url = os.environ["DATABASE_URL"]
    if url.startswith("postgresql"):
        import asyncpg

        conn = await asyncpg.connect(url.replace("+asyncpg", ""))
        try:
            return await conn.fetchval(f"SELECT COUNT(*) FROM {table}")
        finally:
            await conn.close()
    with sqlite3.connect(os.environ["UAM_DB_PATH"]) as conn:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


class _Receiver:
    """Stands in for the webhook endpoint and notes what was committed."""

    def __init__(self):
        self.posts: list[dict] = []

    async def post(self, url, *, content=None, headers=None):
        self.posts.append({
            "url": url,
            "deliveries": await _committed_rows("webhook_deliveries"),
            "seen": await _committed_rows("seen_message_ids"),
        })
        return MagicMock(status_code=200)

    def wait_for_post(self, timeout: float = 5.0) -> dict:
        deadline = time.monotonic() + timeout
        while not self.posts and time.monotonic() < deadline:
            time.sleep(0.01)
        assert self.posts, "webhook was never posted"
        return self.posts[0]


@pytest.fixture()
def receiver(app):
    """Point the relay's webhook client at a fake endpoint."""
    fake = _Receiver()
    with patch(
        "uam.relay.webhook.async_validate_webhook_url",
        new_callable=AsyncMock,
        return_value=(True, ""),
    ):
        yield fake


def _use_receiver(app, receiver):
    client = AsyncMock()
    client.post = receiver.post
    app.state.webhook_service._http_client = client


def _set_webhook(client, agent):
    with patch("uam.relay.webhook_validator.is_public_ip", return_value=True):
        resp = client.put(
            f"/api/v1/agents/{agent['address']}/webhook",
            json={"webhook_url": WEBHOOK_URL},
            headers={"Authorization": f"Bearer {agent['token']}"},
        )
    assert resp.status_code == 200, resp.text


def test_http_send_to_a_webhook_recipient(
    client, app, receiver, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    _set_webhook(client, bob)
    _use_receiver(app, receiver)

    resp = client.post(
        "/api/v1/send",
        json={"envelope": make_envelope(alice, bob)},
        headers={"Authorization": f"Bearer {alice['token']}"},
    )

    assert resp.status_code == 200, resp.text
    # Started, not confirmed: the webhook's receipt.delivered confirms it
    assert resp.json()["status"] == "relayed"
    assert resp.json()["delivered"] is False
    post = receiver.wait_for_post()
    assert post["url"] == WEBHOOK_URL
    assert post["deliveries"] == 1  # committed before the POST went out
    assert post["seen"] == 1


def test_websocket_send_to_a_webhook_recipient(
    client, app, receiver, registered_agent_pair, make_envelope
):
    alice, bob = registered_agent_pair
    _set_webhook(client, bob)
    _use_receiver(app, receiver)

    with client.websocket_connect(
        "/ws", headers={"Authorization": f"Bearer {alice['token']}"}
    ) as ws:
        ws.send_json(make_envelope(alice, bob))
        ack = ws.receive_json()

    assert ack["type"] == "ack"
    assert ack["status"] == "relayed"
    assert ack["delivered"] is False
    assert receiver.wait_for_post()["deliveries"] == 1


@pytest.fixture()
def federated(tmp_path, monkeypatch):
    import uam.db.engine as _eng
    import uam.db.session as _sess

    _eng._engine = None
    _sess._session_factory = None
    db_path = str(tmp_path / "fed.db")
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("UAM_DB_PATH", db_path)
    monkeypatch.setenv("UAM_RELAY_DOMAIN", "test.local")
    monkeypatch.setenv("UAM_FEDERATION_ENABLED", "true")
    monkeypatch.setenv("UAM_RELAY_KEY_PATH", str(tmp_path / "relay_key.pem"))

    relay_sk, relay_vk = generate_keypair()
    sender_sk, sender_vk = generate_keypair()

    async def fake_relay_key(_session, from_relay):
        return serialize_verify_key(relay_vk) if from_relay == REMOTE_RELAY else None

    async def fake_sender_key(_session, address, _service, _settings):
        return serialize_verify_key(sender_vk) if address == REMOTE_SENDER else None

    monkeypatch.setattr(federation_routes, "_get_relay_public_key", fake_relay_key)
    monkeypatch.setattr(federation_routes, "_resolve_remote_sender_key", fake_sender_key)

    app = create_app()
    with TestClient(app) as c:
        yield c, app, relay_sk, sender_sk

    _eng._engine = None
    _sess._session_factory = None


def test_federated_mail_to_a_webhook_recipient(federated):
    client, app, relay_sk, sender_sk = federated
    sk, vk = generate_keypair()
    resp = client.post(
        "/api/v1/register",
        json={"agent_name": "bob", "public_key": serialize_verify_key(vk)},
    )
    assert resp.status_code == 200, resp.text
    bob = resp.json()
    _set_webhook(client, bob)

    receiver = _Receiver()
    _use_receiver(app, receiver)
    wire = to_wire_dict(create_envelope(
        from_address=REMOTE_SENDER,
        to_address=bob["address"],
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"hello from another relay",
        signing_key=sender_sk,
        recipient_verify_key=vk,
    ))
    body = {
        "envelope": wire,
        "via": [],
        "hop_count": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "from_relay": REMOTE_RELAY,
        "nonce": secrets.token_urlsafe(16),
    }

    with patch(
        "uam.relay.webhook.async_validate_webhook_url",
        new_callable=AsyncMock,
        return_value=(True, ""),
    ):
        resp = client.post(
            "/api/v1/federation/deliver",
            json=body,
            headers={"X-UAM-Relay-Signature": sign_federation_request(body, relay_sk)},
        )
        assert resp.status_code == 200, resp.text
        assert receiver.wait_for_post()["deliveries"] == 1
