"""Integration tests for the demo widget REST endpoints.

Uses httpx.AsyncClient with ASGI transport against the real FastAPI app.
Lifespan is triggered via the app's lifespan context manager.
"""

from __future__ import annotations

import json
import re

import httpx
import pytest

from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
)
from uam.protocol.crypto import deserialize_verify_key
from uam.relay.app import create_app
from uam.relay.database import get_agent_by_address, register_agent, store_message


@pytest.fixture()
def demo_app(tmp_path, monkeypatch):
    """Create a relay app backed by a temporary database."""
    monkeypatch.setenv("UAM_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("UAM_RELAY_DOMAIN", "youam.network")
    return create_app()


@pytest.fixture()
async def demo_client(demo_app):
    """Async HTTP client with lifespan triggered via the app's context manager."""
    # Manually trigger lifespan so app.state is populated
    async with demo_app.router.lifespan_context(demo_app):
        transport = httpx.ASGITransport(app=demo_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client


class TestCreateSession:
    """POST /api/v1/demo/session"""

    async def test_returns_id_and_address(self, demo_client):
        resp = await demo_client.post("/api/v1/demo/session")
        assert resp.status_code == 200
        data = resp.json()
        assert "session_id" in data
        assert "address" in data
        assert re.match(r"demo-.+::youam\.network$", data["address"])


class TestDemoSend:
    """POST /api/v1/demo/send"""

    async def test_send_requires_valid_session(self, demo_client):
        resp = await demo_client.post("/api/v1/demo/send", json={
            "session_id": "nonexistent",
            "to_address": "someone::youam.network",
            "message": "hello",
        })
        assert resp.status_code == 404


class TestDemoInbox:
    """GET /api/v1/demo/inbox"""

    async def test_inbox_requires_valid_session(self, demo_client):
        resp = await demo_client.get("/api/v1/demo/inbox", params={"session_id": "fake"})
        assert resp.status_code == 404


class TestDemoRoundTrip:
    """End-to-end: create session, send message, receive decrypted reply."""

    async def test_send_and_receive_round_trip(self, demo_app, demo_client):
        # 1. Register a "target" agent directly in the database
        target_sk, target_vk = generate_keypair()
        target_pk_str = serialize_verify_key(target_vk)
        target_address = "hello::youam.network"
        target_token = "target-token-for-test"

        db = demo_app.state.db
        await register_agent(db, target_address, target_pk_str, target_token)

        # 2. Create a demo session
        resp = await demo_client.post("/api/v1/demo/session")
        assert resp.status_code == 200
        session_data = resp.json()
        session_id = session_data["session_id"]
        demo_address = session_data["address"]

        # 3. Send a message from demo to target
        resp = await demo_client.post("/api/v1/demo/send", json={
            "session_id": session_id,
            "to_address": target_address,
            "message": "Hello from demo widget!",
        })
        assert resp.status_code == 200
        assert "message_id" in resp.json()

        # 4. Create a reply from target back to demo (simulate the agent replying)
        demo_agent = await get_agent_by_address(db, demo_address)
        assert demo_agent is not None
        demo_vk = deserialize_verify_key(demo_agent["public_key"])

        reply_envelope = create_envelope(
            from_address=target_address,
            to_address=demo_address,
            message_type=MessageType.MESSAGE,
            payload_plaintext=b"Hey! Welcome to UAM.",
            signing_key=target_sk,
            recipient_verify_key=demo_vk,
            media_type="text/plain",
        )
        reply_wire = to_wire_dict(reply_envelope)
        await store_message(db, target_address, demo_address, json.dumps(reply_wire))

        # 5. Fetch inbox -- should get the decrypted reply
        resp = await demo_client.get("/api/v1/demo/inbox", params={"session_id": session_id})
        assert resp.status_code == 200
        inbox = resp.json()
        assert len(inbox["messages"]) == 1
        msg = inbox["messages"][0]
        assert msg["from_address"] == target_address
        assert msg["content"] == "Hey! Welcome to UAM."
        assert msg["message_id"] == reply_envelope.message_id


class TestDemoInboxFiltering:
    """Inbox should filter out non-message types."""

    async def test_inbox_filters_handshake_messages(self, demo_app, demo_client):
        # 1. Create a demo session
        resp = await demo_client.post("/api/v1/demo/session")
        assert resp.status_code == 200
        session_data = resp.json()
        session_id = session_data["session_id"]
        demo_address = session_data["address"]

        db = demo_app.state.db

        # 2. Register a sender agent
        sender_sk, sender_vk = generate_keypair()
        sender_pk_str = serialize_verify_key(sender_vk)
        sender_address = "sender::youam.network"
        await register_agent(db, sender_address, sender_pk_str, "sender-token")

        # 3. Look up demo agent's public key
        demo_agent = await get_agent_by_address(db, demo_address)
        demo_vk = deserialize_verify_key(demo_agent["public_key"])

        # 4. Create a handshake.request envelope (should be filtered)
        hs_envelope = create_envelope(
            from_address=sender_address,
            to_address=demo_address,
            message_type=MessageType.HANDSHAKE_REQUEST,
            payload_plaintext=b"handshake request data",
            signing_key=sender_sk,
            recipient_verify_key=demo_vk,
        )
        hs_wire = to_wire_dict(hs_envelope)
        await store_message(db, sender_address, demo_address, json.dumps(hs_wire))

        # 5. Inbox should return empty (handshake filtered out)
        resp = await demo_client.get("/api/v1/demo/inbox", params={"session_id": session_id})
        assert resp.status_code == 200
        inbox = resp.json()
        assert len(inbox["messages"]) == 0
