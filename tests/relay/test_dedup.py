"""Tests for message deduplication (MSG-03).

Covers:
- record_message_id (new ID, duplicate ID)
- REST dedup (POST /send)
- WebSocket dedup (ws:// inbound)
- Different IDs both delivered
- cleanup_expired
"""

from __future__ import annotations

import pytest

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlmodel import SQLModel, select

from uam.db.crud.dedup import cleanup_expired, record_message_id
from uam.db.models import SeenMessageId
from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
)


# ---------------------------------------------------------------------------
# Unit tests: record_message_id
# ---------------------------------------------------------------------------


@pytest.fixture()
async def session():
    """Create an in-memory async engine with SQLModel tables and yield a session."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


class TestRecordMessageId:
    """Unit tests for the record_message_id CRUD function."""

    @pytest.mark.asyncio
    async def test_record_new_id_returns_true(self, session):
        result = await record_message_id(session, "msg-001", "alice::test.local")
        assert result is True

    @pytest.mark.asyncio
    async def test_record_duplicate_returns_false(self, session):
        await record_message_id(session, "msg-001", "alice::test.local")
        result = await record_message_id(session, "msg-001", "alice::test.local")
        assert result is False

    @pytest.mark.asyncio
    async def test_different_ids_both_succeed(self, session):
        r1 = await record_message_id(session, "msg-001", "alice::test.local")
        r2 = await record_message_id(session, "msg-002", "alice::test.local")
        assert r1 is True
        assert r2 is True


# ---------------------------------------------------------------------------
# Unit tests: cleanup_expired
# ---------------------------------------------------------------------------


class TestCleanupExpired:
    """Unit tests for the cleanup_expired CRUD function."""

    @pytest.mark.asyncio
    async def test_cleanup_removes_old_entries(self, session):
        from datetime import datetime, timedelta

        # Insert an entry with seen_at 10 days ago
        old_entry = SeenMessageId(
            message_id="old-msg",
            from_addr="alice::test.local",
            seen_at=datetime.utcnow() - timedelta(days=10),
        )
        session.add(old_entry)
        await session.commit()

        # Insert a fresh entry
        await record_message_id(session, "new-msg", "alice::test.local")

        deleted = await cleanup_expired(session, max_age_days=7)
        assert deleted == 1

        # Verify old one is gone, new one remains
        result = await session.execute(select(SeenMessageId))
        rows = list(result.scalars().all())
        ids = [row.message_id for row in rows]
        assert "new-msg" in ids
        assert "old-msg" not in ids

    @pytest.mark.asyncio
    async def test_cleanup_returns_zero_when_nothing_expired(self, session):
        await record_message_id(session, "fresh-msg", "alice::test.local")
        deleted = await cleanup_expired(session, max_age_days=7)
        assert deleted == 0


# ---------------------------------------------------------------------------
# Integration tests: REST dedup
# ---------------------------------------------------------------------------


def _register_pair(client):
    """Register alice and bob, return their agent dicts."""
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


def _make_envelope(from_agent, to_agent):
    """Create a signed wire-dict envelope."""
    envelope = create_envelope(
        from_address=from_agent["address"],
        to_address=to_agent["address"],
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"Hello dedup test!",
        signing_key=from_agent["signing_key"],
        recipient_verify_key=to_agent["verify_key"],
    )
    return to_wire_dict(envelope)


class TestRestDedup:
    """Integration tests: duplicate POST /send is silently accepted."""

    def test_rest_duplicate_silently_accepted(self, client):
        alice, bob = _register_pair(client)
        wire = _make_envelope(alice, bob)

        # First send -- should succeed
        resp1 = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp1.status_code == 200
        data1 = resp1.json()
        assert data1["message_id"] == wire["message_id"]

        # Second send with same envelope -- should also 200 (duplicate)
        resp2 = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp2.status_code == 200
        data2 = resp2.json()
        assert data2["delivered"] is True
        assert data2["message_id"] == wire["message_id"]

    def test_rest_different_messages_both_delivered(self, client):
        alice, bob = _register_pair(client)
        wire1 = _make_envelope(alice, bob)
        wire2 = _make_envelope(alice, bob)  # different message_id

        resp1 = client.post(
            "/api/v1/send",
            json={"envelope": wire1},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        resp2 = client.post(
            "/api/v1/send",
            json={"envelope": wire2},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        # Different message IDs
        assert resp1.json()["message_id"] != resp2.json()["message_id"]


# ---------------------------------------------------------------------------
# Integration tests: WebSocket dedup
# ---------------------------------------------------------------------------


class TestWebSocketDedup:
    """Integration tests: duplicate WS inbound is silently ACKed."""

    def test_ws_duplicate_silently_acked(self, client):
        alice, bob = _register_pair(client)
        wire = _make_envelope(alice, bob)

        with client.websocket_connect(f"/ws?token={alice['token']}") as ws:
            # First send
            ws.send_json(wire)
            ack1 = ws.receive_json()
            assert ack1["type"] == "ack"
            assert ack1["message_id"] == wire["message_id"]

            # Duplicate send
            ws.send_json(wire)
            ack2 = ws.receive_json()
            assert ack2["type"] == "ack"
            assert ack2["message_id"] == wire["message_id"]
            assert ack2["delivered"] is True
