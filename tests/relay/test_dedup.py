"""Tests for message deduplication (MSG-03).

Covers:
- record_message_id (new ID, duplicate ID)
- REST dedup (POST /send)
- WebSocket dedup (ws:// inbound)
- Different IDs both delivered
- cleanup_expired_dedup
- Migration creates table
- Migration is idempotent
"""

from __future__ import annotations

import asyncio
import json

import aiosqlite
import pytest
from fastapi.testclient import TestClient

from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
)
from uam.relay.database import (
    cleanup_expired_dedup,
    init_db,
    record_message_id,
)


# ---------------------------------------------------------------------------
# Unit tests: record_message_id
# ---------------------------------------------------------------------------


class TestRecordMessageId:
    """Unit tests for the record_message_id helper."""

    @pytest.fixture(autouse=True)
    async def _setup_db(self, tmp_path):
        self.db = await init_db(str(tmp_path / "dedup.db"))
        yield
        await self.db.close()

    @pytest.mark.asyncio
    async def test_record_new_id_returns_true(self):
        result = await record_message_id(self.db, "msg-001", "alice::test.local")
        assert result is True

    @pytest.mark.asyncio
    async def test_record_duplicate_returns_false(self):
        await record_message_id(self.db, "msg-001", "alice::test.local")
        result = await record_message_id(self.db, "msg-001", "alice::test.local")
        assert result is False

    @pytest.mark.asyncio
    async def test_different_ids_both_succeed(self):
        r1 = await record_message_id(self.db, "msg-001", "alice::test.local")
        r2 = await record_message_id(self.db, "msg-002", "alice::test.local")
        assert r1 is True
        assert r2 is True


# ---------------------------------------------------------------------------
# Unit tests: cleanup_expired_dedup
# ---------------------------------------------------------------------------


class TestCleanupExpiredDedup:
    """Unit tests for the cleanup_expired_dedup helper."""

    @pytest.fixture(autouse=True)
    async def _setup_db(self, tmp_path):
        self.db = await init_db(str(tmp_path / "dedup.db"))
        yield
        await self.db.close()

    @pytest.mark.asyncio
    async def test_cleanup_removes_old_entries(self):
        # Insert an entry with seen_at 10 days ago
        await self.db.execute(
            "INSERT INTO seen_message_ids (message_id, from_addr, seen_at) "
            "VALUES (?, ?, datetime('now', '-10 days'))",
            ("old-msg", "alice::test.local"),
        )
        # Insert a fresh entry
        await record_message_id(self.db, "new-msg", "alice::test.local")
        await self.db.commit()

        deleted = await cleanup_expired_dedup(self.db, max_age_days=7)
        assert deleted == 1

        # Verify old one is gone, new one remains
        cursor = await self.db.execute(
            "SELECT message_id FROM seen_message_ids"
        )
        rows = await cursor.fetchall()
        ids = [row[0] for row in rows]
        assert "new-msg" in ids
        assert "old-msg" not in ids

    @pytest.mark.asyncio
    async def test_cleanup_returns_zero_when_nothing_expired(self):
        await record_message_id(self.db, "fresh-msg", "alice::test.local")
        deleted = await cleanup_expired_dedup(self.db, max_age_days=7)
        assert deleted == 0


# ---------------------------------------------------------------------------
# Unit tests: migration
# ---------------------------------------------------------------------------


class TestMigration:
    """Tests for the PRAGMA user_version migration framework."""

    @pytest.mark.asyncio
    async def test_migration_creates_table(self, tmp_path):
        db = await init_db(str(tmp_path / "migrate.db"))
        # Verify table exists by inserting
        result = await record_message_id(db, "test-id", "alice::test.local")
        assert result is True
        # Verify user_version is at latest migration (v2 = expires column)
        cursor = await db.execute("PRAGMA user_version")
        row = await cursor.fetchone()
        assert row[0] >= 1  # At least migration v1 applied
        await db.close()

    @pytest.mark.asyncio
    async def test_migration_is_idempotent(self, tmp_path):
        db_path = str(tmp_path / "migrate.db")
        # Run init_db twice on same file
        db1 = await init_db(db_path)
        await record_message_id(db1, "test-id", "alice::test.local")
        version1_cursor = await db1.execute("PRAGMA user_version")
        version1 = (await version1_cursor.fetchone())[0]
        await db1.close()

        db2 = await init_db(db_path)
        # Original entry should still exist
        result = await record_message_id(db2, "test-id", "alice::test.local")
        assert result is False  # duplicate, data survived
        # Version unchanged after second init
        cursor = await db2.execute("PRAGMA user_version")
        row = await cursor.fetchone()
        assert row[0] == version1
        await db2.close()


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
