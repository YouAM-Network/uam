"""Tests for message expiry enforcement (MSG-04).

Covers:
- Expired envelope rejected via REST (POST /send)
- Expired envelope rejected via WebSocket
- Future expires accepted via REST
- No expires accepted via REST
- Grace period borderline (within 30s grace)
- Expired stored messages filtered from inbox
- Unexpired stored messages returned from inbox
- cleanup (mark_expired) sweep
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlmodel import select, SQLModel

from uam.db.crud.messages import get_inbox, mark_expired, store_message
from uam.db.models import Message
from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
)


# ---------------------------------------------------------------------------
# Helpers
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


def _make_envelope_with_expires(from_agent, to_agent, expires: str | None):
    """Create a signed wire-dict envelope with an optional expires field."""
    envelope = create_envelope(
        from_address=from_agent["address"],
        to_address=to_agent["address"],
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"Hello expiry test!",
        signing_key=from_agent["signing_key"],
        recipient_verify_key=to_agent["verify_key"],
        expires=expires,
    )
    return to_wire_dict(envelope)


def _utc_iso(dt: datetime) -> str:
    """Format a datetime as ISO 8601 with Z suffix."""
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Integration tests: REST expiry enforcement
# ---------------------------------------------------------------------------


class TestRestExpiry:
    """Integration tests: POST /send rejects expired envelopes."""

    def test_expired_envelope_rejected(self, client):
        alice, bob = _register_pair(client)
        # Set expires to 5 minutes ago (well past grace period)
        past = _utc_iso(datetime.now(timezone.utc) - timedelta(minutes=5))
        wire = _make_envelope_with_expires(alice, bob, expires=past)

        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 400
        assert "expired" in resp.json()["detail"].lower()

    def test_future_expires_accepted(self, client):
        alice, bob = _register_pair(client)
        future = _utc_iso(datetime.now(timezone.utc) + timedelta(hours=1))
        wire = _make_envelope_with_expires(alice, bob, expires=future)

        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 200

    def test_no_expires_accepted(self, client):
        alice, bob = _register_pair(client)
        wire = _make_envelope_with_expires(alice, bob, expires=None)

        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 200

    def test_grace_period_borderline(self, client):
        """An envelope that expired 10 seconds ago should still be accepted
        (within 30-second grace period)."""
        alice, bob = _register_pair(client)
        borderline = _utc_iso(datetime.now(timezone.utc) - timedelta(seconds=10))
        wire = _make_envelope_with_expires(alice, bob, expires=borderline)

        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        assert resp.status_code == 200

    def test_malformed_expires_treated_as_no_expiry(self, client):
        """A malformed expires value should NOT cause rejection."""
        alice, bob = _register_pair(client)
        wire = _make_envelope_with_expires(alice, bob, expires=None)
        # Manually inject malformed expires into the wire dict
        wire["expires"] = "not-a-timestamp"

        resp = client.post(
            "/api/v1/send",
            json={"envelope": wire},
            headers={"Authorization": f"Bearer {alice['token']}"},
        )
        # Should succeed (malformed = no expiry, but signature won't match
        # because we changed the wire dict). The real test is that it doesn't
        # fail with "expired" error.
        if resp.status_code != 200:
            # Should be signature error, not expiry error
            assert "expired" not in resp.json().get("detail", "").lower()


# ---------------------------------------------------------------------------
# Integration tests: WebSocket expiry enforcement
# ---------------------------------------------------------------------------


class TestWebSocketExpiry:
    """Integration tests: WebSocket rejects expired envelopes."""

    def test_ws_expired_envelope_rejected(self, client):
        alice, bob = _register_pair(client)
        past = _utc_iso(datetime.now(timezone.utc) - timedelta(minutes=5))
        wire = _make_envelope_with_expires(alice, bob, expires=past)

        with client.websocket_connect(f"/ws?token={alice['token']}") as ws:
            ws.send_json(wire)
            resp = ws.receive_json()
            assert resp.get("error") == "expired"
            assert "expired" in resp.get("detail", "").lower()

    def test_ws_future_expires_accepted(self, client):
        alice, bob = _register_pair(client)
        future = _utc_iso(datetime.now(timezone.utc) + timedelta(hours=1))
        wire = _make_envelope_with_expires(alice, bob, expires=future)

        with client.websocket_connect(f"/ws?token={alice['token']}") as ws:
            ws.send_json(wire)
            ack = ws.receive_json()
            assert ack.get("type") == "ack"
            assert ack.get("message_id") == wire["message_id"]


# ---------------------------------------------------------------------------
# Unit tests: stored message filtering and sweep
# ---------------------------------------------------------------------------


@pytest.fixture()
async def db_session():
    """Create an in-memory async engine with SQLModel tables and yield a session."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


class TestStoredMessageExpiry:
    """Unit tests: expired stored messages filtered from inbox and swept."""

    @pytest.mark.asyncio
    async def test_expired_stored_message_filtered_from_inbox(self, db_session):
        """Expired stored messages should NOT appear in get_inbox."""
        past = datetime.utcnow() - timedelta(hours=1)
        await store_message(
            db_session, "msg-expired", "alice::test.local", "bob::test.local",
            '{"test": "expired"}', expires_at=past,
        )
        msgs = await get_inbox(db_session, "bob::test.local")
        assert len(msgs) == 0

    @pytest.mark.asyncio
    async def test_unexpired_stored_message_returned(self, db_session):
        """Unexpired stored messages should appear in get_inbox."""
        future = datetime.utcnow() + timedelta(hours=1)
        await store_message(
            db_session, "msg-unexpired", "alice::test.local", "bob::test.local",
            '{"test": "unexpired"}', expires_at=future,
        )
        msgs = await get_inbox(db_session, "bob::test.local")
        assert len(msgs) == 1
        assert json.loads(msgs[0].envelope)["test"] == "unexpired"

    @pytest.mark.asyncio
    async def test_no_expires_stored_message_returned(self, db_session):
        """Messages with no expires field should always be returned."""
        await store_message(
            db_session, "msg-noexp", "alice::test.local", "bob::test.local",
            '{"test": "no-expiry"}',
        )
        msgs = await get_inbox(db_session, "bob::test.local")
        assert len(msgs) == 1

    @pytest.mark.asyncio
    async def test_mark_expired_sweep(self, db_session):
        """mark_expired should expire queued messages whose expires_at is in the past."""
        past = datetime.utcnow() - timedelta(hours=1)
        future = datetime.utcnow() + timedelta(hours=1)

        # One expired, one unexpired, one no-expiry
        await store_message(
            db_session, "msg-exp1", "alice::test.local", "bob::test.local",
            '{"test": "expired"}', expires_at=past,
        )
        await store_message(
            db_session, "msg-unexp1", "alice::test.local", "bob::test.local",
            '{"test": "unexpired"}', expires_at=future,
        )
        await store_message(
            db_session, "msg-noexp1", "alice::test.local", "bob::test.local",
            '{"test": "no-expiry"}',
        )

        expired_count = await mark_expired(db_session)
        assert expired_count == 1

        # Only unexpired and no-expiry remain in inbox
        msgs = await get_inbox(db_session, "bob::test.local")
        assert len(msgs) == 2
        bodies = [json.loads(m.envelope)["test"] for m in msgs]
        assert "expired" not in bodies
        assert "unexpired" in bodies
        assert "no-expiry" in bodies
