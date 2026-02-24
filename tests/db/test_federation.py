"""Tests for Federation CRUD operations."""

from __future__ import annotations

from uam.db.crud.federation import (
    add_relay_blocklist,
    enqueue_federation,
    get_known_relay,
    get_pending_queue,
    is_relay_blocked,
    log_federation,
    record_relay_failure,
    record_relay_success,
    remove_relay_blocklist,
    upsert_known_relay,
)


# ---------------------------------------------------------------------------
# Known Relays
# ---------------------------------------------------------------------------


async def test_upsert_known_relay_new(session):
    relay = await upsert_known_relay(
        session,
        domain="relay.youam.network",
        federation_url="https://relay.youam.network/federation",
        public_key="pk_relay",
    )
    assert relay.domain == "relay.youam.network"
    assert relay.federation_url == "https://relay.youam.network/federation"
    assert relay.public_key == "pk_relay"
    assert relay.status == "active"


async def test_upsert_known_relay_update(session):
    await upsert_known_relay(
        session,
        domain="relay.youam.network",
        federation_url="https://old.url/federation",
        public_key="pk_old",
    )
    updated = await upsert_known_relay(
        session,
        domain="relay.youam.network",
        federation_url="https://new.url/federation",
        public_key="pk_new",
    )
    assert updated.federation_url == "https://new.url/federation"
    assert updated.public_key == "pk_new"


async def test_get_known_relay(session):
    await upsert_known_relay(
        session,
        domain="relay.youam.network",
        federation_url="https://relay.youam.network/federation",
        public_key="pk_relay",
    )
    found = await get_known_relay(session, "relay.youam.network")
    assert found is not None
    assert found.domain == "relay.youam.network"

    missing = await get_known_relay(session, "nonexistent.network")
    assert missing is None


# ---------------------------------------------------------------------------
# Federation Log
# ---------------------------------------------------------------------------


async def test_log_federation(session):
    entry = await log_federation(
        session,
        message_id="msg-001",
        from_relay="relay-a.network",
        to_relay="relay-b.network",
        direction="outbound",
        hop_count=1,
        status="delivered",
    )
    assert entry.message_id == "msg-001"
    assert entry.from_relay == "relay-a.network"
    assert entry.to_relay == "relay-b.network"
    assert entry.direction == "outbound"
    assert entry.hop_count == 1
    assert entry.status == "delivered"
    assert entry.created_at is not None


# ---------------------------------------------------------------------------
# Federation Queue
# ---------------------------------------------------------------------------


async def test_enqueue_and_get_pending(session):
    entry = await enqueue_federation(
        session,
        target_domain="remote.network",
        envelope='{"encrypted": "data"}',
    )
    assert entry.status == "pending"
    assert entry.target_domain == "remote.network"

    pending = await get_pending_queue(session)
    assert len(pending) == 1
    assert pending[0].id == entry.id


# ---------------------------------------------------------------------------
# Relay Blocklist
# ---------------------------------------------------------------------------


async def test_relay_blocklist_add_check(session):
    await add_relay_blocklist(session, "evil.network", reason="spam")
    assert await is_relay_blocked(session, "evil.network") is True
    assert await is_relay_blocked(session, "good.network") is False


async def test_relay_blocklist_remove(session):
    await add_relay_blocklist(session, "evil.network", reason="spam")
    removed = await remove_relay_blocklist(session, "evil.network")
    assert removed is True
    assert await is_relay_blocked(session, "evil.network") is False


# ---------------------------------------------------------------------------
# Relay Reputation
# ---------------------------------------------------------------------------


async def test_relay_reputation_success_failure(session):
    # Record success (+1 from default 50)
    rep = await record_relay_success(session, "relay.youam.network")
    assert rep.score == 51
    assert rep.messages_forwarded == 1
    assert rep.last_success is not None

    # Record failure (-5)
    rep2 = await record_relay_failure(session, "relay.youam.network")
    assert rep2.score == 46
    assert rep2.messages_rejected == 1
    assert rep2.last_failure is not None
