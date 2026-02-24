"""Tests for Message CRUD operations."""

from __future__ import annotations

from datetime import datetime, timedelta

from uam.db.crud.messages import (
    get_inbox,
    get_message_by_id,
    get_thread,
    mark_delivered,
    mark_expired,
    store_message,
)


async def _store(session, msg_id="msg-1", **kwargs):
    """Helper to store a test message with sensible defaults."""
    defaults = dict(
        from_addr="alice::youam.network",
        to_addr="bob::youam.network",
        envelope='{"encrypted": "data"}',
    )
    defaults.update(kwargs)
    return await store_message(session, message_id=msg_id, **defaults)


async def test_store_message(session):
    msg = await _store(session)
    assert msg.message_id == "msg-1"
    assert msg.from_addr == "alice::youam.network"
    assert msg.to_addr == "bob::youam.network"
    assert msg.status == "queued"
    assert msg.envelope == '{"encrypted": "data"}'


async def test_get_inbox(session):
    await _store(session, msg_id="m1", to_addr="bob::youam.network")
    await _store(session, msg_id="m2", to_addr="bob::youam.network")
    await _store(session, msg_id="m3", to_addr="bob::youam.network")
    # Message to a different address -- should not appear
    await _store(session, msg_id="m4", to_addr="carol::youam.network")

    inbox = await get_inbox(session, "bob::youam.network")
    assert len(inbox) == 3
    assert all(m.to_addr == "bob::youam.network" for m in inbox)


async def test_get_inbox_excludes_delivered(session):
    msg = await _store(session, msg_id="m1", to_addr="bob::youam.network")
    await _store(session, msg_id="m2", to_addr="bob::youam.network")

    # Mark first as delivered
    await mark_delivered(session, [msg.id])

    inbox = await get_inbox(session, "bob::youam.network")
    assert len(inbox) == 1
    assert inbox[0].message_id == "m2"


async def test_get_inbox_excludes_expired(session):
    # Store a message that expired in the past
    past = datetime.utcnow() - timedelta(hours=1)
    await _store(session, msg_id="expired-msg", to_addr="bob::youam.network", expires_at=past)
    # Store a valid message
    await _store(session, msg_id="valid-msg", to_addr="bob::youam.network")

    inbox = await get_inbox(session, "bob::youam.network")
    assert len(inbox) == 1
    assert inbox[0].message_id == "valid-msg"


async def test_get_thread(session):
    await _store(session, msg_id="t1", thread_id="thread-abc")
    await _store(session, msg_id="t2", thread_id="thread-abc")
    await _store(session, msg_id="t3", thread_id="thread-other")

    thread = await get_thread(session, "thread-abc")
    assert len(thread) == 2
    assert all(m.thread_id == "thread-abc" for m in thread)


async def test_mark_delivered(session):
    msg1 = await _store(session, msg_id="d1")
    msg2 = await _store(session, msg_id="d2")

    count = await mark_delivered(session, [msg1.id, msg2.id])
    assert count == 2

    # Verify the messages are delivered
    inbox = await get_inbox(session, "bob::youam.network")
    assert len(inbox) == 0


async def test_mark_expired(session):
    past = datetime.utcnow() - timedelta(hours=1)
    await _store(session, msg_id="exp1", expires_at=past)
    await _store(session, msg_id="valid1")  # no expiry

    count = await mark_expired(session)
    assert count == 1

    # Verify valid message still in inbox
    inbox = await get_inbox(session, "bob::youam.network")
    assert len(inbox) == 1
    assert inbox[0].message_id == "valid1"


async def test_get_message_by_id(session):
    await _store(session, msg_id="lookup-me")
    found = await get_message_by_id(session, "lookup-me")
    assert found is not None
    assert found.message_id == "lookup-me"

    # Non-existent
    missing = await get_message_by_id(session, "does-not-exist")
    assert missing is None
