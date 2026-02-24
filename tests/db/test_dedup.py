"""Tests for SeenMessageId (deduplication) CRUD operations."""

from __future__ import annotations

from datetime import datetime, timedelta

from uam.db.crud.dedup import (
    check_seen,
    cleanup_expired,
    record_message_id,
)
from uam.db.models import SeenMessageId


async def test_record_new_message_id(session):
    result = await record_message_id(session, "msg-001", "alice::youam.network")
    assert result is True

    # Verify it was stored
    is_seen = await check_seen(session, "msg-001")
    assert is_seen is True


async def test_record_duplicate(session):
    first = await record_message_id(session, "msg-dup", "alice::youam.network")
    assert first is True

    second = await record_message_id(session, "msg-dup", "alice::youam.network")
    assert second is False


async def test_cleanup_expired(session):
    # Record a message
    await record_message_id(session, "old-msg", "alice::youam.network")

    # Manually set its seen_at to the past via session.add
    from sqlmodel import select
    stmt = select(SeenMessageId).where(SeenMessageId.message_id == "old-msg")
    result = await session.execute(stmt)
    entry = result.scalar_one()
    entry.seen_at = datetime.utcnow() - timedelta(days=10)
    session.add(entry)
    await session.commit()

    # Record a fresh message
    await record_message_id(session, "new-msg", "bob::youam.network")

    # Cleanup with 7-day max age
    deleted = await cleanup_expired(session, max_age_days=7)
    assert deleted == 1

    # Old message should be gone, new one should remain
    assert await check_seen(session, "old-msg") is False
    assert await check_seen(session, "new-msg") is True
