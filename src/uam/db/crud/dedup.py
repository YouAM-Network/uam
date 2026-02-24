"""CRUD operations for SeenMessageId (deduplication) entities.

Every function takes ``session: AsyncSession`` as its first parameter.
Uses ``IntegrityError`` for duplicate detection on the primary key.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import delete as sa_delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import SeenMessageId


async def record_message_id(
    session: AsyncSession, message_id: str, from_addr: str, *, commit: bool = True
) -> bool:
    """Record a message ID as seen.

    Returns ``True`` if the ID was new (inserted successfully).
    Returns ``False`` if it was already seen (duplicate).

    When *commit* is ``False`` the row is flushed (so constraints are
    checked) but the caller is responsible for committing the session.
    """
    entry = SeenMessageId(message_id=message_id, from_addr=from_addr)
    session.add(entry)
    try:
        if commit:
            await session.commit()
        else:
            await session.flush()
        return True
    except IntegrityError:
        await session.rollback()
        return False


async def check_seen(session: AsyncSession, message_id: str) -> bool:
    """Check whether a message ID has already been seen."""
    stmt = select(SeenMessageId).where(SeenMessageId.message_id == message_id)
    result = await session.execute(stmt)
    return result.scalar_one_or_none() is not None


async def cleanup_expired(
    session: AsyncSession, max_age_days: int = 7
) -> int:
    """Delete seen-message entries older than *max_age_days*.

    Returns the number of rows deleted.
    """
    cutoff = datetime.utcnow() - timedelta(days=max_age_days)
    stmt = sa_delete(SeenMessageId).where(SeenMessageId.seen_at < cutoff)
    result = await session.execute(stmt)
    await session.commit()
    return result.rowcount  # type: ignore[return-value]
