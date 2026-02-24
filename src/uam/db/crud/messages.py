"""CRUD operations for Message entities.

Every function takes ``session: AsyncSession`` as its first parameter.
Read queries filter ``deleted_at IS NULL`` by default.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import Message


async def store_message(
    session: AsyncSession,
    message_id: str,
    from_addr: str,
    to_addr: str,
    envelope: str,
    thread_id: str | None = None,
    expires_at: datetime | None = None,
    *,
    commit: bool = True,
) -> Message:
    """Store a new message envelope for delivery.

    When *commit* is ``False`` the row is flushed (so auto-generated
    columns like ``id`` are available) but the caller is responsible
    for committing the session.
    """
    msg = Message(
        message_id=message_id,
        from_addr=from_addr,
        to_addr=to_addr,
        envelope=envelope,
        thread_id=thread_id,
        expires_at=expires_at,
        status="queued",
    )
    session.add(msg)
    if commit:
        await session.commit()
        await session.refresh(msg)
    else:
        await session.flush()
    return msg


async def get_inbox(
    session: AsyncSession, to_addr: str, limit: int = 50
) -> list[Message]:
    """Fetch queued, non-expired messages for *to_addr* (soft-delete filtered)."""
    now = datetime.utcnow()
    stmt = (
        select(Message)
        .where(
            Message.to_addr == to_addr,
            Message.status == "queued",
            Message.deleted_at.is_(None),  # type: ignore[union-attr]
        )
        .where(
            (Message.expires_at.is_(None)) | (Message.expires_at > now)  # type: ignore[union-attr]
        )
        .order_by(Message.id.asc())  # type: ignore[union-attr]
        .limit(limit)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_inbox_with_deleted(
    session: AsyncSession, to_addr: str, limit: int = 50
) -> list[Message]:
    """Fetch queued, non-expired messages including soft-deleted.

    For admin visibility into soft-deleted messages.
    """
    now = datetime.utcnow()
    stmt = (
        select(Message)
        .where(
            Message.to_addr == to_addr,
            Message.status == "queued",
        )
        .where(
            (Message.expires_at.is_(None)) | (Message.expires_at > now)  # type: ignore[union-attr]
        )
        .order_by(Message.id.asc())  # type: ignore[union-attr]
        .limit(limit)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_thread(
    session: AsyncSession, thread_id: str, limit: int = 100
) -> list[Message]:
    """Fetch messages in a thread (soft-delete filtered), oldest first."""
    stmt = (
        select(Message)
        .where(
            Message.thread_id == thread_id,
            Message.deleted_at.is_(None),  # type: ignore[union-attr]
        )
        .order_by(Message.created_at.asc())  # type: ignore[union-attr]
        .limit(limit)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_thread_with_deleted(
    session: AsyncSession, thread_id: str, limit: int = 100
) -> list[Message]:
    """Fetch messages in a thread including soft-deleted. For admin thread inspection."""
    stmt = (
        select(Message)
        .where(Message.thread_id == thread_id)
        .order_by(Message.created_at.asc())  # type: ignore[union-attr]
        .limit(limit)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def mark_delivered(
    session: AsyncSession, message_ids: list[int]
) -> int:
    """Mark messages as delivered by primary-key IDs. Returns count updated."""
    if not message_ids:
        return 0
    now = datetime.utcnow()
    stmt = (
        update(Message)
        .where(Message.id.in_(message_ids))  # type: ignore[union-attr]
        .values(status="delivered", delivered_at=now)
    )
    result = await session.execute(stmt)
    await session.commit()
    return result.rowcount  # type: ignore[return-value]


async def mark_expired(session: AsyncSession) -> int:
    """Expire queued messages whose expires_at is in the past. Returns count."""
    now = datetime.utcnow()
    stmt = (
        update(Message)
        .where(
            Message.expires_at < now,
            Message.status == "queued",
            Message.deleted_at.is_(None),  # type: ignore[union-attr]
        )
        .values(status="expired")
    )
    result = await session.execute(stmt)
    await session.commit()
    return result.rowcount  # type: ignore[return-value]


async def purge_expired(
    session: AsyncSession, retention_days: int = 90
) -> int:
    """Hard-delete old soft-deleted and expired/delivered messages.

    Removes:
    - Messages soft-deleted more than *retention_days* ago.
    - Messages with status ``expired`` or ``delivered`` created more than
      *retention_days* ago.

    Returns the total count deleted.
    """
    cutoff = datetime.utcnow() - timedelta(days=retention_days)
    total = 0

    # Soft-deleted past retention
    stmt1 = delete(Message).where(
        Message.deleted_at.isnot(None),  # type: ignore[union-attr]
        Message.deleted_at < cutoff,  # type: ignore[operator]
    )
    r1 = await session.execute(stmt1)
    total += r1.rowcount  # type: ignore[operator]

    # Expired / delivered past retention
    stmt2 = delete(Message).where(
        Message.status.in_(["expired", "delivered"]),  # type: ignore[union-attr]
        Message.created_at < cutoff,
    )
    r2 = await session.execute(stmt2)
    total += r2.rowcount  # type: ignore[operator]

    await session.commit()
    return total


async def get_message_by_id(
    session: AsyncSession, message_id: str
) -> Message | None:
    """Look up a message by its ``message_id`` field (soft-delete filtered)."""
    stmt = select(Message).where(
        Message.message_id == message_id,
        Message.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()
