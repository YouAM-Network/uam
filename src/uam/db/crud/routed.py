"""CRUD operations for RoutedMessage entities (receipt binding, MSG-05).

Every function takes ``session: AsyncSession`` as its first parameter.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete as sa_delete
from sqlalchemy import update as sa_update
from sqlalchemy.ext.asyncio import AsyncSession

from uam.db.models import RoutedMessage

# How many receipts one routed message can bind.
MAX_RECEIPTS_PER_MESSAGE = 3


async def record_routed(
    session: AsyncSession, message_id: str, from_addr: str, to_addr: str
) -> None:
    """Record that this relay accepted *message_id* from -> to.

    Flushed, not committed: it belongs to the caller's delivery transaction.
    """
    session.add(RoutedMessage(message_id=message_id, from_addr=from_addr, to_addr=to_addr))
    await session.flush()


async def claim_receipt(
    session: AsyncSession, reply_to: str, receipt_from: str, receipt_to: str
) -> bool:
    """Bind a receipt from *receipt_from* to *receipt_to* about *reply_to*.

    True when *reply_to* was routed the other way (receipt_to ->
    receipt_from) and has bound fewer than ``MAX_RECEIPTS_PER_MESSAGE``
    receipts so far; the count is taken in the same statement.
    Flushed, not committed.
    """
    stmt = (
        sa_update(RoutedMessage)
        .where(
            RoutedMessage.message_id == reply_to,
            RoutedMessage.from_addr == receipt_to,
            RoutedMessage.to_addr == receipt_from,
            RoutedMessage.receipt_count < MAX_RECEIPTS_PER_MESSAGE,
        )
        .values(receipt_count=RoutedMessage.receipt_count + 1)
    )
    result = await session.execute(stmt)
    return result.rowcount == 1


async def cleanup_routed(session: AsyncSession, max_age_days: int = 7) -> int:
    """Delete routed-message rows older than *max_age_days*.

    Returns the number of rows deleted.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    stmt = sa_delete(RoutedMessage).where(RoutedMessage.routed_at < cutoff)
    result = await session.execute(stmt)
    await session.commit()
    return result.rowcount  # type: ignore[return-value]
