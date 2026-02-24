"""CRUD operations for Reputation entities.

Every function takes ``session: AsyncSession`` as its first parameter.
Scores are always clamped to the 0--100 range.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import Reputation


def _clamp(score: int) -> int:
    """Clamp *score* to the 0--100 range."""
    return max(0, min(100, score))


async def init_reputation(
    session: AsyncSession, address: str, score: int = 30
) -> Reputation:
    """Create a reputation record, or return the existing one.

    Uses try/except around commit for upsert-like behaviour -- if a
    record already exists (``IntegrityError`` on the primary key),
    the existing row is returned instead.
    """
    rep = Reputation(address=address, score=_clamp(score))
    session.add(rep)
    try:
        await session.commit()
        await session.refresh(rep)
        return rep
    except IntegrityError:
        await session.rollback()
        existing = await get_reputation(session, address)
        assert existing is not None  # PK exists since IntegrityError fired
        return existing


async def get_reputation(
    session: AsyncSession, address: str
) -> Reputation | None:
    """Get the reputation record for *address*."""
    stmt = select(Reputation).where(Reputation.address == address)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def update_score(
    session: AsyncSession, address: str, delta: int
) -> Reputation | None:
    """Add *delta* to the current score (clamped 0--100).

    Returns the updated record or ``None`` if no record exists.
    """
    rep = await get_reputation(session, address)
    if rep is None:
        return None
    rep.score = _clamp(rep.score + delta)
    rep.updated_at = datetime.utcnow()
    session.add(rep)
    await session.commit()
    await session.refresh(rep)
    return rep


async def set_score(
    session: AsyncSession, address: str, score: int
) -> Reputation | None:
    """Set an absolute score (clamped 0--100).

    Returns the updated record or ``None`` if no record exists.
    """
    rep = await get_reputation(session, address)
    if rep is None:
        return None
    rep.score = _clamp(score)
    rep.updated_at = datetime.utcnow()
    session.add(rep)
    await session.commit()
    await session.refresh(rep)
    return rep


async def record_sent(
    session: AsyncSession, address: str
) -> Reputation | None:
    """Increment ``messages_sent`` counter. Auto-inits if no record exists."""
    rep = await get_reputation_with_default(session, address)
    rep.messages_sent += 1
    rep.updated_at = datetime.utcnow()
    session.add(rep)
    await session.commit()
    await session.refresh(rep)
    return rep


async def record_rejected(
    session: AsyncSession, address: str
) -> Reputation | None:
    """Increment ``messages_rejected`` counter. Auto-inits if no record exists."""
    rep = await get_reputation_with_default(session, address)
    rep.messages_rejected += 1
    rep.updated_at = datetime.utcnow()
    session.add(rep)
    await session.commit()
    await session.refresh(rep)
    return rep


async def get_reputation_with_default(
    session: AsyncSession, address: str, default_score: int = 30
) -> Reputation:
    """Get existing reputation or create with *default_score*. Always returns a record."""
    rep = await get_reputation(session, address)
    if rep is not None:
        return rep
    return await init_reputation(session, address, score=default_score)
