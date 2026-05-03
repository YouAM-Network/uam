"""CRUD operations for Reputation entities.

Every function takes ``session: AsyncSession`` as its first parameter.
Scores are always clamped to the 0--100 range.

Phase 44 Plan 44-06 (T4.7 H1, H6):
    The mutating functions ``record_sent``, ``record_rejected``,
    ``update_score``, and ``set_score`` are now single atomic
    ``UPDATE`` statements with arithmetic in SQL. The previous
    SELECT-then-mutate-in-Python-then-UPDATE pattern was vulnerable
    to lost-update races: 100 concurrent ``record_sent`` calls could
    all read ``messages_sent=N``, all write ``messages_sent=N+1``,
    and lose 99 increments.

    The atomic form is:

        UPDATE reputation
        SET messages_sent = messages_sent + 1, updated_at = now()
        WHERE address = :address

    Both Postgres and SQLite evaluate ``messages_sent + 1`` atomically
    inside the row lock, so 100 concurrent invocations land 100
    increments. ``update_score`` uses the same pattern with a SQL
    ``CASE`` expression to clamp ``MAX(0, MIN(100, score + :delta))``
    portably across both backends.
"""

from __future__ import annotations

from sqlalchemy import case, func, update
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

    T4.7 H6: atomic ``UPDATE`` with arithmetic and clamp evaluated in
    SQL via a ``CASE`` expression. Concurrent ``update_score(addr, +1)``
    calls land all increments without lost updates.

    Returns the updated record or ``None`` if no record exists.
    """
    new_score_expr = case(
        (Reputation.score + delta < 0, 0),
        (Reputation.score + delta > 100, 100),
        else_=Reputation.score + delta,
    )
    stmt = (
        update(Reputation)
        .where(Reputation.address == address)
        .values(score=new_score_expr, updated_at=func.now())
        .returning(Reputation)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    await session.commit()
    if row is None:
        return None
    # Refresh to surface the canonical row (RETURNING already gives us the
    # post-update values; refresh keeps the ORM identity map consistent).
    await session.refresh(row)
    return row


async def set_score(
    session: AsyncSession, address: str, score: int
) -> Reputation | None:
    """Set an absolute score (clamped 0--100).

    T4.7 H6: atomic ``UPDATE`` -- the clamp is computed Python-side
    (a single value, no race) and the assignment is a single SQL
    statement.

    Returns the updated record or ``None`` if no record exists.
    """
    clamped = _clamp(score)
    stmt = (
        update(Reputation)
        .where(Reputation.address == address)
        .values(score=clamped, updated_at=func.now())
        .returning(Reputation)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    await session.commit()
    if row is None:
        return None
    await session.refresh(row)
    return row


async def record_sent(
    session: AsyncSession, address: str
) -> Reputation | None:
    """Increment ``messages_sent`` counter. Auto-inits if no record exists.

    T4.7 H1: atomic ``UPDATE Reputation SET messages_sent =
    messages_sent + 1, updated_at = now() WHERE address = ?``.
    100 concurrent invocations land 100 increments; the lost-update
    race in the prior SELECT-then-mutate implementation is gone.
    """
    # Ensure the row exists before the atomic UPDATE. ``get_reputation_with_default``
    # is idempotent (it swallows IntegrityError on the primary-key collision).
    await get_reputation_with_default(session, address)
    stmt = (
        update(Reputation)
        .where(Reputation.address == address)
        .values(
            messages_sent=Reputation.messages_sent + 1,
            updated_at=func.now(),
        )
        .returning(Reputation)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    await session.commit()
    if row is None:
        return None
    await session.refresh(row)
    return row


async def record_rejected(
    session: AsyncSession, address: str
) -> Reputation | None:
    """Increment ``messages_rejected`` counter. Auto-inits if no record exists.

    T4.7 H1: atomic ``UPDATE`` with arithmetic in SQL -- mirrors
    ``record_sent`` but on the ``messages_rejected`` column.
    """
    await get_reputation_with_default(session, address)
    stmt = (
        update(Reputation)
        .where(Reputation.address == address)
        .values(
            messages_rejected=Reputation.messages_rejected + 1,
            updated_at=func.now(),
        )
        .returning(Reputation)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    await session.commit()
    if row is None:
        return None
    await session.refresh(row)
    return row


async def get_reputation_with_default(
    session: AsyncSession, address: str, default_score: int = 30
) -> Reputation:
    """Get existing reputation or create with *default_score*. Always returns a record."""
    rep = await get_reputation(session, address)
    if rep is not None:
        return rep
    return await init_reputation(session, address, score=default_score)
