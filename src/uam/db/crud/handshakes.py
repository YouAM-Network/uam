"""CRUD operations for Handshake entities.

Every function takes ``session: AsyncSession`` as its first parameter.
Read queries filter ``deleted_at IS NULL`` by default.

Phase 44 Plan 44-06 (T4.7 H11):
    ``respond_handshake`` is now a single atomic
    ``UPDATE ... WHERE id=? AND status='pending' AND deleted_at IS NULL
    RETURNING *`` so concurrent ``approve`` + ``deny`` on the same
    handshake produce exactly one winner. The previous SELECT-then-
    mutate-in-Python-then-UPDATE pattern silently last-writer-wins:
    both callers observed ``status='pending'`` and both reported
    success, but only one ``status`` value landed in the row with no
    audit-trail signal to the loser.

    The atomic form lets the loser detect rejection via a ``None``
    return value; the route layer in ``relay/routes/handshakes.py``
    already guards on ``result is None`` and surfaces a 404.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import Handshake

_VALID_RESPONSES = frozenset({"approved", "denied", "expired"})


async def create_handshake(
    session: AsyncSession,
    from_addr: str,
    to_addr: str,
    contact_card: dict | None = None,
    *,
    commit: bool = True,
) -> Handshake:
    """Create a new pending handshake request.

    When *commit* is ``False`` the row is flushed but the caller is
    responsible for committing the session.
    """
    hs = Handshake(
        from_addr=from_addr,
        to_addr=to_addr,
        contact_card=contact_card,
        status="pending",
    )
    session.add(hs)
    if commit:
        await session.commit()
        await session.refresh(hs)
    else:
        await session.flush()
    return hs


async def get_pending(
    session: AsyncSession, to_addr: str
) -> list[Handshake]:
    """Get pending handshakes for *to_addr* (soft-delete filtered)."""
    stmt = select(Handshake).where(
        Handshake.to_addr == to_addr,
        Handshake.status == "pending",
        Handshake.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_pending_with_deleted(
    session: AsyncSession, to_addr: str
) -> list[Handshake]:
    """Get pending handshakes including soft-deleted. For admin visibility."""
    stmt = select(Handshake).where(
        Handshake.to_addr == to_addr,
        Handshake.status == "pending",
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def respond_handshake(
    session: AsyncSession, handshake_id: int, status: str, *, commit: bool = True
) -> Handshake | None:
    """Respond to a handshake by updating its status.

    T4.7 H11: atomic ``UPDATE Handshake SET status=?, resolved_at=now
    WHERE id=? AND status='pending' AND deleted_at IS NULL RETURNING *``.
    Concurrent ``approve`` + ``deny`` on the same handshake produce
    exactly one winner: the second writer's WHERE clause matches no
    rows (status was flipped to 'approved' or 'denied' by the first
    writer) and the loser receives ``None``.

    Returns
    -------
    Handshake | None
        The updated row on success. ``None`` if the handshake does not
        exist, has been soft-deleted, or has already been resolved by
        a concurrent caller (race-loss).

    Parameters
    ----------
    status:
        Must be one of ``approved``, ``denied``, or ``expired``.
    commit:
        When ``False`` the change is flushed but the caller is
        responsible for committing the session.

    Raises
    ------
    ValueError
        If *status* is not a valid response.
    """
    if status not in _VALID_RESPONSES:
        raise ValueError(
            f"Invalid handshake response status '{status}'. "
            f"Must be one of: {', '.join(sorted(_VALID_RESPONSES))}"
        )

    # T7.4: tz-aware now() matches Handshake.resolved_at column's
    # DateTime(timezone=True) declaration. resolved_at has no
    # server_default — it's an explicit-action column written here.
    now = datetime.now(timezone.utc)
    stmt = (
        update(Handshake)
        .where(
            Handshake.id == handshake_id,
            Handshake.status == "pending",
            Handshake.deleted_at.is_(None),  # type: ignore[union-attr]
        )
        .values(status=status, resolved_at=now)
        .returning(Handshake)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()

    if commit:
        await session.commit()
    else:
        await session.flush()

    if row is None:
        return None
    # Refresh to keep the ORM identity map consistent with the post-update row.
    await session.refresh(row)
    return row


async def get_handshake_by_id(
    session: AsyncSession, handshake_id: int
) -> Handshake | None:
    """Look up a handshake by primary-key ID (soft-delete filtered)."""
    stmt = select(Handshake).where(
        Handshake.id == handshake_id,
        Handshake.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()
