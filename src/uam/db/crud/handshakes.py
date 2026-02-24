"""CRUD operations for Handshake entities.

Every function takes ``session: AsyncSession`` as its first parameter.
Read queries filter ``deleted_at IS NULL`` by default.
"""

from __future__ import annotations

from datetime import datetime

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

    hs = await get_handshake_by_id(session, handshake_id)
    if hs is None:
        return None

    hs.status = status
    hs.resolved_at = datetime.utcnow()
    session.add(hs)
    if commit:
        await session.commit()
        await session.refresh(hs)
    else:
        await session.flush()
    return hs


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
