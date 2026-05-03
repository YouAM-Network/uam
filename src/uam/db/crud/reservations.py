"""CRUD operations for Reservation entities.

Every function takes ``session: AsyncSession`` as its first parameter.
Read queries filter ``deleted_at IS NULL`` by default.

Handles the full reservation lifecycle: check availability, create,
look up active/by-token, claim, expire, and rate-limit counting.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import Agent, Reservation


class AddressAlreadyReserved(Exception):
    """Raised when a reservation is attempted for an address that already
    has an active (status='reserved') reservation."""

    pass


async def check_address_available(
    session: AsyncSession, address: str
) -> bool:
    """Return ``True`` if *address* is not registered as an agent AND has
    no active reservation (status='reserved' and not expired).
    """
    # Check if an active agent exists with this address
    agent_stmt = select(Agent).where(
        Agent.address == address,
        Agent.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    agent_result = await session.execute(agent_stmt)
    if agent_result.scalar_one_or_none() is not None:
        return False

    # Check if an active reservation exists
    now = datetime.utcnow()
    res_stmt = select(Reservation).where(
        Reservation.address == address,
        Reservation.status == "reserved",
        Reservation.expires_at > now,
        Reservation.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    res_result = await session.execute(res_stmt)
    if res_result.scalar_one_or_none() is not None:
        return False

    return True


async def create_reservation(
    session: AsyncSession,
    address: str,
    claim_token: str,
    ip_address: str,
    expires_at: datetime,
    *,
    commit: bool = True,
) -> Reservation:
    """Insert a new reservation with status='reserved'.

    On ``IntegrityError`` (duplicate address+status), rolls back and
    raises :class:`AddressAlreadyReserved`.
    """
    reservation = Reservation(
        address=address,
        claim_token=claim_token,
        status="reserved",
        ip_address=ip_address,
        expires_at=expires_at,
    )
    session.add(reservation)
    try:
        if commit:
            await session.commit()
            await session.refresh(reservation)
        else:
            await session.flush()
        return reservation
    except IntegrityError:
        await session.rollback()
        raise AddressAlreadyReserved(
            f"Address {address!r} already has an active reservation"
        )


async def get_active_reservation(
    session: AsyncSession, address: str
) -> Reservation | None:
    """Return the active reservation for *address* (status='reserved',
    not expired, not soft-deleted), or ``None``.
    """
    now = datetime.utcnow()
    stmt = select(Reservation).where(
        Reservation.address == address,
        Reservation.status == "reserved",
        Reservation.expires_at > now,
        Reservation.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def get_reservation_by_token(
    session: AsyncSession, claim_token: str
) -> Reservation | None:
    """Return the reservation matching *claim_token* (soft-delete filtered).

    Does **not** filter by status or expiry -- the caller decides how to
    handle expired or already-claimed tokens.
    """
    stmt = select(Reservation).where(
        Reservation.claim_token == claim_token,
        Reservation.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def claim_reservation(
    session: AsyncSession, claim_token: str, *, commit: bool = True
) -> Reservation | None:
    """Atomically claim a reservation by its *claim_token* (T4.4).

    Single-statement ``UPDATE ... WHERE pre-state ... RETURNING`` —
    collapses the previous SELECT-then-UPDATE race window into one
    round-trip. Postgres and SQLite (>=3.35; project uses 3.51.2) both
    support RETURNING.

    The WHERE clause enforces every precondition that the previous
    Python-level checks did:

      * ``claim_token`` matches
      * ``status == 'reserved'`` (not yet claimed, not yet expired/swept)
      * ``expires_at > now`` (TTL still in the future)
      * ``deleted_at IS NULL`` (not soft-deleted)

    Returns the updated :class:`Reservation` row (``status='claimed'``,
    ``claimed_at=now``) on success, or ``None`` if the token did not
    exist, was already claimed, was expired, or was soft-deleted.

    Concurrency contract: two concurrent calls with the same valid
    token produce EXACTLY ONE winner. The database serializes the
    UPDATE — the first caller flips ``status`` from ``'reserved'`` to
    ``'claimed'`` and the row is returned; every subsequent caller's
    UPDATE matches zero rows because the WHERE pre-state no longer
    holds, and ``scalar_one_or_none()`` returns ``None``.

    Side benefit (H10 from REVIEW-data-layer): the
    ``expire_reservations`` sweeper and ``claim_reservation`` racing
    at the boundary now produce a clean outcome — whichever fires
    first wins; the loser sees ``rowcount=0`` and returns ``None``.

    The ``commit`` parameter preserves the existing API contract used
    by ``routes/reserve.py`` (which batches claim + agent registration
    in a single outer transaction with ``commit=False``).
    """
    now = datetime.utcnow()
    stmt = (
        update(Reservation)
        .where(
            Reservation.claim_token == claim_token,
            Reservation.status == "reserved",
            Reservation.expires_at > now,
            Reservation.deleted_at.is_(None),  # type: ignore[union-attr]
        )
        .values(status="claimed", claimed_at=now)
        .returning(Reservation)
    )
    result = await session.execute(stmt)
    row = result.scalar_one_or_none()
    if commit:
        await session.commit()
    return row


async def expire_reservations(
    session: AsyncSession, *, commit: bool = True
) -> int:
    """Bulk-update all past-deadline reservations to status='expired'.

    Returns the count of expired reservations.
    """
    now = datetime.utcnow()
    stmt = (
        update(Reservation)
        .where(
            Reservation.status == "reserved",
            Reservation.expires_at <= now,
        )
        .values(status="expired")
    )
    result = await session.execute(stmt)
    if commit:
        await session.commit()
    return result.rowcount  # type: ignore[return-value]


async def count_active_reservations_by_ip(
    session: AsyncSession, ip_address: str, window_hours: int = 1
) -> int:
    """Count active reservations from *ip_address* within the time window.

    Counts reservations with status IN ('reserved', 'claimed') created
    within the last *window_hours* hours.  This supports the
    5-per-IP-per-hour rate limit (RES-06).
    """
    cutoff = datetime.utcnow() - timedelta(hours=window_hours)
    stmt = (
        select(func.count())
        .select_from(Reservation)
        .where(
            Reservation.ip_address == ip_address,
            Reservation.status.in_(["reserved", "claimed"]),  # type: ignore[union-attr]
            Reservation.created_at >= cutoff,
        )
    )
    result = await session.execute(stmt)
    return result.scalar_one()
