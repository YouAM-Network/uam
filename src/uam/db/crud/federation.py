"""CRUD operations for federation entities.

Covers five sub-tables: ``known_relays``, ``federation_log``,
``federation_queue``, ``relay_blocklist``/``relay_allowlist``, and
``relay_reputation``.

Every function takes ``session: AsyncSession`` as its first parameter.

Phase 44 Plan 44-06 (T4.7 H2):
    The state-machine and counter mutations are now single atomic
    ``UPDATE`` statements:

      - ``update_queue_entry``: ``UPDATE ... WHERE id=? AND status=?
        ... RETURNING *`` with an ``expected_current_status`` parameter
        (default ``'pending'``) so concurrent workers cannot both pick
        up the same pending row.
      - ``record_relay_success`` / ``record_relay_failure``: atomic
        counter increment + clamped score adjustment via SQL ``CASE``
        expressions. 50 concurrent ``record_relay_success`` calls land
        50 increments — the prior SELECT-then-mutate pattern lost
        updates.

    SQLite-only SQL in ``relay_reputation.py`` (REVIEW-relay-core M9)
    is OUT OF SCOPE for this plan and deferred to Phase 47/48.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import case, delete as sa_delete, func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import (
    FederationLog,
    FederationQueueEntry,
    KnownRelay,
    RelayAllowlistEntry,
    RelayBlocklistEntry,
    RelayReputation,
)


def _clamp(score: int) -> int:
    """Clamp *score* to the 0--100 range."""
    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Known Relays
# ---------------------------------------------------------------------------


async def upsert_known_relay(
    session: AsyncSession,
    domain: str,
    federation_url: str,
    public_key: str,
    discovered_via: str = "well-known",
    ttl_hours: int = 1,
) -> KnownRelay:
    """Create or update a known relay record for *domain*."""
    stmt = select(KnownRelay).where(KnownRelay.domain == domain)
    result = await session.execute(stmt)
    existing = result.scalar_one_or_none()

    now = datetime.now(timezone.utc)
    if existing is not None:
        existing.federation_url = federation_url
        existing.public_key = public_key
        existing.discovered_via = discovered_via
        existing.last_verified = now
        existing.ttl_hours = ttl_hours
        existing.status = "active"
        session.add(existing)
        await session.commit()
        await session.refresh(existing)
        return existing

    relay = KnownRelay(
        domain=domain,
        federation_url=federation_url,
        public_key=public_key,
        discovered_via=discovered_via,
        ttl_hours=ttl_hours,
    )
    session.add(relay)
    await session.commit()
    await session.refresh(relay)
    return relay


async def get_known_relay(
    session: AsyncSession, domain: str
) -> KnownRelay | None:
    """Get a known relay by *domain*."""
    stmt = select(KnownRelay).where(KnownRelay.domain == domain)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


# ---------------------------------------------------------------------------
# Federation Log
# ---------------------------------------------------------------------------


async def log_federation(
    session: AsyncSession,
    message_id: str,
    from_relay: str,
    to_relay: str,
    direction: str,
    hop_count: int,
    status: str,
    error: str | None = None,
    *,
    commit: bool = True,
) -> FederationLog:
    """Append an entry to the federation log.

    When *commit* is ``False`` the row is flushed but the caller is
    responsible for committing the session.
    """
    entry = FederationLog(
        message_id=message_id,
        from_relay=from_relay,
        to_relay=to_relay,
        direction=direction,
        hop_count=hop_count,
        status=status,
        error=error,
    )
    session.add(entry)
    if commit:
        await session.commit()
        await session.refresh(entry)
    else:
        await session.flush()
    return entry


async def query_federation_log(
    session: AsyncSession,
    message_id: str | None = None,
    from_relay: str | None = None,
    limit: int = 100,
) -> list[FederationLog]:
    """Query the federation log with optional filters.

    Results are ordered by ``created_at`` descending.
    """
    stmt = select(FederationLog)
    if message_id is not None:
        stmt = stmt.where(FederationLog.message_id == message_id)
    if from_relay is not None:
        stmt = stmt.where(FederationLog.from_relay == from_relay)
    stmt = stmt.order_by(FederationLog.created_at.desc()).limit(limit)  # type: ignore[union-attr]
    result = await session.execute(stmt)
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Federation Queue
# ---------------------------------------------------------------------------


async def enqueue_federation(
    session: AsyncSession,
    target_domain: str,
    envelope: str,
    via: str = "[]",
    hop_count: int = 0,
    *,
    commit: bool = True,
) -> FederationQueueEntry:
    """Add a message to the outbound federation queue.

    When *commit* is ``False`` the row is flushed but the caller is
    responsible for committing the session.
    """
    entry = FederationQueueEntry(
        target_domain=target_domain,
        envelope=envelope,
        via=via,
        hop_count=hop_count,
        status="pending",
        next_retry=datetime.now(timezone.utc),
    )
    session.add(entry)
    if commit:
        await session.commit()
        await session.refresh(entry)
    else:
        await session.flush()
    return entry


async def get_pending_queue(
    session: AsyncSession, limit: int = 50
) -> list[FederationQueueEntry]:
    """Get pending queue entries whose retry time has elapsed."""
    now = datetime.now(timezone.utc)
    stmt = (
        select(FederationQueueEntry)
        .where(
            FederationQueueEntry.status == "pending",
            FederationQueueEntry.next_retry <= now,
        )
        .order_by(FederationQueueEntry.created_at.asc())  # type: ignore[union-attr]
        .limit(limit)
    )
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def update_queue_entry(
    session: AsyncSession,
    entry_id: int,
    status: str,
    error: str | None = None,
    next_retry: datetime | None = None,
    *,
    expected_current_status: str = "pending",
) -> FederationQueueEntry | None:
    """Atomically transition a queue entry's status (T4.7 H2 part).

    ``UPDATE federation_queue SET status=?, error=?, attempt_count=
    attempt_count + 1[, next_retry=?] WHERE id=? AND status=?
    RETURNING *``

    Concurrent retry-loop workers cannot both pick up the same pending
    row: only the first writer's WHERE clause matches; subsequent
    writers see ``status != expected_current_status`` and receive
    ``None``. Callers in ``relay/app.py`` already transition rows from
    ``pending`` (the get_pending_queue filter), so the default
    ``expected_current_status='pending'`` matches today's behaviour.
    Pass an alternate value when transitioning from a non-pending state
    (e.g. ``in_progress`` -> ``completed``).

    Returns the updated row, or ``None`` if no row matched (entry
    missing, or pre-state did not match — race-loss).
    """
    values: dict = {
        "status": status,
        "error": error,
        "attempt_count": FederationQueueEntry.attempt_count + 1,
    }
    if next_retry is not None:
        values["next_retry"] = next_retry

    stmt = (
        update(FederationQueueEntry)
        .where(
            FederationQueueEntry.id == entry_id,
            FederationQueueEntry.status == expected_current_status,
        )
        .values(**values)
        .returning(FederationQueueEntry)
    )
    result = await session.execute(stmt)
    entry = result.scalar_one_or_none()
    await session.commit()
    if entry is None:
        return None
    await session.refresh(entry)
    return entry


async def delete_completed_queue(
    session: AsyncSession, max_age_days: int = 7
) -> int:
    """Hard-delete completed/failed queue entries older than *max_age_days*."""
    # T7.4: tz-aware cutoff matches FederationQueueEntry.created_at column's
    # DateTime(timezone=True) declaration.
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    stmt = sa_delete(FederationQueueEntry).where(
        FederationQueueEntry.status.in_(["completed", "failed"]),
        FederationQueueEntry.created_at < cutoff,  # type: ignore[operator]
    )
    result = await session.execute(stmt)
    await session.commit()
    return result.rowcount  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Relay Blocklist / Allowlist
# ---------------------------------------------------------------------------


async def is_relay_blocked(session: AsyncSession, domain: str) -> bool:
    """Check if a relay domain is on the blocklist."""
    stmt = select(RelayBlocklistEntry).where(
        RelayBlocklistEntry.domain == domain
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none() is not None


async def is_relay_allowed(session: AsyncSession, domain: str) -> bool:
    """Check if a relay domain is on the allowlist."""
    stmt = select(RelayAllowlistEntry).where(
        RelayAllowlistEntry.domain == domain
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none() is not None


async def add_relay_blocklist(
    session: AsyncSession, domain: str, reason: str | None = None
) -> RelayBlocklistEntry:
    """Add a relay domain to the blocklist.

    Returns the existing entry if the domain is already blocked.
    """
    entry = RelayBlocklistEntry(domain=domain, reason=reason)
    session.add(entry)
    try:
        await session.commit()
        await session.refresh(entry)
        return entry
    except IntegrityError:
        await session.rollback()
        stmt = select(RelayBlocklistEntry).where(
            RelayBlocklistEntry.domain == domain
        )
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()
        assert existing is not None
        return existing


async def remove_relay_blocklist(
    session: AsyncSession, domain: str
) -> bool:
    """Remove a relay domain from the blocklist. Returns ``True`` if removed."""
    stmt = sa_delete(RelayBlocklistEntry).where(
        RelayBlocklistEntry.domain == domain
    )
    result = await session.execute(stmt)
    await session.commit()
    return (result.rowcount or 0) > 0


async def list_relay_blocklist(
    session: AsyncSession,
) -> list[RelayBlocklistEntry]:
    """List all relay blocklist entries."""
    stmt = select(RelayBlocklistEntry)
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def add_relay_allowlist(
    session: AsyncSession, domain: str, reason: str | None = None
) -> RelayAllowlistEntry:
    """Add a relay domain to the allowlist.

    Returns the existing entry if the domain is already allowed.
    """
    entry = RelayAllowlistEntry(domain=domain, reason=reason)
    session.add(entry)
    try:
        await session.commit()
        await session.refresh(entry)
        return entry
    except IntegrityError:
        await session.rollback()
        stmt = select(RelayAllowlistEntry).where(
            RelayAllowlistEntry.domain == domain
        )
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()
        assert existing is not None
        return existing


async def remove_relay_allowlist(
    session: AsyncSession, domain: str
) -> bool:
    """Remove a relay domain from the allowlist. Returns ``True`` if removed."""
    stmt = sa_delete(RelayAllowlistEntry).where(
        RelayAllowlistEntry.domain == domain
    )
    result = await session.execute(stmt)
    await session.commit()
    return (result.rowcount or 0) > 0


async def list_relay_allowlist(
    session: AsyncSession,
) -> list[RelayAllowlistEntry]:
    """List all relay allowlist entries."""
    stmt = select(RelayAllowlistEntry)
    result = await session.execute(stmt)
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Relay Reputation
# ---------------------------------------------------------------------------


async def get_relay_reputation(
    session: AsyncSession, domain: str
) -> RelayReputation | None:
    """Get the reputation record for a relay *domain*."""
    stmt = select(RelayReputation).where(RelayReputation.domain == domain)
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def upsert_relay_reputation(
    session: AsyncSession, domain: str, score: int = 50
) -> RelayReputation:
    """Create or return existing reputation record for *domain*."""
    rep = RelayReputation(domain=domain, score=_clamp(score))
    session.add(rep)
    try:
        await session.commit()
        await session.refresh(rep)
        return rep
    except IntegrityError:
        await session.rollback()
        existing = await get_relay_reputation(session, domain)
        assert existing is not None
        return existing


async def record_relay_success(
    session: AsyncSession, domain: str
) -> RelayReputation:
    """Increment ``messages_forwarded`` and boost score (+1, clamped).

    T4.7 H2: atomic ``UPDATE relay_reputation SET messages_forwarded =
    messages_forwarded + 1, score = MIN(100, score + 1), last_success =
    now(), updated_at = now() WHERE domain = ?``. Concurrent invocations
    land all increments — the prior SELECT-then-mutate pattern lost
    updates.

    The clamp at 100 is expressed as a SQL ``CASE`` so the arithmetic
    and clamp evaluate atomically inside the row lock.
    """
    # Ensure the row exists. ``upsert_relay_reputation`` is idempotent
    # via swallow-IntegrityError on the primary-key collision.
    await upsert_relay_reputation(session, domain)
    new_score_expr = case(
        (RelayReputation.score + 1 > 100, 100),
        else_=RelayReputation.score + 1,
    )
    now = datetime.now(timezone.utc)
    stmt = (
        update(RelayReputation)
        .where(RelayReputation.domain == domain)
        .values(
            messages_forwarded=RelayReputation.messages_forwarded + 1,
            score=new_score_expr,
            last_success=now,
            updated_at=func.now(),
        )
        .returning(RelayReputation)
    )
    result = await session.execute(stmt)
    rep = result.scalar_one_or_none()
    await session.commit()
    assert rep is not None  # upsert ensured the row exists
    await session.refresh(rep)
    return rep


async def record_relay_failure(
    session: AsyncSession, domain: str
) -> RelayReputation:
    """Increment ``messages_rejected`` and penalise score (-5, clamped).

    T4.7 H2: atomic ``UPDATE`` mirroring ``record_relay_success`` but on
    the failure column with a ``-5`` score adjustment clamped at 0.
    """
    await upsert_relay_reputation(session, domain)
    new_score_expr = case(
        (RelayReputation.score - 5 < 0, 0),
        else_=RelayReputation.score - 5,
    )
    now = datetime.now(timezone.utc)
    stmt = (
        update(RelayReputation)
        .where(RelayReputation.domain == domain)
        .values(
            messages_rejected=RelayReputation.messages_rejected + 1,
            score=new_score_expr,
            last_failure=now,
            updated_at=func.now(),
        )
        .returning(RelayReputation)
    )
    result = await session.execute(stmt)
    rep = result.scalar_one_or_none()
    await session.commit()
    assert rep is not None  # upsert ensured the row exists
    await session.refresh(rep)
    return rep
