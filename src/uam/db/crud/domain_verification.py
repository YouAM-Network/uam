"""CRUD operations for DomainVerification entities.

Every function takes ``session: AsyncSession`` as its first parameter.
Read queries filter ``deleted_at IS NULL`` and ``status='verified'`` by
default.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import DomainVerification


async def upsert_verification(
    session: AsyncSession,
    agent_address: str,
    domain: str,
    public_key: str,
    method: str = "dns",
    ttl_hours: int = 24,
) -> DomainVerification:
    """Create or update a domain verification record.

    If an active record already exists for *agent_address* + *domain*,
    its fields are refreshed.  Otherwise a new record is created.
    """
    stmt = select(DomainVerification).where(
        DomainVerification.agent_address == agent_address,
        DomainVerification.domain == domain,
        DomainVerification.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    result = await session.execute(stmt)
    existing = result.scalar_one_or_none()

    now = datetime.utcnow()
    if existing is not None:
        existing.public_key = public_key
        existing.method = method
        existing.verified_at = now
        existing.last_checked = now
        existing.ttl_hours = ttl_hours
        existing.status = "verified"
        session.add(existing)
        await session.commit()
        await session.refresh(existing)
        return existing

    record = DomainVerification(
        agent_address=agent_address,
        domain=domain,
        public_key=public_key,
        method=method,
        ttl_hours=ttl_hours,
    )
    session.add(record)
    await session.commit()
    await session.refresh(record)
    return record


async def get_verification(
    session: AsyncSession, agent_address: str
) -> DomainVerification | None:
    """Get the verified domain record for *agent_address*."""
    stmt = select(DomainVerification).where(
        DomainVerification.agent_address == agent_address,
        DomainVerification.status == "verified",
        DomainVerification.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def get_verification_by_domain(
    session: AsyncSession, domain: str
) -> DomainVerification | None:
    """Get the verified record for a specific *domain*."""
    stmt = select(DomainVerification).where(
        DomainVerification.domain == domain,
        DomainVerification.status == "verified",
        DomainVerification.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def list_expired(session: AsyncSession) -> list[DomainVerification]:
    """List verified records whose TTL has elapsed.

    For cross-DB compatibility, all verified records are fetched and
    filtered in Python based on ``last_checked + ttl_hours``.
    """
    stmt = select(DomainVerification).where(
        DomainVerification.status == "verified",
        DomainVerification.deleted_at.is_(None),  # type: ignore[union-attr]
    )
    result = await session.execute(stmt)
    records = list(result.scalars().all())

    now = datetime.utcnow()
    expired = [
        r
        for r in records
        if (now - r.last_checked).total_seconds() > r.ttl_hours * 3600
    ]
    return expired


async def downgrade_verification(
    session: AsyncSession, verification_id: int
) -> DomainVerification | None:
    """Mark a verification record as expired."""
    stmt = select(DomainVerification).where(
        DomainVerification.id == verification_id
    )
    result = await session.execute(stmt)
    record = result.scalar_one_or_none()
    if record is None:
        return None
    record.status = "expired"
    session.add(record)
    await session.commit()
    await session.refresh(record)
    return record


async def update_verification_timestamp(
    session: AsyncSession, verification_id: int
) -> DomainVerification | None:
    """Refresh the ``last_checked`` timestamp on a verification record."""
    stmt = select(DomainVerification).where(
        DomainVerification.id == verification_id
    )
    result = await session.execute(stmt)
    record = result.scalar_one_or_none()
    if record is None:
        return None
    record.last_checked = datetime.utcnow()
    session.add(record)
    await session.commit()
    await session.refresh(record)
    return record
