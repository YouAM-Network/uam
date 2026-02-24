"""CRUD operations for AuditLog entities.

Every function takes ``session: AsyncSession`` as its first parameter.
The audit log is **append-only** -- no update or delete operations are
provided.
"""

from __future__ import annotations

from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import AuditLog


async def log_action(
    session: AsyncSession,
    action: str,
    entity_type: str,
    entity_id: str,
    actor_address: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> AuditLog:
    """Append an entry to the audit log.

    This is the function other modules will call after state changes
    (wiring deferred to Phase 35 relay integration).
    """
    entry = AuditLog(
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        actor_address=actor_address,
        details=details,
        ip_address=ip_address,
    )
    session.add(entry)
    await session.commit()
    await session.refresh(entry)
    return entry


async def query_audit_log(
    session: AsyncSession,
    entity_type: str | None = None,
    entity_id: str | None = None,
    actor_address: str | None = None,
    action: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[AuditLog]:
    """Query the audit log with optional filters.

    Results are ordered by timestamp descending (newest first).
    """
    stmt = select(AuditLog)
    if entity_type is not None:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    if entity_id is not None:
        stmt = stmt.where(AuditLog.entity_id == entity_id)
    if actor_address is not None:
        stmt = stmt.where(AuditLog.actor_address == actor_address)
    if action is not None:
        stmt = stmt.where(AuditLog.action == action)
    stmt = stmt.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit)  # type: ignore[union-attr]
    result = await session.execute(stmt)
    return list(result.scalars().all())


async def count_audit_log(
    session: AsyncSession, entity_type: str | None = None
) -> int:
    """Count audit log entries, optionally filtered by *entity_type*."""
    stmt = select(func.count()).select_from(AuditLog)
    if entity_type is not None:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    result = await session.execute(stmt)
    return result.scalar_one()
