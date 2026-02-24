"""CRUD operations for BlocklistEntry and AllowlistEntry (spam defense).

Every function takes ``session: AsyncSession`` as its first parameter.
Supports both exact address matching and domain-wildcard patterns
(e.g. ``*::example.com``).
"""

from __future__ import annotations

from sqlalchemy import delete as sa_delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import AllowlistEntry, BlocklistEntry


# ---------------------------------------------------------------------------
# Blocklist
# ---------------------------------------------------------------------------


async def add_blocklist(
    session: AsyncSession, pattern: str, reason: str | None = None
) -> BlocklistEntry:
    """Add a pattern to the blocklist.

    Returns the existing entry if the pattern is already present.
    """
    entry = BlocklistEntry(pattern=pattern, reason=reason)
    session.add(entry)
    try:
        await session.commit()
        await session.refresh(entry)
        return entry
    except IntegrityError:
        await session.rollback()
        stmt = select(BlocklistEntry).where(BlocklistEntry.pattern == pattern)
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()
        assert existing is not None
        return existing


async def remove_blocklist(session: AsyncSession, pattern: str) -> bool:
    """Remove a pattern from the blocklist. Returns ``True`` if removed."""
    stmt = sa_delete(BlocklistEntry).where(BlocklistEntry.pattern == pattern)
    result = await session.execute(stmt)
    await session.commit()
    return (result.rowcount or 0) > 0


async def check_blocklist(session: AsyncSession, address: str) -> bool:
    """Check whether *address* matches the blocklist.

    Matches both exact address and domain wildcard patterns.
    The domain is extracted from the address by splitting on ``::``
    and checking for a ``*::{domain}`` pattern.
    """
    parts = address.split("::")
    domain = parts[-1] if len(parts) > 1 else address
    candidates = [address, f"*::{domain}"]
    stmt = select(BlocklistEntry).where(
        BlocklistEntry.pattern.in_(candidates)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none() is not None


async def list_blocklist(session: AsyncSession) -> list[BlocklistEntry]:
    """List all blocklist entries."""
    stmt = select(BlocklistEntry)
    result = await session.execute(stmt)
    return list(result.scalars().all())


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------


async def add_allowlist(
    session: AsyncSession, pattern: str, reason: str | None = None
) -> AllowlistEntry:
    """Add a pattern to the allowlist.

    Returns the existing entry if the pattern is already present.
    """
    entry = AllowlistEntry(pattern=pattern, reason=reason)
    session.add(entry)
    try:
        await session.commit()
        await session.refresh(entry)
        return entry
    except IntegrityError:
        await session.rollback()
        stmt = select(AllowlistEntry).where(
            AllowlistEntry.pattern == pattern
        )
        result = await session.execute(stmt)
        existing = result.scalar_one_or_none()
        assert existing is not None
        return existing


async def remove_allowlist(session: AsyncSession, pattern: str) -> bool:
    """Remove a pattern from the allowlist. Returns ``True`` if removed."""
    stmt = sa_delete(AllowlistEntry).where(AllowlistEntry.pattern == pattern)
    result = await session.execute(stmt)
    await session.commit()
    return (result.rowcount or 0) > 0


async def check_allowlist(session: AsyncSession, address: str) -> bool:
    """Check whether *address* matches the allowlist.

    Uses the same exact + domain-wildcard matching logic as
    :func:`check_blocklist`.
    """
    parts = address.split("::")
    domain = parts[-1] if len(parts) > 1 else address
    candidates = [address, f"*::{domain}"]
    stmt = select(AllowlistEntry).where(
        AllowlistEntry.pattern.in_(candidates)
    )
    result = await session.execute(stmt)
    return result.scalar_one_or_none() is not None


async def list_allowlist(session: AsyncSession) -> list[AllowlistEntry]:
    """List all allowlist entries."""
    stmt = select(AllowlistEntry)
    result = await session.execute(stmt)
    return list(result.scalars().all())
