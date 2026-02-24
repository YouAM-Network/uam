"""Allow/block list for relay-level spam filtering (SPAM-01).

Two-form pattern matching consistent with SDK Phase 8 ContactBook:
- Exact address: ``spammer::evil.com``
- Domain wildcard: ``*::evil.com``

All lookups are O(1) via in-memory set membership.  Persistence is
handled through AsyncSession queries against the ``blocklist`` and
``allowlist`` tables.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import AllowlistEntry, BlocklistEntry

logger = logging.getLogger(__name__)


def _classify_pattern(pattern: str) -> tuple[str, str]:
    """Classify a pattern as exact or domain.

    Returns ``("exact", pattern)`` or ``("domain", domain_part)``.
    Raises :class:`ValueError` if the pattern does not contain ``::``
    """
    if "::" not in pattern:
        raise ValueError(
            f"Invalid pattern {pattern!r}: must contain '::' "
            "(e.g. 'name::domain' or '*::domain')"
        )
    local, domain = pattern.split("::", 1)
    if local == "*":
        return ("domain", domain)
    return ("exact", pattern)


class AllowBlockList:
    """In-memory allow/block list backed by async DB persistence.

    Four sets provide O(1) lookup:
    - ``_blocked_exact``: exact address matches
    - ``_blocked_domains``: domain-level blocks
    - ``_allowed_exact``: exact address matches
    - ``_allowed_domains``: domain-level allows
    """

    def __init__(self) -> None:
        self._blocked_exact: set[str] = set()
        self._blocked_domains: set[str] = set()
        self._allowed_exact: set[str] = set()
        self._allowed_domains: set[str] = set()

    # ------------------------------------------------------------------
    # Lookup (O(1))
    # ------------------------------------------------------------------

    def is_blocked(self, address: str) -> bool:
        """Return True if *address* matches a block pattern."""
        if address in self._blocked_exact:
            return True
        if "::" in address:
            domain = address.split("::", 1)[1]
            if domain in self._blocked_domains:
                return True
        return False

    def is_allowed(self, address: str) -> bool:
        """Return True if *address* matches an allow pattern."""
        if address in self._allowed_exact:
            return True
        if "::" in address:
            domain = address.split("::", 1)[1]
            if domain in self._allowed_domains:
                return True
        return False

    # ------------------------------------------------------------------
    # Load from DB (startup)
    # ------------------------------------------------------------------

    async def load(self, session: AsyncSession) -> None:
        """Load all patterns from blocklist/allowlist tables into memory."""
        self._blocked_exact.clear()
        self._blocked_domains.clear()
        self._allowed_exact.clear()
        self._allowed_domains.clear()

        result = await session.execute(select(BlocklistEntry))
        for row in result.scalars().all():
            kind, value = _classify_pattern(row.pattern)
            if kind == "domain":
                self._blocked_domains.add(value)
            else:
                self._blocked_exact.add(value)

        result = await session.execute(select(AllowlistEntry))
        for row in result.scalars().all():
            kind, value = _classify_pattern(row.pattern)
            if kind == "domain":
                self._allowed_domains.add(value)
            else:
                self._allowed_exact.add(value)

        logger.info(
            "Loaded %d blocked (%d exact, %d domain) and %d allowed (%d exact, %d domain) patterns",
            len(self._blocked_exact) + len(self._blocked_domains),
            len(self._blocked_exact),
            len(self._blocked_domains),
            len(self._allowed_exact) + len(self._allowed_domains),
            len(self._allowed_exact),
            len(self._allowed_domains),
        )

    # ------------------------------------------------------------------
    # Blocklist CRUD
    # ------------------------------------------------------------------

    async def add_blocked(
        self, session: AsyncSession, pattern: str, reason: str | None = None
    ) -> None:
        """Add a pattern to the blocklist (DB + in-memory)."""
        kind, value = _classify_pattern(pattern)
        entry = BlocklistEntry(pattern=pattern, reason=reason)
        session.add(entry)
        try:
            await session.commit()
        except Exception:
            await session.rollback()
            # Already exists (unique constraint) -- ignore
            return
        if kind == "domain":
            self._blocked_domains.add(value)
        else:
            self._blocked_exact.add(value)
        logger.info("Blocked pattern %r (reason: %s)", pattern, reason)

    async def remove_blocked(self, session: AsyncSession, pattern: str) -> bool:
        """Remove a pattern from the blocklist. Returns True if it existed."""
        kind, value = _classify_pattern(pattern)
        result = await session.execute(
            select(BlocklistEntry).where(BlocklistEntry.pattern == pattern)
        )
        entry = result.scalar_one_or_none()
        if entry is None:
            return False
        await session.delete(entry)
        await session.commit()
        if kind == "domain":
            self._blocked_domains.discard(value)
        else:
            self._blocked_exact.discard(value)
        logger.info("Unblocked pattern %r", pattern)
        return True

    async def list_blocked(self, session: AsyncSession) -> list[dict[str, Any]]:
        """Return all blocklist entries from DB."""
        result = await session.execute(
            select(BlocklistEntry).order_by(BlocklistEntry.id)
        )
        rows = result.scalars().all()
        return [
            {
                "id": row.id,
                "pattern": row.pattern,
                "reason": row.reason,
                "created_at": str(row.created_at),
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Allowlist CRUD
    # ------------------------------------------------------------------

    async def add_allowed(
        self, session: AsyncSession, pattern: str, reason: str | None = None
    ) -> None:
        """Add a pattern to the allowlist (DB + in-memory)."""
        kind, value = _classify_pattern(pattern)
        entry = AllowlistEntry(pattern=pattern, reason=reason)
        session.add(entry)
        try:
            await session.commit()
        except Exception:
            await session.rollback()
            return
        if kind == "domain":
            self._allowed_domains.add(value)
        else:
            self._allowed_exact.add(value)
        logger.info("Allowed pattern %r (reason: %s)", pattern, reason)

    async def remove_allowed(self, session: AsyncSession, pattern: str) -> bool:
        """Remove a pattern from the allowlist. Returns True if it existed."""
        kind, value = _classify_pattern(pattern)
        result = await session.execute(
            select(AllowlistEntry).where(AllowlistEntry.pattern == pattern)
        )
        entry = result.scalar_one_or_none()
        if entry is None:
            return False
        await session.delete(entry)
        await session.commit()
        if kind == "domain":
            self._allowed_domains.discard(value)
        else:
            self._allowed_exact.discard(value)
        logger.info("Removed allow pattern %r", pattern)
        return True

    async def list_allowed(self, session: AsyncSession) -> list[dict[str, Any]]:
        """Return all allowlist entries from DB."""
        result = await session.execute(
            select(AllowlistEntry).order_by(AllowlistEntry.id)
        )
        rows = result.scalars().all()
        return [
            {
                "id": row.id,
                "pattern": row.pattern,
                "reason": row.reason,
                "created_at": str(row.created_at),
            }
            for row in rows
        ]
