"""Allow/block list for relay-level federation filtering (FED-07).

Domain-only filtering for peer relay domains.  Unlike the agent-level
:class:`AllowBlockList` (which uses ``name::domain`` patterns), relay
filtering operates on plain domain strings (e.g. ``"evil-relay.com"``).

All lookups are O(1) via in-memory set membership.  Persistence is
handled through AsyncSession queries against the ``relay_blocklist`` and
``relay_allowlist`` tables.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from uam.db.models import RelayAllowlistEntry, RelayBlocklistEntry

logger = logging.getLogger(__name__)


class RelayAllowBlockList:
    """In-memory allow/block list for peer relay domains, backed by async DB.

    Two sets provide O(1) lookup:
    - ``_blocked``: blocked relay domains
    - ``_allowed``: allowed relay domains
    """

    def __init__(self) -> None:
        self._blocked: set[str] = set()
        self._allowed: set[str] = set()

    # ------------------------------------------------------------------
    # Lookup (O(1))
    # ------------------------------------------------------------------

    def is_blocked(self, domain: str) -> bool:
        """Return True if *domain* is on the relay blocklist."""
        return domain in self._blocked

    def is_allowed(self, domain: str) -> bool:
        """Return True if *domain* is on the relay allowlist."""
        return domain in self._allowed

    # ------------------------------------------------------------------
    # Load from DB (startup)
    # ------------------------------------------------------------------

    async def load(self, session: AsyncSession) -> None:
        """Load all domains from relay_blocklist/relay_allowlist tables."""
        self._blocked.clear()
        self._allowed.clear()

        result = await session.execute(select(RelayBlocklistEntry))
        for row in result.scalars().all():
            self._blocked.add(row.domain)

        result = await session.execute(select(RelayAllowlistEntry))
        for row in result.scalars().all():
            self._allowed.add(row.domain)

        logger.info(
            "Loaded %d blocked and %d allowed relay domains",
            len(self._blocked),
            len(self._allowed),
        )

    # ------------------------------------------------------------------
    # Blocklist CRUD
    # ------------------------------------------------------------------

    async def add_blocked(
        self, session: AsyncSession, domain: str, reason: str | None = None
    ) -> None:
        """Block a relay domain (DB + in-memory)."""
        entry = RelayBlocklistEntry(domain=domain, reason=reason)
        session.add(entry)
        try:
            await session.commit()
        except Exception:
            await session.rollback()
            return
        self._blocked.add(domain)
        logger.info("Blocked relay domain %r (reason: %s)", domain, reason)

    async def remove_blocked(self, session: AsyncSession, domain: str) -> bool:
        """Unblock a relay domain.  Returns True if it existed."""
        result = await session.execute(
            select(RelayBlocklistEntry).where(RelayBlocklistEntry.domain == domain)
        )
        entry = result.scalar_one_or_none()
        if entry is None:
            return False
        await session.delete(entry)
        await session.commit()
        self._blocked.discard(domain)
        logger.info("Unblocked relay domain %r", domain)
        return True

    async def list_blocked(self, session: AsyncSession) -> list[dict[str, Any]]:
        """Return all blocklist entries from DB."""
        result = await session.execute(
            select(RelayBlocklistEntry).order_by(RelayBlocklistEntry.id)
        )
        rows = result.scalars().all()
        return [
            {
                "id": row.id,
                "domain": row.domain,
                "reason": row.reason,
                "created_at": str(row.created_at),
            }
            for row in rows
        ]

    # ------------------------------------------------------------------
    # Allowlist CRUD
    # ------------------------------------------------------------------

    async def add_allowed(
        self, session: AsyncSession, domain: str, reason: str | None = None
    ) -> None:
        """Allowlist a relay domain (DB + in-memory)."""
        entry = RelayAllowlistEntry(domain=domain, reason=reason)
        session.add(entry)
        try:
            await session.commit()
        except Exception:
            await session.rollback()
            return
        self._allowed.add(domain)
        logger.info("Allowed relay domain %r (reason: %s)", domain, reason)

    async def remove_allowed(self, session: AsyncSession, domain: str) -> bool:
        """Remove relay from allowlist.  Returns True if it existed."""
        result = await session.execute(
            select(RelayAllowlistEntry).where(RelayAllowlistEntry.domain == domain)
        )
        entry = result.scalar_one_or_none()
        if entry is None:
            return False
        await session.delete(entry)
        await session.commit()
        self._allowed.discard(domain)
        logger.info("Removed relay allow domain %r", domain)
        return True

    async def list_allowed(self, session: AsyncSession) -> list[dict[str, Any]]:
        """Return all allowlist entries from DB."""
        result = await session.execute(
            select(RelayAllowlistEntry).order_by(RelayAllowlistEntry.id)
        )
        rows = result.scalars().all()
        return [
            {
                "id": row.id,
                "domain": row.domain,
                "reason": row.reason,
                "created_at": str(row.created_at),
            }
            for row in rows
        ]
