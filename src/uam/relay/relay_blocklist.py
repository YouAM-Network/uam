"""Allow/block list for relay-level federation filtering (FED-07).

Domain-only filtering for peer relay domains.  Unlike the agent-level
:class:`AllowBlockList` (which uses ``name::domain`` patterns), relay
filtering operates on plain domain strings (e.g. ``"evil-relay.com"``).

All lookups are O(1) via in-memory set membership.  Persistence is
handled through aiosqlite queries against the ``relay_blocklist`` and
``relay_allowlist`` tables.
"""

from __future__ import annotations

import logging
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)


class RelayAllowBlockList:
    """In-memory allow/block list for peer relay domains, backed by SQLite.

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

    async def load(self, db: aiosqlite.Connection) -> None:
        """Load all domains from relay_blocklist/relay_allowlist tables."""
        self._blocked.clear()
        self._allowed.clear()

        cursor = await db.execute("SELECT domain FROM relay_blocklist")
        rows = await cursor.fetchall()
        for row in rows:
            domain = row[0] if isinstance(row, tuple) else row["domain"]
            self._blocked.add(domain)

        cursor = await db.execute("SELECT domain FROM relay_allowlist")
        rows = await cursor.fetchall()
        for row in rows:
            domain = row[0] if isinstance(row, tuple) else row["domain"]
            self._allowed.add(domain)

        logger.info(
            "Loaded %d blocked and %d allowed relay domains",
            len(self._blocked),
            len(self._allowed),
        )

    # ------------------------------------------------------------------
    # Blocklist CRUD
    # ------------------------------------------------------------------

    async def add_blocked(
        self, db: aiosqlite.Connection, domain: str, reason: str | None = None
    ) -> None:
        """Block a relay domain (DB + in-memory)."""
        await db.execute(
            "INSERT OR IGNORE INTO relay_blocklist (domain, reason) VALUES (?, ?)",
            (domain, reason),
        )
        await db.commit()
        self._blocked.add(domain)
        logger.info("Blocked relay domain %r (reason: %s)", domain, reason)

    async def remove_blocked(self, db: aiosqlite.Connection, domain: str) -> bool:
        """Unblock a relay domain.  Returns True if it existed."""
        cursor = await db.execute(
            "DELETE FROM relay_blocklist WHERE domain = ?", (domain,)
        )
        await db.commit()
        removed = cursor.rowcount > 0  # type: ignore[operator]
        self._blocked.discard(domain)
        if removed:
            logger.info("Unblocked relay domain %r", domain)
        return removed

    async def list_blocked(self, db: aiosqlite.Connection) -> list[dict[str, Any]]:
        """Return all blocklist entries from DB."""
        cursor = await db.execute(
            "SELECT id, domain, reason, created_at FROM relay_blocklist ORDER BY id"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Allowlist CRUD
    # ------------------------------------------------------------------

    async def add_allowed(
        self, db: aiosqlite.Connection, domain: str, reason: str | None = None
    ) -> None:
        """Allowlist a relay domain (DB + in-memory)."""
        await db.execute(
            "INSERT OR IGNORE INTO relay_allowlist (domain, reason) VALUES (?, ?)",
            (domain, reason),
        )
        await db.commit()
        self._allowed.add(domain)
        logger.info("Allowed relay domain %r (reason: %s)", domain, reason)

    async def remove_allowed(self, db: aiosqlite.Connection, domain: str) -> bool:
        """Remove relay from allowlist.  Returns True if it existed."""
        cursor = await db.execute(
            "DELETE FROM relay_allowlist WHERE domain = ?", (domain,)
        )
        await db.commit()
        removed = cursor.rowcount > 0  # type: ignore[operator]
        self._allowed.discard(domain)
        if removed:
            logger.info("Removed relay allow domain %r", domain)
        return removed

    async def list_allowed(self, db: aiosqlite.Connection) -> list[dict[str, Any]]:
        """Return all allowlist entries from DB."""
        cursor = await db.execute(
            "SELECT id, domain, reason, created_at FROM relay_allowlist ORDER BY id"
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]
