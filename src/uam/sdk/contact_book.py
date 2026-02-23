"""SQLite-backed local contact storage (HAND-03).

Stores known contacts with their public keys and trust state.
Provides a fast in-memory cache for is_known() and is_blocked() checks.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import aiosqlite

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS contacts (
    address      TEXT PRIMARY KEY,
    public_key   TEXT NOT NULL,
    display_name TEXT,
    trust_state  TEXT NOT NULL DEFAULT 'unknown',
    trust_source TEXT DEFAULT 'legacy-unknown',
    relay        TEXT,
    relays_json  TEXT,
    pinned_at    TEXT,
    first_seen   TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS pending_handshakes (
    address      TEXT PRIMARY KEY,
    contact_card TEXT NOT NULL,
    received_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS blocked_patterns (
    pattern     TEXT PRIMARY KEY,
    blocked_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class ContactBook:
    """SQLite-backed contact storage with in-memory address cache.

    Usage::

        book = ContactBook(data_dir)
        await book.open()
        book.is_known("alice::youam.network")  # synchronous, in-memory
        await book.add_contact("alice::youam.network", "base64-pubkey")
        await book.close()
    """

    def __init__(self, data_dir: Path) -> None:
        self._db_path = Path(data_dir) / "contacts" / "contacts.db"
        self._db: aiosqlite.Connection | None = None
        self._known_addresses: set[str] = set()
        self._blocked_exact: set[str] = set()
        self._blocked_domains: set[str] = set()

    async def open(self) -> None:
        """Open the database, create tables, run migrations, load caches."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        await self._db.executescript(_SCHEMA)
        await self._db.commit()

        # Run schema migrations
        await self._migrate()

        # Load all known addresses into memory for fast sync lookups
        async with self._db.execute("SELECT address FROM contacts") as cursor:
            rows = await cursor.fetchall()
            self._known_addresses = {row[0] for row in rows}

        # Load blocked patterns into memory
        self._blocked_exact.clear()
        self._blocked_domains.clear()
        async with self._db.execute(
            "SELECT pattern FROM blocked_patterns"
        ) as cursor:
            for row in await cursor.fetchall():
                self._cache_block_pattern(row[0])

    async def _migrate(self) -> None:
        """Run schema migrations using PRAGMA user_version."""
        async with self._db.execute("PRAGMA user_version") as cur:
            version = (await cur.fetchone())[0]

        if version < 1:
            logger.info("Migrating ContactBook schema to version 1")
            try:
                await self._db.execute(
                    "ALTER TABLE contacts ADD COLUMN trust_source TEXT DEFAULT 'legacy-unknown'"
                )
            except Exception:
                pass  # Column already exists (fresh DB has it in _SCHEMA)
            await self._db.execute(
                """
                CREATE TABLE IF NOT EXISTS blocked_patterns (
                    pattern     TEXT PRIMARY KEY,
                    blocked_at  TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )
            await self._db.execute("PRAGMA user_version = 1")
            await self._db.commit()

        if version < 2:
            logger.info("Migrating ContactBook schema to version 2 (CARD-04: relay columns)")
            try:
                await self._db.execute(
                    "ALTER TABLE contacts ADD COLUMN relay TEXT"
                )
            except Exception:
                pass  # Column already exists (fresh DB has it in _SCHEMA)
            try:
                await self._db.execute(
                    "ALTER TABLE contacts ADD COLUMN relays_json TEXT"
                )
            except Exception:
                pass  # Column already exists (fresh DB has it in _SCHEMA)
            await self._db.execute("PRAGMA user_version = 2")
            await self._db.commit()

        if version < 3:
            logger.info("Migrating ContactBook schema to version 3 (TOFU: pinned_at)")
            try:
                await self._db.execute(
                    "ALTER TABLE contacts ADD COLUMN pinned_at TEXT"
                )
            except Exception:
                pass  # Column already exists (fresh DB has it in _SCHEMA)
            await self._db.execute("PRAGMA user_version = 3")
            await self._db.commit()

    async def close(self) -> None:
        """Close the database connection."""
        if self._db is not None:
            await self._db.close()
            self._db = None

    def is_known(self, address: str) -> bool:
        """Check if an address is in the contact book (in-memory, no I/O)."""
        return address in self._known_addresses

    async def get_public_key(self, address: str) -> str | None:
        """Look up the public key for a known contact."""
        if self._db is None:
            return None
        async with self._db.execute(
            "SELECT public_key FROM contacts WHERE address = ?", (address,)
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None

    async def get_relay_urls(self, address: str) -> list[str] | None:
        """Return the relay URLs for a known contact (CARD-04).

        If the contact has a ``relays`` array, returns that list.
        If only a primary ``relay`` is stored, returns ``[relay]``.
        Returns ``None`` if the contact is unknown or has no relay data.
        """
        if self._db is None:
            return None
        async with self._db.execute(
            "SELECT relay, relays_json FROM contacts WHERE address = ?", (address,)
        ) as cursor:
            row = await cursor.fetchone()
            if row is None:
                return None
            relay, relays_json = row
            if relays_json is not None:
                return json.loads(relays_json)
            if relay is not None:
                return [relay]
            return None

    async def add_contact(
        self,
        address: str,
        public_key: str,
        display_name: str | None = None,
        trust_state: str = "trusted",
        trust_source: str | None = None,
        relay: str | None = None,
        relays: list[str] | None = None,
    ) -> None:
        """Add or update a contact (upsert).

        Args:
            trust_source: How this contact was established (e.g.,
                ``"auto-accepted"``, ``"explicit-approval"``).  If ``None``,
                existing trust_source is preserved on update.
            relay: The contact's primary relay URL (CARD-04).
            relays: List of alternative relay URLs for failover (CARD-04).
        """
        if self._db is None:
            raise RuntimeError("ContactBook not open. Call open() first.")
        relays_json = json.dumps(relays) if relays is not None else None
        await self._db.execute(
            """
            INSERT INTO contacts (address, public_key, display_name, trust_state, trust_source, relay, relays_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(address) DO UPDATE SET
                public_key = excluded.public_key,
                display_name = excluded.display_name,
                trust_state = excluded.trust_state,
                trust_source = COALESCE(excluded.trust_source, contacts.trust_source),
                relay = COALESCE(excluded.relay, contacts.relay),
                relays_json = COALESCE(excluded.relays_json, contacts.relays_json),
                last_seen = datetime('now')
            """,
            (address, public_key, display_name, trust_state, trust_source, relay, relays_json),
        )
        await self._db.commit()
        self._known_addresses.add(address)

    async def list_contacts(self) -> list[dict]:
        """Return all contacts with address, display_name, trust_state, first_seen, last_seen."""
        if self._db is None:
            return []
        async with self._db.execute(
            "SELECT address, display_name, trust_state, first_seen, last_seen "
            "FROM contacts ORDER BY last_seen DESC"
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                {
                    "address": r[0],
                    "display_name": r[1],
                    "trust_state": r[2],
                    "first_seen": r[3],
                    "last_seen": r[4],
                }
                for r in rows
            ]

    async def add_pending(self, address: str, contact_card_json: str) -> None:
        """Store a pending handshake request."""
        if self._db is None:
            raise RuntimeError("ContactBook not open. Call open() first.")
        await self._db.execute(
            """
            INSERT OR REPLACE INTO pending_handshakes (address, contact_card)
            VALUES (?, ?)
            """,
            (address, contact_card_json),
        )
        await self._db.commit()

    async def get_pending(self) -> list[dict]:
        """Retrieve all pending handshake requests."""
        if self._db is None:
            return []
        async with self._db.execute(
            "SELECT address, contact_card, received_at FROM pending_handshakes"
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                {"address": row[0], "contact_card": row[1], "received_at": row[2]}
                for row in rows
            ]

    async def remove_pending(self, address: str) -> None:
        """Remove a pending handshake request."""
        if self._db is None:
            return
        await self._db.execute(
            "DELETE FROM pending_handshakes WHERE address = ?", (address,)
        )
        await self._db.commit()

    async def get_expired_pending(self, days: int = 7) -> list[dict]:
        """Return pending handshakes older than *days* days."""
        if self._db is None:
            return []
        async with self._db.execute(
            """
            SELECT address, contact_card, received_at FROM pending_handshakes
            WHERE datetime(received_at, '+' || ? || ' days') < datetime('now')
            """,
            (str(days),),
        ) as cursor:
            rows = await cursor.fetchall()
            return [
                {"address": r[0], "contact_card": r[1], "received_at": r[2]}
                for r in rows
            ]

    async def get_trust_state(self, address: str) -> str | None:
        """Return the trust_state for *address*, or ``None`` if unknown."""
        if self._db is None:
            return None
        async with self._db.execute(
            "SELECT trust_state FROM contacts WHERE address = ?", (address,)
        ) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None

    async def set_pinned_at(self, address: str) -> None:
        """Set the pinned_at timestamp for a contact."""
        if self._db is None:
            raise RuntimeError("ContactBook not open.")
        await self._db.execute(
            "UPDATE contacts SET pinned_at = datetime('now') WHERE address = ?",
            (address,),
        )
        await self._db.commit()

    async def remove_contact(self, address: str) -> bool:
        """Remove a contact by address. Returns True if a contact was deleted."""
        if self._db is None:
            raise RuntimeError("ContactBook not open.")
        cursor = await self._db.execute(
            "DELETE FROM contacts WHERE address = ?", (address,)
        )
        await self._db.commit()
        self._known_addresses.discard(address)
        return cursor.rowcount > 0

    async def is_trusted_or_verified(self, address: str) -> bool:
        """Return True if *address* has trust_state 'trusted', 'verified', or 'pinned'.

        Convenience helper for inbound message filtering (CARD-05, TOFU-02).
        """
        state = await self.get_trust_state(address)
        return state in ("trusted", "verified", "pinned")

    # -- Blocking (HAND-04) --------------------------------------------------

    def _cache_block_pattern(self, pattern: str) -> None:
        """Add *pattern* to the appropriate in-memory cache set."""
        if pattern.startswith("*::"):
            self._blocked_domains.add(pattern[3:])  # strip '*::'
        else:
            self._blocked_exact.add(pattern)

    def _uncache_block_pattern(self, pattern: str) -> None:
        """Remove *pattern* from the in-memory cache."""
        if pattern.startswith("*::"):
            self._blocked_domains.discard(pattern[3:])
        else:
            self._blocked_exact.discard(pattern)

    def is_blocked(self, address: str) -> bool:
        """Check if *address* matches any blocked pattern (O(1) set lookup)."""
        if address in self._blocked_exact:
            return True
        # Extract domain from 'name::domain' format
        if "::" in address:
            domain = address.split("::")[1]
            return domain in self._blocked_domains
        return False

    async def add_block(self, pattern: str) -> None:
        """Block an address or domain pattern (e.g., ``*::evil.com``)."""
        if self._db is None:
            raise RuntimeError("ContactBook not open. Call open() first.")
        await self._db.execute(
            "INSERT OR IGNORE INTO blocked_patterns (pattern) VALUES (?)",
            (pattern,),
        )
        await self._db.commit()
        self._cache_block_pattern(pattern)

    async def remove_block(self, pattern: str) -> None:
        """Remove a block pattern."""
        if self._db is None:
            raise RuntimeError("ContactBook not open. Call open() first.")
        await self._db.execute(
            "DELETE FROM blocked_patterns WHERE pattern = ?", (pattern,)
        )
        await self._db.commit()
        self._uncache_block_pattern(pattern)

    async def list_blocked(self) -> list[dict]:
        """Return all blocked patterns with their timestamps."""
        if self._db is None:
            return []
        async with self._db.execute(
            "SELECT pattern, blocked_at FROM blocked_patterns ORDER BY blocked_at DESC"
        ) as cursor:
            rows = await cursor.fetchall()
            return [{"pattern": r[0], "blocked_at": r[1]} for r in rows]
