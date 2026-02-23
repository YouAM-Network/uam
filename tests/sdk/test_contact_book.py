"""Tests for ContactBook SQLite-backed contact storage (HAND-03)."""

from __future__ import annotations

import aiosqlite
import pytest

from uam.sdk.contact_book import ContactBook


@pytest.fixture()
def data_dir(tmp_path):
    """Temporary data directory for contact book tests."""
    d = tmp_path / ".uam"
    d.mkdir(parents=True, exist_ok=True)
    return d


class TestContactBook:
    """ContactBook stores contacts in SQLite with in-memory address cache."""

    async def test_open_creates_database(self, data_dir):
        """Opening the contact book creates the database file."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            assert (data_dir / "contacts" / "contacts.db").exists()
        finally:
            await book.close()

    async def test_add_and_lookup_contact(self, data_dir):
        """Adding a contact allows public key lookup."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact("alice::test.local", "base64-pubkey-alice")
            pk = await book.get_public_key("alice::test.local")
            assert pk == "base64-pubkey-alice"
        finally:
            await book.close()

    async def test_is_known_after_add(self, data_dir):
        """is_known returns True after adding, False for unknown."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            assert book.is_known("alice::test.local") is False
            await book.add_contact("alice::test.local", "key123")
            assert book.is_known("alice::test.local") is True
            assert book.is_known("unknown::test.local") is False
        finally:
            await book.close()

    async def test_is_known_loaded_from_disk(self, data_dir):
        """Contacts persist to disk and load into memory on open."""
        book1 = ContactBook(data_dir)
        await book1.open()
        await book1.add_contact("alice::test.local", "key-alice")
        await book1.close()

        # Open a fresh ContactBook -- should load from disk
        book2 = ContactBook(data_dir)
        await book2.open()
        try:
            assert book2.is_known("alice::test.local") is True
            pk = await book2.get_public_key("alice::test.local")
            assert pk == "key-alice"
        finally:
            await book2.close()

    async def test_add_pending_and_get(self, data_dir):
        """Pending handshakes can be stored and retrieved."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_pending("alice::test.local", '{"card": "data"}')
            pending = await book.get_pending()
            assert len(pending) == 1
            assert pending[0]["address"] == "alice::test.local"
            assert pending[0]["contact_card"] == '{"card": "data"}'
        finally:
            await book.close()

    async def test_remove_pending(self, data_dir):
        """Pending handshakes can be removed."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_pending("alice::test.local", '{"card": "data"}')
            await book.remove_pending("alice::test.local")
            pending = await book.get_pending()
            assert len(pending) == 0
        finally:
            await book.close()

    async def test_update_existing_contact(self, data_dir):
        """Adding an existing contact with new data updates (upsert)."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact(
                "alice::test.local", "key1", display_name="Alice v1"
            )
            await book.add_contact(
                "alice::test.local", "key2", display_name="Alice v2"
            )
            pk = await book.get_public_key("alice::test.local")
            assert pk == "key2"
        finally:
            await book.close()

    async def test_get_public_key_unknown(self, data_dir):
        """get_public_key returns None for unknown addresses."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            pk = await book.get_public_key("unknown::test.local")
            assert pk is None
        finally:
            await book.close()


class TestSchemaMigration:
    """PRAGMA user_version-based schema migration (HAND-05)."""

    async def test_fresh_database_has_trust_source_column(self, data_dir):
        """A fresh database includes the trust_source column after migration."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact(
                "alice::test.local", "key-a",
                trust_source="auto-accepted",
            )
            # Verify via raw SQL
            async with book._db.execute(
                "SELECT trust_source FROM contacts WHERE address = ?",
                ("alice::test.local",),
            ) as cur:
                row = await cur.fetchone()
                assert row[0] == "auto-accepted"
        finally:
            await book.close()

    async def test_migration_adds_trust_source_to_existing(self, data_dir):
        """Existing contacts get trust_source='legacy-unknown' after migration."""
        db_path = data_dir / "contacts" / "contacts.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)

        # Create a database with the old schema (no trust_source, user_version=0)
        db = await aiosqlite.connect(str(db_path))
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS contacts (
                address      TEXT PRIMARY KEY,
                public_key   TEXT NOT NULL,
                display_name TEXT,
                trust_state  TEXT NOT NULL DEFAULT 'unknown',
                first_seen   TEXT NOT NULL DEFAULT (datetime('now')),
                last_seen    TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS pending_handshakes (
                address      TEXT PRIMARY KEY,
                contact_card TEXT NOT NULL,
                received_at  TEXT NOT NULL DEFAULT (datetime('now'))
            );
        """)
        await db.execute(
            "INSERT INTO contacts (address, public_key) VALUES (?, ?)",
            ("old::test.local", "old-key"),
        )
        await db.commit()
        await db.close()

        # Open with ContactBook -- migration should run
        book = ContactBook(data_dir)
        await book.open()
        try:
            async with book._db.execute(
                "SELECT trust_source FROM contacts WHERE address = ?",
                ("old::test.local",),
            ) as cur:
                row = await cur.fetchone()
                assert row[0] == "legacy-unknown"
        finally:
            await book.close()

    async def test_migration_creates_blocked_patterns_table(self, data_dir):
        """Migration creates the blocked_patterns table."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            async with book._db.execute(
                "PRAGMA table_info(blocked_patterns)"
            ) as cur:
                columns = [row[1] for row in await cur.fetchall()]
                assert "pattern" in columns
                assert "blocked_at" in columns
        finally:
            await book.close()

    async def test_migration_is_idempotent(self, data_dir):
        """Opening the database twice does not cause errors."""
        book = ContactBook(data_dir)
        await book.open()
        await book.close()

        # Second open should not fail
        book2 = ContactBook(data_dir)
        await book2.open()
        try:
            async with book2._db.execute("PRAGMA user_version") as cur:
                version = (await cur.fetchone())[0]
                assert version == 3
        finally:
            await book2.close()

    async def test_trust_source_preserved_on_update_without_explicit(self, data_dir):
        """Updating a contact without trust_source preserves the existing value."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact(
                "alice::test.local", "key-a",
                trust_source="auto-accepted",
            )
            # Update without specifying trust_source
            await book.add_contact(
                "alice::test.local", "key-a2",
                trust_state="trusted",
            )
            async with book._db.execute(
                "SELECT trust_source FROM contacts WHERE address = ?",
                ("alice::test.local",),
            ) as cur:
                row = await cur.fetchone()
                assert row[0] == "auto-accepted"
        finally:
            await book.close()

    async def test_trust_source_updated_when_explicit(self, data_dir):
        """Updating a contact with an explicit trust_source overwrites."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact(
                "alice::test.local", "key-a",
                trust_source="auto-accepted",
            )
            await book.add_contact(
                "alice::test.local", "key-a",
                trust_source="explicit-approval",
            )
            async with book._db.execute(
                "SELECT trust_source FROM contacts WHERE address = ?",
                ("alice::test.local",),
            ) as cur:
                row = await cur.fetchone()
                assert row[0] == "explicit-approval"
        finally:
            await book.close()


class TestBlocking:
    """Blocking addresses and domain patterns (HAND-04)."""

    async def test_block_exact_address(self, data_dir):
        """Blocking an exact address makes is_blocked return True for it only."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_block("spammer::evil.com")
            assert book.is_blocked("spammer::evil.com") is True
            assert book.is_blocked("other::evil.com") is False
        finally:
            await book.close()

    async def test_block_domain_pattern(self, data_dir):
        """Blocking *::domain blocks all addresses on that domain."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_block("*::evil.com")
            assert book.is_blocked("any::evil.com") is True
            assert book.is_blocked("spammer::evil.com") is True
            assert book.is_blocked("any::good.com") is False
        finally:
            await book.close()

    async def test_unblock_removes_pattern(self, data_dir):
        """Unblocking removes the pattern so is_blocked returns False."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_block("spammer::evil.com")
            assert book.is_blocked("spammer::evil.com") is True
            await book.remove_block("spammer::evil.com")
            assert book.is_blocked("spammer::evil.com") is False
        finally:
            await book.close()

    async def test_unblock_domain_pattern(self, data_dir):
        """Unblocking a domain pattern restores access."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_block("*::evil.com")
            assert book.is_blocked("any::evil.com") is True
            await book.remove_block("*::evil.com")
            assert book.is_blocked("any::evil.com") is False
        finally:
            await book.close()

    async def test_blocked_persists_across_open(self, data_dir):
        """Blocked patterns persist to disk and reload on open."""
        book1 = ContactBook(data_dir)
        await book1.open()
        await book1.add_block("spammer::evil.com")
        await book1.add_block("*::spam.org")
        await book1.close()

        book2 = ContactBook(data_dir)
        await book2.open()
        try:
            assert book2.is_blocked("spammer::evil.com") is True
            assert book2.is_blocked("anyone::spam.org") is True
            assert book2.is_blocked("good::safe.net") is False
        finally:
            await book2.close()

    async def test_list_blocked(self, data_dir):
        """list_blocked returns all blocked patterns with timestamps."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_block("spammer::evil.com")
            await book.add_block("*::spam.org")
            blocked = await book.list_blocked()
            patterns = {b["pattern"] for b in blocked}
            assert patterns == {"spammer::evil.com", "*::spam.org"}
            for b in blocked:
                assert "blocked_at" in b
                assert b["blocked_at"] is not None
        finally:
            await book.close()

    async def test_is_blocked_address_without_domain(self, data_dir):
        """is_blocked returns False for addresses without :: separator."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_block("*::evil.com")
            assert book.is_blocked("plain-address") is False
        finally:
            await book.close()


class TestExpiredPending:
    """Expired pending handshake queries (HAND-03)."""

    async def test_get_expired_pending_none(self, data_dir):
        """Freshly added pending entry is NOT expired."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_pending("alice::test.local", '{"card": "data"}')
            expired = await book.get_expired_pending(7)
            assert len(expired) == 0
        finally:
            await book.close()

    async def test_get_expired_pending_finds_old(self, data_dir):
        """Pending entries older than 7 days are returned as expired."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            # Insert with explicit past timestamp (8 days ago)
            await book._db.execute(
                "INSERT INTO pending_handshakes (address, contact_card, received_at) "
                "VALUES (?, ?, datetime('now', '-8 days'))",
                ("old::test.local", '{"card": "old"}'),
            )
            await book._db.commit()

            expired = await book.get_expired_pending(7)
            assert len(expired) == 1
            assert expired[0]["address"] == "old::test.local"
        finally:
            await book.close()

    async def test_get_expired_pending_ignores_recent(self, data_dir):
        """Only entries older than the threshold are returned."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            # 8-day-old entry (expired)
            await book._db.execute(
                "INSERT INTO pending_handshakes (address, contact_card, received_at) "
                "VALUES (?, ?, datetime('now', '-8 days'))",
                ("old::test.local", '{"card": "old"}'),
            )
            # 1-day-old entry (recent, not expired)
            await book._db.execute(
                "INSERT INTO pending_handshakes (address, contact_card, received_at) "
                "VALUES (?, ?, datetime('now', '-1 days'))",
                ("recent::test.local", '{"card": "recent"}'),
            )
            await book._db.commit()

            expired = await book.get_expired_pending(7)
            assert len(expired) == 1
            assert expired[0]["address"] == "old::test.local"
        finally:
            await book.close()

    async def test_get_expired_pending_custom_days(self, data_dir):
        """get_expired_pending respects the days parameter."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book._db.execute(
                "INSERT INTO pending_handshakes (address, contact_card, received_at) "
                "VALUES (?, ?, datetime('now', '-3 days'))",
                ("mid::test.local", '{"card": "mid"}'),
            )
            await book._db.commit()

            # Not expired at 7-day threshold
            assert len(await book.get_expired_pending(7)) == 0
            # Expired at 2-day threshold
            assert len(await book.get_expired_pending(2)) == 1
        finally:
            await book.close()


class TestGetTrustState:
    """get_trust_state returns the trust state for a contact."""

    async def test_returns_trust_state(self, data_dir):
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact("alice::test.local", "key-a", trust_state="trusted")
            assert await book.get_trust_state("alice::test.local") == "trusted"
        finally:
            await book.close()

    async def test_returns_none_for_unknown(self, data_dir):
        book = ContactBook(data_dir)
        await book.open()
        try:
            assert await book.get_trust_state("unknown::test.local") is None
        finally:
            await book.close()


class TestVerifiedTrustState:
    """Verified trust state support (CARD-05)."""

    async def test_store_verified_trust_state(self, data_dir):
        """Contact book can store 'verified' as a trust_state."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact("alice::example.com", "key-a", trust_state="verified")
            assert await book.get_trust_state("alice::example.com") == "verified"
        finally:
            await book.close()

    async def test_is_trusted_or_verified_trusted(self, data_dir):
        """is_trusted_or_verified returns True for 'trusted'."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact("alice::test.local", "key-a", trust_state="trusted")
            assert await book.is_trusted_or_verified("alice::test.local") is True
        finally:
            await book.close()

    async def test_is_trusted_or_verified_verified(self, data_dir):
        """is_trusted_or_verified returns True for 'verified'."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact("alice::example.com", "key-a", trust_state="verified")
            assert await book.is_trusted_or_verified("alice::example.com") is True
        finally:
            await book.close()

    async def test_is_trusted_or_verified_unverified(self, data_dir):
        """is_trusted_or_verified returns False for 'unverified'."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact("alice::test.local", "key-a", trust_state="unverified")
            assert await book.is_trusted_or_verified("alice::test.local") is False
        finally:
            await book.close()

    async def test_is_trusted_or_verified_unknown_address(self, data_dir):
        """is_trusted_or_verified returns False for unknown address."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            assert await book.is_trusted_or_verified("unknown::test.local") is False
        finally:
            await book.close()

    async def test_is_trusted_or_verified_handshake_sent(self, data_dir):
        """is_trusted_or_verified returns False for 'handshake-sent'."""
        book = ContactBook(data_dir)
        await book.open()
        try:
            await book.add_contact("alice::test.local", "key-a", trust_state="handshake-sent")
            assert await book.is_trusted_or_verified("alice::test.local") is False
        finally:
            await book.close()

    async def test_verified_persists_across_open(self, data_dir):
        """Verified trust state persists to disk and reloads correctly."""
        book1 = ContactBook(data_dir)
        await book1.open()
        await book1.add_contact("alice::example.com", "key-a", trust_state="verified")
        await book1.close()

        book2 = ContactBook(data_dir)
        await book2.open()
        try:
            assert await book2.get_trust_state("alice::example.com") == "verified"
            assert await book2.is_trusted_or_verified("alice::example.com") is True
        finally:
            await book2.close()
