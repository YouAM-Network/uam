"""Unit tests for AllowBlockList (SPAM-01).

Tests cover:
- Exact and domain-wildcard pattern matching for blocked/allowed lists
- CRUD operations: add, remove, list
- Persistence via in-memory aiosqlite database
- Edge cases: invalid patterns, duplicate handling
"""

from __future__ import annotations

import pytest
import aiosqlite

from uam.relay.spam_filter import AllowBlockList, _classify_pattern


# ---------------------------------------------------------------------------
# Helper: create an in-memory DB with the blocklist/allowlist schema
# ---------------------------------------------------------------------------


@pytest.fixture()
async def db():
    """Create an in-memory aiosqlite database with blocklist/allowlist tables."""
    conn = await aiosqlite.connect(":memory:")
    conn.row_factory = aiosqlite.Row
    await conn.executescript("""
        CREATE TABLE blocklist (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern     TEXT NOT NULL UNIQUE,
            reason      TEXT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE allowlist (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern     TEXT NOT NULL UNIQUE,
            reason      TEXT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );
    """)
    await conn.commit()
    yield conn
    await conn.close()


# ---------------------------------------------------------------------------
# _classify_pattern tests
# ---------------------------------------------------------------------------


class TestClassifyPattern:
    """Tests for the module-level _classify_pattern helper."""

    def test_exact_pattern(self):
        kind, value = _classify_pattern("spammer::evil.com")
        assert kind == "exact"
        assert value == "spammer::evil.com"

    def test_domain_wildcard(self):
        kind, value = _classify_pattern("*::evil.com")
        assert kind == "domain"
        assert value == "evil.com"

    def test_invalid_pattern_no_separator(self):
        with pytest.raises(ValueError, match="must contain '::'"):
            _classify_pattern("nocolon")

    def test_invalid_pattern_empty_string(self):
        with pytest.raises(ValueError, match="must contain '::'"):
            _classify_pattern("")


# ---------------------------------------------------------------------------
# Blocklist tests
# ---------------------------------------------------------------------------


class TestBlockedExact:
    """Tests for exact-address blocking."""

    @pytest.mark.asyncio
    async def test_is_blocked_exact_match(self, db):
        abl = AllowBlockList()
        await abl.add_blocked(db, "spammer::evil.com")
        assert abl.is_blocked("spammer::evil.com") is True
        assert abl.is_blocked("innocent::good.com") is False

    @pytest.mark.asyncio
    async def test_not_blocked_by_default(self, db):
        abl = AllowBlockList()
        assert abl.is_blocked("anyone::anywhere.com") is False


class TestBlockedDomain:
    """Tests for domain-wildcard blocking."""

    @pytest.mark.asyncio
    async def test_is_blocked_domain_wildcard(self, db):
        abl = AllowBlockList()
        await abl.add_blocked(db, "*::evil.com")
        assert abl.is_blocked("agent1::evil.com") is True
        assert abl.is_blocked("agent2::evil.com") is True
        assert abl.is_blocked("agent::good.com") is False

    @pytest.mark.asyncio
    async def test_domain_wildcard_does_not_block_exact_without_match(self, db):
        abl = AllowBlockList()
        await abl.add_blocked(db, "*::evil.com")
        # Address on a different domain is not blocked
        assert abl.is_blocked("evil::good.com") is False


class TestBlockedCRUD:
    """Tests for blocklist add/remove/list operations."""

    @pytest.mark.asyncio
    async def test_add_and_remove_blocked(self, db):
        abl = AllowBlockList()
        await abl.add_blocked(db, "bad::actor.net")
        assert abl.is_blocked("bad::actor.net") is True
        removed = await abl.remove_blocked(db, "bad::actor.net")
        assert removed is True
        assert abl.is_blocked("bad::actor.net") is False

    @pytest.mark.asyncio
    async def test_remove_nonexistent_returns_false(self, db):
        abl = AllowBlockList()
        removed = await abl.remove_blocked(db, "ghost::nowhere.com")
        assert removed is False

    @pytest.mark.asyncio
    async def test_list_blocked(self, db):
        abl = AllowBlockList()
        await abl.add_blocked(db, "a::one.com", reason="spam")
        await abl.add_blocked(db, "*::two.com", reason="phishing")
        entries = await abl.list_blocked(db)
        patterns = [e["pattern"] for e in entries]
        assert "a::one.com" in patterns
        assert "*::two.com" in patterns
        assert len(entries) == 2

    @pytest.mark.asyncio
    async def test_duplicate_pattern_handling(self, db):
        """Adding the same pattern twice does not error (INSERT OR IGNORE)."""
        abl = AllowBlockList()
        await abl.add_blocked(db, "dup::test.com")
        await abl.add_blocked(db, "dup::test.com")  # should not raise
        entries = await abl.list_blocked(db)
        assert len(entries) == 1

    @pytest.mark.asyncio
    async def test_invalid_pattern_rejected(self, db):
        abl = AllowBlockList()
        with pytest.raises(ValueError, match="must contain '::'"):
            await abl.add_blocked(db, "no-separator")


# ---------------------------------------------------------------------------
# Allowlist tests
# ---------------------------------------------------------------------------


class TestAllowedExact:
    """Tests for exact-address allowing."""

    @pytest.mark.asyncio
    async def test_is_allowed_exact_match(self, db):
        abl = AllowBlockList()
        await abl.add_allowed(db, "vip::trusted.org")
        assert abl.is_allowed("vip::trusted.org") is True
        assert abl.is_allowed("random::other.org") is False

    @pytest.mark.asyncio
    async def test_not_allowed_by_default(self, db):
        abl = AllowBlockList()
        assert abl.is_allowed("anyone::anywhere.com") is False


class TestAllowedDomain:
    """Tests for domain-wildcard allowing."""

    @pytest.mark.asyncio
    async def test_is_allowed_domain_wildcard(self, db):
        abl = AllowBlockList()
        await abl.add_allowed(db, "*::trusted.org")
        assert abl.is_allowed("agent1::trusted.org") is True
        assert abl.is_allowed("agent2::trusted.org") is True
        assert abl.is_allowed("agent::other.org") is False


class TestAllowedCRUD:
    """Tests for allowlist add/remove/list operations."""

    @pytest.mark.asyncio
    async def test_add_and_remove_allowed(self, db):
        abl = AllowBlockList()
        await abl.add_allowed(db, "friend::good.net")
        assert abl.is_allowed("friend::good.net") is True
        removed = await abl.remove_allowed(db, "friend::good.net")
        assert removed is True
        assert abl.is_allowed("friend::good.net") is False

    @pytest.mark.asyncio
    async def test_list_allowed(self, db):
        abl = AllowBlockList()
        await abl.add_allowed(db, "x::one.com")
        await abl.add_allowed(db, "*::two.com")
        entries = await abl.list_allowed(db)
        patterns = [e["pattern"] for e in entries]
        assert "x::one.com" in patterns
        assert "*::two.com" in patterns
        assert len(entries) == 2


# ---------------------------------------------------------------------------
# Load from DB (persistence round-trip)
# ---------------------------------------------------------------------------


class TestLoadFromDB:
    """Tests for loading patterns from the database into a fresh instance."""

    @pytest.mark.asyncio
    async def test_load_blocked_from_db(self, db):
        """Insert patterns directly into DB, load into fresh AllowBlockList."""
        await db.execute("INSERT INTO blocklist (pattern) VALUES (?)", ("spam::evil.com",))
        await db.execute("INSERT INTO blocklist (pattern) VALUES (?)", ("*::bad.org",))
        await db.commit()

        abl = AllowBlockList()
        await abl.load(db)
        assert abl.is_blocked("spam::evil.com") is True
        assert abl.is_blocked("anyone::bad.org") is True
        assert abl.is_blocked("clean::good.com") is False

    @pytest.mark.asyncio
    async def test_load_allowed_from_db(self, db):
        """Insert patterns directly into DB, load into fresh AllowBlockList."""
        await db.execute("INSERT INTO allowlist (pattern) VALUES (?)", ("vip::trusted.com",))
        await db.execute("INSERT INTO allowlist (pattern) VALUES (?)", ("*::partner.net",))
        await db.commit()

        abl = AllowBlockList()
        await abl.load(db)
        assert abl.is_allowed("vip::trusted.com") is True
        assert abl.is_allowed("any::partner.net") is True
        assert abl.is_allowed("random::other.com") is False

    @pytest.mark.asyncio
    async def test_load_clears_previous_state(self, db):
        """Calling load() replaces in-memory state, doesn't accumulate."""
        abl = AllowBlockList()
        await abl.add_blocked(db, "old::pattern.com")
        assert abl.is_blocked("old::pattern.com") is True

        # Remove from DB directly, then reload
        await db.execute("DELETE FROM blocklist WHERE pattern = ?", ("old::pattern.com",))
        await db.commit()
        await abl.load(db)
        assert abl.is_blocked("old::pattern.com") is False
