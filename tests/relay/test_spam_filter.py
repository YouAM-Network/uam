"""Unit tests for AllowBlockList (SPAM-01).

Tests cover:
- Exact and domain-wildcard pattern matching for blocked/allowed lists
- CRUD operations: add, remove, list
- Persistence via in-memory SQLModel/AsyncSession database
- Edge cases: invalid patterns, duplicate handling
"""

from __future__ import annotations

import pytest

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.asyncio import async_sessionmaker
from sqlmodel import SQLModel

from uam.relay.spam_filter import AllowBlockList, _classify_pattern


# ---------------------------------------------------------------------------
# Helper: create an in-memory DB with SQLModel tables
# ---------------------------------------------------------------------------


@pytest.fixture()
async def session():
    """Create an in-memory async engine with SQLModel tables and yield a session."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        yield sess
    await engine.dispose()


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
    async def test_is_blocked_exact_match(self, session):
        abl = AllowBlockList()
        await abl.add_blocked(session, "spammer::evil.com")
        assert abl.is_blocked("spammer::evil.com") is True
        assert abl.is_blocked("innocent::good.com") is False

    @pytest.mark.asyncio
    async def test_not_blocked_by_default(self, session):
        abl = AllowBlockList()
        assert abl.is_blocked("anyone::anywhere.com") is False


class TestBlockedDomain:
    """Tests for domain-wildcard blocking."""

    @pytest.mark.asyncio
    async def test_is_blocked_domain_wildcard(self, session):
        abl = AllowBlockList()
        await abl.add_blocked(session, "*::evil.com")
        assert abl.is_blocked("agent1::evil.com") is True
        assert abl.is_blocked("agent2::evil.com") is True
        assert abl.is_blocked("agent::good.com") is False

    @pytest.mark.asyncio
    async def test_domain_wildcard_does_not_block_exact_without_match(self, session):
        abl = AllowBlockList()
        await abl.add_blocked(session, "*::evil.com")
        # Address on a different domain is not blocked
        assert abl.is_blocked("evil::good.com") is False


class TestBlockedCRUD:
    """Tests for blocklist add/remove/list operations."""

    @pytest.mark.asyncio
    async def test_add_and_remove_blocked(self, session):
        abl = AllowBlockList()
        await abl.add_blocked(session, "bad::actor.net")
        assert abl.is_blocked("bad::actor.net") is True
        removed = await abl.remove_blocked(session, "bad::actor.net")
        assert removed is True
        assert abl.is_blocked("bad::actor.net") is False

    @pytest.mark.asyncio
    async def test_remove_nonexistent_returns_false(self, session):
        abl = AllowBlockList()
        removed = await abl.remove_blocked(session, "ghost::nowhere.com")
        assert removed is False

    @pytest.mark.asyncio
    async def test_list_blocked(self, session):
        abl = AllowBlockList()
        await abl.add_blocked(session, "a::one.com", reason="spam")
        await abl.add_blocked(session, "*::two.com", reason="phishing")
        entries = await abl.list_blocked(session)
        patterns = [e["pattern"] for e in entries]
        assert "a::one.com" in patterns
        assert "*::two.com" in patterns
        assert len(entries) == 2

    @pytest.mark.asyncio
    async def test_duplicate_pattern_handling(self, session):
        """Adding the same pattern twice does not error (INSERT OR IGNORE)."""
        abl = AllowBlockList()
        await abl.add_blocked(session, "dup::test.com")
        await abl.add_blocked(session, "dup::test.com")  # should not raise
        entries = await abl.list_blocked(session)
        assert len(entries) == 1

    @pytest.mark.asyncio
    async def test_invalid_pattern_rejected(self, session):
        abl = AllowBlockList()
        with pytest.raises(ValueError, match="must contain '::'"):
            await abl.add_blocked(session, "no-separator")


# ---------------------------------------------------------------------------
# Allowlist tests
# ---------------------------------------------------------------------------


class TestAllowedExact:
    """Tests for exact-address allowing."""

    @pytest.mark.asyncio
    async def test_is_allowed_exact_match(self, session):
        abl = AllowBlockList()
        await abl.add_allowed(session, "vip::trusted.org")
        assert abl.is_allowed("vip::trusted.org") is True
        assert abl.is_allowed("random::other.org") is False

    @pytest.mark.asyncio
    async def test_not_allowed_by_default(self, session):
        abl = AllowBlockList()
        assert abl.is_allowed("anyone::anywhere.com") is False


class TestAllowedDomain:
    """Tests for domain-wildcard allowing."""

    @pytest.mark.asyncio
    async def test_is_allowed_domain_wildcard(self, session):
        abl = AllowBlockList()
        await abl.add_allowed(session, "*::trusted.org")
        assert abl.is_allowed("agent1::trusted.org") is True
        assert abl.is_allowed("agent2::trusted.org") is True
        assert abl.is_allowed("agent::other.org") is False


class TestAllowedCRUD:
    """Tests for allowlist add/remove/list operations."""

    @pytest.mark.asyncio
    async def test_add_and_remove_allowed(self, session):
        abl = AllowBlockList()
        await abl.add_allowed(session, "friend::good.net")
        assert abl.is_allowed("friend::good.net") is True
        removed = await abl.remove_allowed(session, "friend::good.net")
        assert removed is True
        assert abl.is_allowed("friend::good.net") is False

    @pytest.mark.asyncio
    async def test_list_allowed(self, session):
        abl = AllowBlockList()
        await abl.add_allowed(session, "x::one.com")
        await abl.add_allowed(session, "*::two.com")
        entries = await abl.list_allowed(session)
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
    async def test_load_blocked_from_db(self, session):
        """Insert patterns via CRUD, load into fresh AllowBlockList."""
        abl1 = AllowBlockList()
        await abl1.add_blocked(session, "spam::evil.com")
        await abl1.add_blocked(session, "*::bad.org")

        abl2 = AllowBlockList()
        await abl2.load(session)
        assert abl2.is_blocked("spam::evil.com") is True
        assert abl2.is_blocked("anyone::bad.org") is True
        assert abl2.is_blocked("clean::good.com") is False

    @pytest.mark.asyncio
    async def test_load_allowed_from_db(self, session):
        """Insert patterns via CRUD, load into fresh AllowBlockList."""
        abl1 = AllowBlockList()
        await abl1.add_allowed(session, "vip::trusted.com")
        await abl1.add_allowed(session, "*::partner.net")

        abl2 = AllowBlockList()
        await abl2.load(session)
        assert abl2.is_allowed("vip::trusted.com") is True
        assert abl2.is_allowed("any::partner.net") is True
        assert abl2.is_allowed("random::other.com") is False

    @pytest.mark.asyncio
    async def test_load_clears_previous_state(self, session):
        """Calling load() replaces in-memory state, doesn't accumulate."""
        abl = AllowBlockList()
        await abl.add_blocked(session, "old::pattern.com")
        assert abl.is_blocked("old::pattern.com") is True

        # Remove from DB via CRUD, then reload
        await abl.remove_blocked(session, "old::pattern.com")
        await abl.load(session)
        assert abl.is_blocked("old::pattern.com") is False
