"""Unit tests for ReputationManager (SPAM-02, SPAM-04).

Tests cover:
- Default score for unknown agents
- Score initialization (with/without DNS verification)
- Tier classification and send limits
- Score mutations: update (delta), set (admin override)
- Score clamping at 0 and 100
- Cache loading from DB
- Reputation info retrieval
- Message counters
- INSERT OR IGNORE behavior for init_score
"""

from __future__ import annotations

import pytest
import aiosqlite

from uam.relay.reputation import ReputationManager


# ---------------------------------------------------------------------------
# Helper: create an in-memory DB with reputation + agents tables
# ---------------------------------------------------------------------------


@pytest.fixture()
async def db():
    """Create an in-memory aiosqlite database with reputation and agents tables."""
    conn = await aiosqlite.connect(":memory:")
    conn.row_factory = aiosqlite.Row
    await conn.executescript("""
        CREATE TABLE agents (
            address     TEXT PRIMARY KEY,
            public_key  TEXT NOT NULL,
            token       TEXT NOT NULL UNIQUE,
            webhook_url TEXT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE TABLE reputation (
            address          TEXT PRIMARY KEY,
            score            INTEGER NOT NULL DEFAULT 30,
            messages_sent    INTEGER NOT NULL DEFAULT 0,
            messages_rejected INTEGER NOT NULL DEFAULT 0,
            created_at       TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (address) REFERENCES agents(address)
        );
    """)
    await conn.commit()
    yield conn
    await conn.close()


@pytest.fixture()
async def mgr(db):
    """Create a ReputationManager backed by the in-memory DB."""
    return ReputationManager(db)


# We need a registered agent for foreign key constraint satisfaction
async def _register_agent(db, address: str = "bot::test.local") -> str:
    """Insert a dummy agent row and return the address."""
    await db.execute(
        "INSERT OR IGNORE INTO agents (address, public_key, token) VALUES (?, ?, ?)",
        (address, "pk_placeholder", f"key_{address}"),
    )
    await db.commit()
    return address


# ---------------------------------------------------------------------------
# Default and initialization
# ---------------------------------------------------------------------------


class TestDefaults:
    """Tests for default score behavior."""

    @pytest.mark.asyncio
    async def test_default_score_for_unknown_agent(self, mgr):
        """get_score for unregistered address returns 30."""
        assert mgr.get_score("unknown::nowhere.com") == 30

    @pytest.mark.asyncio
    async def test_init_score_tier1(self, db, mgr):
        """init_score with dns_verified=False sets score to 30."""
        addr = await _register_agent(db)
        await mgr.init_score(addr, dns_verified=False)
        assert mgr.get_score(addr) == 30

    @pytest.mark.asyncio
    async def test_init_score_dns_verified(self, db, mgr):
        """init_score with dns_verified=True sets score to 60."""
        addr = await _register_agent(db, "verified::test.local")
        await mgr.init_score(addr, dns_verified=True)
        assert mgr.get_score(addr) == 60

    @pytest.mark.asyncio
    async def test_init_score_does_not_overwrite(self, db, mgr):
        """Calling init_score on an existing agent doesn't overwrite the score."""
        addr = await _register_agent(db, "existing::test.local")
        await mgr.init_score(addr, dns_verified=True)
        assert mgr.get_score(addr) == 60

        # Call again with different dns_verified -- should not change
        await mgr.init_score(addr, dns_verified=False)
        assert mgr.get_score(addr) == 60


# ---------------------------------------------------------------------------
# Tier classification
# ---------------------------------------------------------------------------


class TestTiers:
    """Tests for tier classification and send limits."""

    @pytest.mark.asyncio
    async def test_get_tier_full(self, db, mgr):
        """Score 80+ returns 'full'."""
        addr = await _register_agent(db)
        await mgr.init_score(addr)
        mgr._cache[addr] = 80
        assert mgr.get_tier(addr) == "full"

    @pytest.mark.asyncio
    async def test_get_tier_full_at_100(self, db, mgr):
        """Score 100 returns 'full'."""
        addr = await _register_agent(db)
        mgr._cache[addr] = 100
        assert mgr.get_tier(addr) == "full"

    @pytest.mark.asyncio
    async def test_get_tier_reduced(self, db, mgr):
        """Score 50-79 returns 'reduced'."""
        addr = await _register_agent(db)
        mgr._cache[addr] = 50
        assert mgr.get_tier(addr) == "reduced"
        mgr._cache[addr] = 79
        assert mgr.get_tier(addr) == "reduced"

    @pytest.mark.asyncio
    async def test_get_tier_throttled(self, db, mgr):
        """Score 20-49 returns 'throttled'."""
        addr = await _register_agent(db)
        mgr._cache[addr] = 20
        assert mgr.get_tier(addr) == "throttled"
        mgr._cache[addr] = 49
        assert mgr.get_tier(addr) == "throttled"

    @pytest.mark.asyncio
    async def test_get_tier_blocked(self, db, mgr):
        """Score <20 returns 'blocked'."""
        addr = await _register_agent(db)
        mgr._cache[addr] = 19
        assert mgr.get_tier(addr) == "blocked"
        mgr._cache[addr] = 0
        assert mgr.get_tier(addr) == "blocked"

    @pytest.mark.asyncio
    async def test_get_send_limit_by_tier(self, db, mgr):
        """Verify 60/30/10/0 for each tier."""
        addr = await _register_agent(db)

        mgr._cache[addr] = 80
        assert mgr.get_send_limit(addr) == 60  # full

        mgr._cache[addr] = 50
        assert mgr.get_send_limit(addr) == 30  # reduced

        mgr._cache[addr] = 20
        assert mgr.get_send_limit(addr) == 10  # throttled

        mgr._cache[addr] = 10
        assert mgr.get_send_limit(addr) == 0   # blocked


# ---------------------------------------------------------------------------
# Score mutations
# ---------------------------------------------------------------------------


class TestScoreUpdates:
    """Tests for update_score and set_score."""

    @pytest.mark.asyncio
    async def test_update_score_positive(self, db, mgr):
        """update_score with positive delta increases score."""
        addr = await _register_agent(db)
        await mgr.init_score(addr, dns_verified=False)
        new = await mgr.update_score(addr, +20)
        assert new == 50
        assert mgr.get_score(addr) == 50

    @pytest.mark.asyncio
    async def test_update_score_negative(self, db, mgr):
        """update_score with negative delta decreases score."""
        addr = await _register_agent(db)
        await mgr.init_score(addr, dns_verified=False)
        new = await mgr.update_score(addr, -10)
        assert new == 20
        assert mgr.get_score(addr) == 20

    @pytest.mark.asyncio
    async def test_update_score_clamped_at_100(self, db, mgr):
        """Score cannot exceed 100."""
        addr = await _register_agent(db)
        await mgr.init_score(addr, dns_verified=True)  # starts at 60
        new = await mgr.update_score(addr, +500)
        assert new == 100

    @pytest.mark.asyncio
    async def test_update_score_clamped_at_0(self, db, mgr):
        """Score cannot go below 0."""
        addr = await _register_agent(db)
        await mgr.init_score(addr, dns_verified=False)  # starts at 30
        new = await mgr.update_score(addr, -999)
        assert new == 0

    @pytest.mark.asyncio
    async def test_set_score_admin_override(self, db, mgr):
        """set_score directly sets the value."""
        addr = await _register_agent(db)
        await mgr.init_score(addr)
        await mgr.set_score(addr, 99)
        assert mgr.get_score(addr) == 99

    @pytest.mark.asyncio
    async def test_set_score_clamps_over_100(self, db, mgr):
        """set_score clamps values over 100."""
        addr = await _register_agent(db)
        await mgr.init_score(addr)
        await mgr.set_score(addr, 200)
        assert mgr.get_score(addr) == 100

    @pytest.mark.asyncio
    async def test_set_score_clamps_below_0(self, db, mgr):
        """set_score clamps values below 0."""
        addr = await _register_agent(db)
        await mgr.init_score(addr)
        await mgr.set_score(addr, -50)
        assert mgr.get_score(addr) == 0


# ---------------------------------------------------------------------------
# Cache loading
# ---------------------------------------------------------------------------


class TestCacheLoading:
    """Tests for load_cache() persistence round-trip."""

    @pytest.mark.asyncio
    async def test_load_cache_from_db(self, db):
        """Insert scores directly into DB, load_cache() populates manager."""
        addr = "preloaded::test.local"
        await db.execute(
            "INSERT INTO agents (address, public_key, token) VALUES (?, ?, ?)",
            (addr, "pk", "key1"),
        )
        await db.execute(
            "INSERT INTO reputation (address, score) VALUES (?, ?)",
            (addr, 75),
        )
        await db.commit()

        mgr = ReputationManager(db)
        await mgr.load_cache()
        assert mgr.get_score(addr) == 75

    @pytest.mark.asyncio
    async def test_load_cache_clears_old_entries(self, db):
        """load_cache() replaces previous cache state."""
        mgr = ReputationManager(db)
        mgr._cache["stale::entry.com"] = 99
        await mgr.load_cache()
        # Stale entry should be gone (nothing in DB)
        assert mgr.get_score("stale::entry.com") == 30  # falls back to default


# ---------------------------------------------------------------------------
# Reputation info and counters
# ---------------------------------------------------------------------------


class TestReputationInfo:
    """Tests for get_reputation_info and message counters."""

    @pytest.mark.asyncio
    async def test_get_reputation_info(self, db, mgr):
        """Returns full record including messages_sent, messages_rejected."""
        addr = await _register_agent(db)
        await mgr.init_score(addr)
        info = await mgr.get_reputation_info(addr)
        assert info is not None
        assert info["address"] == addr
        assert info["score"] == 30
        assert info["messages_sent"] == 0
        assert info["messages_rejected"] == 0
        assert "created_at" in info
        assert "updated_at" in info

    @pytest.mark.asyncio
    async def test_get_reputation_info_not_found(self, db, mgr):
        """Returns None for unknown address."""
        info = await mgr.get_reputation_info("ghost::unknown.com")
        assert info is None

    @pytest.mark.asyncio
    async def test_record_message_sent_increments(self, db, mgr):
        """After record_message_sent, messages_sent counter increases."""
        addr = await _register_agent(db)
        await mgr.init_score(addr)
        await mgr.record_message_sent(addr)
        await mgr.record_message_sent(addr)
        info = await mgr.get_reputation_info(addr)
        assert info["messages_sent"] == 2

    @pytest.mark.asyncio
    async def test_record_message_rejected_increments(self, db, mgr):
        """After record_message_rejected, messages_rejected counter increases."""
        addr = await _register_agent(db)
        await mgr.init_score(addr)
        await mgr.record_message_rejected(addr)
        info = await mgr.get_reputation_info(addr)
        assert info["messages_rejected"] == 1
