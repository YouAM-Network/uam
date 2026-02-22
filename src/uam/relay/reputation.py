"""Reputation scoring for relay agents (SPAM-02).

Each registered agent has a reputation score (0-100) that determines
their tier and associated rate limits:

- **Full** (>=80): 60 msg/min -- trusted agents
- **Reduced** (>=50): 30 msg/min -- normal agents
- **Throttled** (>=20): 10 msg/min -- probationary
- **Blocked** (<20): 0 msg/min -- effectively silenced

Scores are cached in memory with SQLite persistence.  New agents
default to score 30 (Tier 1); DNS-verified agents start at 60.
"""

from __future__ import annotations

import logging
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)


class ReputationManager:
    """In-memory cached reputation scores backed by SQLite."""

    # Tier thresholds (score >= threshold)
    TIER_FULL = 80
    TIER_REDUCED = 50
    TIER_THROTTLED = 20

    # Rate limits per tier
    TIER_LIMITS: dict[str, dict[str, int]] = {
        "full": {"send_limit": 60},
        "reduced": {"send_limit": 30},
        "throttled": {"send_limit": 10},
        "blocked": {"send_limit": 0},
    }

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db
        self._cache: dict[str, int] = {}
        self._dirty: set[str] = set()

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------

    async def load_cache(self) -> None:
        """Load all reputation scores from DB into the in-memory cache."""
        cursor = await self._db.execute("SELECT address, score FROM reputation")
        rows = await cursor.fetchall()
        self._cache.clear()
        for row in rows:
            self._cache[row["address"] if isinstance(row, dict) else row[0]] = (
                row["score"] if isinstance(row, dict) else row[1]
            )
        logger.info("Loaded %d reputation scores into cache", len(self._cache))

    # ------------------------------------------------------------------
    # O(1) lookups (memory only)
    # ------------------------------------------------------------------

    def get_score(self, address: str) -> int:
        """Return the reputation score for *address* (default 30)."""
        return self._cache.get(address, 30)

    def get_tier(self, address: str) -> str:
        """Return the tier name for *address* based on score thresholds."""
        score = self.get_score(address)
        if score >= self.TIER_FULL:
            return "full"
        if score >= self.TIER_REDUCED:
            return "reduced"
        if score >= self.TIER_THROTTLED:
            return "throttled"
        return "blocked"

    def get_send_limit(self, address: str) -> int:
        """Return the send rate limit for the agent's current tier."""
        return self.TIER_LIMITS[self.get_tier(address)]["send_limit"]

    # ------------------------------------------------------------------
    # Score mutations (DB + cache)
    # ------------------------------------------------------------------

    async def init_score(self, address: str, dns_verified: bool = False) -> None:
        """Initialize reputation for a newly registered agent.

        DNS-verified agents start at 60; others at 30.
        Uses ``INSERT OR IGNORE`` so existing scores are not overwritten.
        """
        score = 60 if dns_verified else 30
        await self._db.execute(
            "INSERT OR IGNORE INTO reputation (address, score) VALUES (?, ?)",
            (address, score),
        )
        await self._db.commit()
        # Only update cache if not already present (matches INSERT OR IGNORE)
        if address not in self._cache:
            self._cache[address] = score
            logger.info(
                "Initialized reputation for %s: score=%d (dns_verified=%s)",
                address, score, dns_verified,
            )

    async def update_score(self, address: str, delta: int) -> int:
        """Atomically adjust score by *delta* (clamped 0-100).

        If the address has no reputation row yet, one is created with
        default score 30 before applying the delta.  Returns the new score.
        """
        # Ensure row exists
        await self._db.execute(
            "INSERT OR IGNORE INTO reputation (address, score) VALUES (?, 30)",
            (address,),
        )
        await self._db.execute(
            "UPDATE reputation SET score = MAX(0, MIN(100, score + ?)), "
            "updated_at = datetime('now') WHERE address = ?",
            (delta, address),
        )
        await self._db.commit()

        # Read back the actual clamped value
        cursor = await self._db.execute(
            "SELECT score FROM reputation WHERE address = ?", (address,)
        )
        row = await cursor.fetchone()
        new_score: int = row["score"] if isinstance(row, dict) else row[0]  # type: ignore[index]
        old_score = self._cache.get(address, 30)
        self._cache[address] = new_score

        # Log tier transitions
        old_tier = self._tier_for_score(old_score)
        new_tier = self._tier_for_score(new_score)
        if old_tier != new_tier:
            logger.warning(
                "Tier change for %s: %s -> %s (score %d -> %d)",
                address, old_tier, new_tier, old_score, new_score,
            )
        else:
            logger.info(
                "Score updated for %s: %d -> %d (delta=%+d)",
                address, old_score, new_score, delta,
            )
        return new_score

    async def set_score(self, address: str, score: int) -> None:
        """Admin override -- directly set a score (clamped 0-100)."""
        clamped = max(0, min(100, score))
        await self._db.execute(
            "INSERT INTO reputation (address, score) VALUES (?, ?) "
            "ON CONFLICT(address) DO UPDATE SET score = ?, updated_at = datetime('now')",
            (address, clamped, clamped),
        )
        await self._db.commit()
        old_score = self._cache.get(address, 30)
        self._cache[address] = clamped
        logger.warning(
            "Admin set score for %s: %d -> %d", address, old_score, clamped,
        )

    # ------------------------------------------------------------------
    # Counters
    # ------------------------------------------------------------------

    async def record_message_sent(self, address: str) -> None:
        """Increment the messages_sent counter for *address*."""
        await self._db.execute(
            "UPDATE reputation SET messages_sent = messages_sent + 1, "
            "updated_at = datetime('now') WHERE address = ?",
            (address,),
        )
        await self._db.commit()

    async def record_message_rejected(self, address: str) -> None:
        """Increment the messages_rejected counter for *address*."""
        await self._db.execute(
            "UPDATE reputation SET messages_rejected = messages_rejected + 1, "
            "updated_at = datetime('now') WHERE address = ?",
            (address,),
        )
        await self._db.commit()

    # ------------------------------------------------------------------
    # Admin inspection
    # ------------------------------------------------------------------

    async def get_reputation_info(self, address: str) -> dict[str, Any] | None:
        """Return the full reputation row for admin inspection, or None."""
        cursor = await self._db.execute(
            "SELECT address, score, messages_sent, messages_rejected, "
            "created_at, updated_at FROM reputation WHERE address = ?",
            (address,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _tier_for_score(self, score: int) -> str:
        """Determine tier from a raw score value."""
        if score >= self.TIER_FULL:
            return "full"
        if score >= self.TIER_REDUCED:
            return "reduced"
        if score >= self.TIER_THROTTLED:
            return "throttled"
        return "blocked"
