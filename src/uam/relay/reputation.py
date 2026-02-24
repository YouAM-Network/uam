"""Reputation scoring for relay agents (SPAM-02).

Each registered agent has a reputation score (0-100) that determines
their tier and associated rate limits:

- **Full** (>=80): 60 msg/min -- trusted agents
- **Reduced** (>=50): 30 msg/min -- normal agents
- **Throttled** (>=20): 10 msg/min -- probationary
- **Blocked** (<20): 0 msg/min -- effectively silenced

Scores are cached in memory with SQLAlchemy/SQLModel persistence.  New agents
default to score 30 (Tier 1); DNS-verified agents start at 60.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlmodel import select

from uam.db.models import Reputation

logger = logging.getLogger(__name__)


class ReputationManager:
    """In-memory cached reputation scores backed by async DB sessions."""

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

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._cache: dict[str, int] = {}
        self._dirty: set[str] = set()

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------

    async def load_cache(self) -> None:
        """Load all reputation scores from DB into the in-memory cache."""
        async with self._session_factory() as session:
            result = await session.execute(select(Reputation))
            rows = result.scalars().all()
            self._cache.clear()
            for row in rows:
                self._cache[row.address] = row.score
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
        Skips insert if a row already exists (INSERT OR IGNORE semantics).
        """
        score = 60 if dns_verified else 30
        async with self._session_factory() as session:
            # Check if row already exists
            result = await session.execute(
                select(Reputation).where(Reputation.address == address)
            )
            if result.scalar_one_or_none() is not None:
                return  # already exists, don't overwrite
            entry = Reputation(address=address, score=score)
            session.add(entry)
            await session.commit()
        # Only update cache if not already present
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
        async with self._session_factory() as session:
            # Ensure row exists
            result = await session.execute(
                select(Reputation).where(Reputation.address == address)
            )
            row = result.scalar_one_or_none()
            if row is None:
                row = Reputation(address=address, score=30)
                session.add(row)
                await session.flush()

            # Apply delta with clamping
            row.score = max(0, min(100, row.score + delta))
            row.updated_at = datetime.utcnow()
            session.add(row)
            await session.commit()
            await session.refresh(row)
            new_score = row.score

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
        async with self._session_factory() as session:
            result = await session.execute(
                select(Reputation).where(Reputation.address == address)
            )
            row = result.scalar_one_or_none()
            if row is None:
                row = Reputation(address=address, score=clamped)
            else:
                row.score = clamped
                row.updated_at = datetime.utcnow()
            session.add(row)
            await session.commit()
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
        async with self._session_factory() as session:
            result = await session.execute(
                select(Reputation).where(Reputation.address == address)
            )
            row = result.scalar_one_or_none()
            if row is not None:
                row.messages_sent += 1
                row.updated_at = datetime.utcnow()
                session.add(row)
                await session.commit()

    async def record_message_rejected(self, address: str) -> None:
        """Increment the messages_rejected counter for *address*."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(Reputation).where(Reputation.address == address)
            )
            row = result.scalar_one_or_none()
            if row is not None:
                row.messages_rejected += 1
                row.updated_at = datetime.utcnow()
                session.add(row)
                await session.commit()

    # ------------------------------------------------------------------
    # Admin inspection
    # ------------------------------------------------------------------

    async def get_reputation_info(self, address: str) -> dict[str, Any] | None:
        """Return the full reputation row for admin inspection, or None."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(Reputation).where(Reputation.address == address)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return None
            return {
                "address": row.address,
                "score": row.score,
                "messages_sent": row.messages_sent,
                "messages_rejected": row.messages_rejected,
                "created_at": str(row.created_at),
                "updated_at": str(row.updated_at),
            }

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
