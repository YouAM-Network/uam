"""Reputation scoring for relay agents (SPAM-02).

Each registered agent has a reputation score (0-100) that determines
their tier and associated rate limits:

- **Full** (>=80): 60 msg/min -- trusted agents
- **Reduced** (>=50): 30 msg/min -- normal agents
- **Throttled** (>=20): 10 msg/min -- probationary
- **Blocked** (<20): 0 msg/min -- effectively silenced

Scores are cached in memory with SQLAlchemy/SQLModel persistence.  New agents
default to score 30 (Tier 1); DNS-verified agents start at 60.

Phase 46 Plan 46-04 (T6.4):
    ``update_score``, ``record_message_sent``, and ``record_message_rejected``
    were converted from SELECT-then-mutate-in-Python-then-COMMIT to a single
    atomic ``UPDATE`` statement with arithmetic in SQL. The previous
    read-modify-write pattern was vulnerable to lost-update races: 100
    concurrent ``record_message_sent`` calls could all read
    ``messages_sent=N`` and all write ``messages_sent=N+1``, losing 99
    increments.

    The atomic form is::

        UPDATE reputation
        SET score = MAX(0, MIN(100, score + :delta)),
            updated_at = now()
        WHERE address = :address

    Both Postgres and SQLite evaluate ``score + :delta`` atomically inside
    the row lock, so 100 concurrent invocations land 100 deltas. Row-existence
    is ensured first via a try/IntegrityError-rollback in a separate session,
    mirroring the existing portable pattern from
    ``src/uam/db/crud/reputation.py:init_reputation``.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, update
from sqlalchemy.exc import IntegrityError
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

    async def _ensure_row(self, address: str, score: int = 30) -> None:
        """Insert default-score row if absent. Race-safe via IntegrityError.

        Mirrors the portable pattern from
        ``src/uam/db/crud/reputation.py:init_reputation``. Runs in its own
        session so a rollback here cannot poison the caller's session state.
        """
        async with self._session_factory() as session:
            try:
                session.add(Reputation(address=address, score=score))
                await session.commit()
            except IntegrityError:
                await session.rollback()  # row already exists -- fine

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

        T6.4: single SQL ``UPDATE`` with arithmetic-in-SQL clamp via
        ``func.max``/``func.min`` -- both Postgres and SQLite serialize
        the row mutation, so concurrent calls do not lose updates.

        If the address has no reputation row yet, one is created with
        default score 30 before applying the delta.  Returns the new score.
        """
        # Step 1: ensure row exists in its own session (race-safe via IntegrityError).
        await self._ensure_row(address, score=30)

        # Step 2: atomic UPDATE -- arithmetic + clamp inside SQL.
        async with self._session_factory() as session:
            stmt = (
                update(Reputation)
                .where(Reputation.address == address)
                .values(
                    score=func.max(0, func.min(100, Reputation.score + delta)),
                    updated_at=func.now(),
                )
            )
            await session.execute(stmt)
            await session.commit()

            # Step 3: read back for cache + tier-transition logging.
            result = await session.execute(
                select(Reputation.score).where(Reputation.address == address)
            )
            new_score = int(result.scalar_one())

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
        # Ensure row exists, then atomic UPDATE (consistent with update_score).
        await self._ensure_row(address, score=clamped)
        async with self._session_factory() as session:
            stmt = (
                update(Reputation)
                .where(Reputation.address == address)
                .values(
                    score=clamped,
                    updated_at=func.now(),
                )
            )
            await session.execute(stmt)
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
        """Increment the messages_sent counter for *address*.

        T6.4: atomic ``UPDATE Reputation SET messages_sent =
        messages_sent + 1, updated_at = now() WHERE address = ?`` --
        100 concurrent invocations land 100 increments.
        """
        await self._ensure_row(address, score=30)
        async with self._session_factory() as session:
            stmt = (
                update(Reputation)
                .where(Reputation.address == address)
                .values(
                    messages_sent=Reputation.messages_sent + 1,
                    updated_at=func.now(),
                )
            )
            await session.execute(stmt)
            await session.commit()

    async def record_message_rejected(self, address: str) -> None:
        """Increment the messages_rejected counter for *address*.

        T6.4: atomic ``UPDATE`` with arithmetic in SQL -- mirrors
        ``record_message_sent`` but on the ``messages_rejected`` column.
        """
        await self._ensure_row(address, score=30)
        async with self._session_factory() as session:
            stmt = (
                update(Reputation)
                .where(Reputation.address == address)
                .values(
                    messages_rejected=Reputation.messages_rejected + 1,
                    updated_at=func.now(),
                )
            )
            await session.execute(stmt)
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
