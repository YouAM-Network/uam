"""Reputation scoring for peer relay domains (FED-08).

Each peer relay has a reputation score (0-100) that determines its
federation rate limit tier:

- **Full** (>=80): ``base_rate_limit`` msg/min (default 1000)
- **Normal** (>=50): ``base_rate_limit / 2`` msg/min (default 500)
- **Throttled** (>=20): ``base_rate_limit / 10`` msg/min (default 100)
- **Blocked** (<20): 0 msg/min -- effectively federation-blocklisted

Scores are cached in memory with SQLAlchemy/SQLModel persistence.  New relays
default to score 50 (neutral trust -- higher than agent default of 30
because relays are more accountable infrastructure).

Phase 46 Plan 46-04 (T6.3):
    The previous implementation used SQLite-only SQL via raw ``text(...)``
    upsert and ``now()`` literals, which crashes on PostgreSQL with a
    syntax error. The federation forwarding path would fail at the first
    inbound peer-relay message in production.

    The portable replacement uses SQLAlchemy ORM expressions throughout:

    - Upsert: ``session.add(...)`` + try/except IntegrityError with
      rollback (mirrors ``src/uam/db/crud/reputation.py:init_reputation``).
    - Timestamps: ``func.now()`` (dialect-aware -- emits CURRENT_TIMESTAMP
      on Postgres, the equivalent SQLite literal on SQLite).
    - Score arithmetic clamps moved into ``func.min`` / ``func.max``
      inside the ORM ``update().values()`` call.

    Both ``record_success`` and ``record_failure`` now ensure-row in a
    separate session (try/IntegrityError) and then run an atomic UPDATE
    with arithmetic-in-SQL -- portable across SQLite and PostgreSQL.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlmodel import select

from uam.db.models import RelayReputation

logger = logging.getLogger(__name__)


class RelayReputationManager:
    """In-memory cached reputation scores for peer relay domains."""

    # Tier thresholds (score >= threshold)
    TIER_FULL = 80
    TIER_NORMAL = 50
    TIER_THROTTLED = 20

    # Default neutral-trust score for newly-seen peer relays.
    DEFAULT_SCORE = 50

    def __init__(self, session_factory: async_sessionmaker[AsyncSession], base_rate_limit: int = 1000) -> None:
        self._session_factory = session_factory
        self._cache: dict[str, int] = {}
        self._base_rate_limit = base_rate_limit

    # ------------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------------

    async def load_cache(self) -> None:
        """Load all relay reputation scores from DB into the in-memory cache."""
        async with self._session_factory() as session:
            result = await session.execute(select(RelayReputation))
            rows = result.scalars().all()
            self._cache.clear()
            for row in rows:
                self._cache[row.domain] = row.score
            logger.info("Loaded %d relay reputation scores into cache", len(self._cache))

    # ------------------------------------------------------------------
    # O(1) lookups (memory only)
    # ------------------------------------------------------------------

    def get_score(self, domain: str) -> int:
        """Return the reputation score for *domain* (default 50)."""
        return self._cache.get(domain, self.DEFAULT_SCORE)

    def get_tier(self, domain: str) -> str:
        """Return the tier name for *domain* based on score thresholds."""
        score = self.get_score(domain)
        return self._tier_for_score(score)

    def get_rate_limit(self, domain: str) -> int:
        """Return the federation rate limit for this peer based on reputation tier.

        - full (>=80): base_rate_limit (default 1000)
        - normal (>=50): base_rate_limit / 2 (default 500)
        - throttled (>=20): base_rate_limit / 10 (default 100)
        - blocked (<20): 0
        """
        tier = self.get_tier(domain)
        if tier == "full":
            return self._base_rate_limit
        if tier == "normal":
            return self._base_rate_limit // 2
        if tier == "throttled":
            return self._base_rate_limit // 10
        return 0  # blocked

    # ------------------------------------------------------------------
    # Score mutations (DB + cache)
    # ------------------------------------------------------------------

    async def _ensure_row(self, domain: str) -> None:
        """Insert default-score row if absent. Race-safe via IntegrityError.

        Mirrors the portable pattern from
        ``src/uam/db/crud/reputation.py:init_reputation``. Runs in its own
        session so a rollback here cannot poison the caller's session state.
        """
        async with self._session_factory() as session:
            try:
                session.add(RelayReputation(domain=domain, score=self.DEFAULT_SCORE))
                await session.commit()
            except IntegrityError:
                await session.rollback()  # row already exists -- fine

    async def record_success(self, domain: str) -> None:
        """Record a successful federation delivery from *domain*.

        Increments ``messages_forwarded``, updates ``last_success``,
        and bumps score by +1 (capped at 100).

        T6.3: portable SQL -- try/IntegrityError-rollback for ensure-row +
        atomic ``UPDATE`` with ``func.min`` clamp + ``func.now()`` timestamp.
        """
        # Step 1: ensure row exists (portable, race-safe).
        await self._ensure_row(domain)

        # Step 2: atomic UPDATE -- increment counter + clamped score + portable timestamp.
        async with self._session_factory() as session:
            stmt = (
                update(RelayReputation)
                .where(RelayReputation.domain == domain)
                .values(
                    messages_forwarded=RelayReputation.messages_forwarded + 1,
                    score=func.min(100, RelayReputation.score + 1),
                    last_success=func.now(),
                    updated_at=func.now(),
                )
            )
            await session.execute(stmt)
            await session.commit()

            # Step 3: read back actual clamped value for cache + tier-transition logging.
            result = await session.execute(
                select(RelayReputation.score).where(RelayReputation.domain == domain)
            )
            new_score = int(result.scalar_one())

        old_score = self._cache.get(domain, self.DEFAULT_SCORE)
        self._cache[domain] = new_score

        # Log tier transitions
        old_tier = self._tier_for_score(old_score)
        new_tier = self._tier_for_score(new_score)
        if old_tier != new_tier:
            logger.warning(
                "Relay tier change for %s: %s -> %s (score %d -> %d)",
                domain, old_tier, new_tier, old_score, new_score,
            )
        else:
            logger.debug(
                "Relay success for %s: score %d -> %d",
                domain, old_score, new_score,
            )

    async def record_failure(self, domain: str, reason: str = "") -> None:
        """Record a failed/rejected federation attempt from *domain*.

        Increments ``messages_rejected``, updates ``last_failure``,
        and decrements score by -5 (floor at 0).

        T6.3: portable SQL -- try/IntegrityError-rollback for ensure-row +
        atomic ``UPDATE`` with ``func.max`` clamp + ``func.now()`` timestamp.
        """
        # Step 1: ensure row exists (portable, race-safe).
        await self._ensure_row(domain)

        # Step 2: atomic UPDATE -- increment counter + clamped score + portable timestamp.
        async with self._session_factory() as session:
            stmt = (
                update(RelayReputation)
                .where(RelayReputation.domain == domain)
                .values(
                    messages_rejected=RelayReputation.messages_rejected + 1,
                    score=func.max(0, RelayReputation.score - 5),
                    last_failure=func.now(),
                    updated_at=func.now(),
                )
            )
            await session.execute(stmt)
            await session.commit()

            # Step 3: read back actual clamped value for cache + tier-transition logging.
            result = await session.execute(
                select(RelayReputation.score).where(RelayReputation.domain == domain)
            )
            new_score = int(result.scalar_one())

        old_score = self._cache.get(domain, self.DEFAULT_SCORE)
        self._cache[domain] = new_score

        # Log tier transitions
        old_tier = self._tier_for_score(old_score)
        new_tier = self._tier_for_score(new_score)
        if old_tier != new_tier:
            logger.warning(
                "Relay tier change for %s: %s -> %s (score %d -> %d, reason: %s)",
                domain, old_tier, new_tier, old_score, new_score, reason,
            )
        else:
            logger.info(
                "Relay failure for %s: score %d -> %d (reason: %s)",
                domain, old_score, new_score, reason,
            )

    # ------------------------------------------------------------------
    # Admin inspection
    # ------------------------------------------------------------------

    async def get_info(self, domain: str) -> dict[str, Any] | None:
        """Return the full reputation row for admin inspection, or None."""
        async with self._session_factory() as session:
            result = await session.execute(
                select(RelayReputation).where(RelayReputation.domain == domain)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return None
            return {
                "domain": row.domain,
                "score": row.score,
                "messages_forwarded": row.messages_forwarded,
                "messages_rejected": row.messages_rejected,
                "last_success": str(row.last_success) if row.last_success else None,
                "last_failure": str(row.last_failure) if row.last_failure else None,
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
        if score >= self.TIER_NORMAL:
            return "normal"
        if score >= self.TIER_THROTTLED:
            return "throttled"
        return "blocked"
