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
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import text
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
        return self._cache.get(domain, 50)

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

    async def record_success(self, domain: str) -> None:
        """Record a successful federation delivery from *domain*.

        Increments ``messages_forwarded``, updates ``last_success``,
        and bumps score by +1 (capped at 100).
        """
        async with self._session_factory() as session:
            # Ensure row exists with default score 50
            await session.execute(
                text("INSERT OR IGNORE INTO relay_reputation (domain) VALUES (:domain)"),
                {"domain": domain},
            )
            await session.execute(
                text(
                    "UPDATE relay_reputation SET "
                    "messages_forwarded = messages_forwarded + 1, "
                    "score = MIN(100, score + 1), "
                    "last_success = datetime('now'), "
                    "updated_at = datetime('now') "
                    "WHERE domain = :domain"
                ),
                {"domain": domain},
            )
            await session.commit()

            # Read back actual clamped value
            result = await session.execute(
                select(RelayReputation.score).where(RelayReputation.domain == domain)
            )
            new_score: int = result.scalar_one()

        old_score = self._cache.get(domain, 50)
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
        """
        async with self._session_factory() as session:
            # Ensure row exists with default score 50
            await session.execute(
                text("INSERT OR IGNORE INTO relay_reputation (domain) VALUES (:domain)"),
                {"domain": domain},
            )
            await session.execute(
                text(
                    "UPDATE relay_reputation SET "
                    "messages_rejected = messages_rejected + 1, "
                    "score = MAX(0, score - 5), "
                    "last_failure = datetime('now'), "
                    "updated_at = datetime('now') "
                    "WHERE domain = :domain"
                ),
                {"domain": domain},
            )
            await session.commit()

            # Read back actual clamped value
            result = await session.execute(
                select(RelayReputation.score).where(RelayReputation.domain == domain)
            )
            new_score: int = result.scalar_one()

        old_score = self._cache.get(domain, 50)
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
