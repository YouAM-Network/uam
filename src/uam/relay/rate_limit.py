"""Sliding-window rate limiter for the UAM relay server (RELAY-05).

Per-sender limit: 60 msg/min.
Per-recipient limit: 100 msg/min.

Uses ``time.monotonic()`` for timestamps -- immune to wall-clock adjustments.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class SlidingWindowCounter:
    """In-memory sliding-window counter for rate limiting."""

    limit: int
    window_seconds: float
    _buckets: dict[str, list[float]] = field(
        default_factory=lambda: defaultdict(list),
        repr=False,
    )

    def check(self, key: str, limit: int | None = None) -> bool:
        """Return True if *key* is under the rate limit, else False.

        Prunes stale timestamps, then checks count. If under limit,
        records a new timestamp and returns True.

        An optional *limit* overrides the instance default for this
        single call, enabling adaptive per-sender rate limiting.
        """
        effective_limit = limit if limit is not None else self.limit
        now = time.monotonic()
        cutoff = now - self.window_seconds
        bucket = self._buckets[key]
        # Prune expired entries
        self._buckets[key] = bucket = [ts for ts in bucket if ts > cutoff]
        if len(bucket) >= effective_limit:
            return False
        bucket.append(now)
        return True

    def remaining(self, key: str, limit: int | None = None) -> int:
        """Return the number of requests remaining for *key*.

        An optional *limit* overrides the instance default, matching
        the adaptive behaviour of :meth:`check`.
        """
        effective_limit = limit if limit is not None else self.limit
        now = time.monotonic()
        cutoff = now - self.window_seconds
        bucket = self._buckets.get(key, [])
        current = sum(1 for ts in bucket if ts > cutoff)
        return max(0, effective_limit - current)

    def cleanup(self) -> None:
        """Remove keys with no recent events (prevents memory leak)."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        empty_keys = [
            key
            for key, bucket in self._buckets.items()
            if not any(ts > cutoff for ts in bucket)
        ]
        for key in empty_keys:
            del self._buckets[key]

    def __len__(self) -> int:
        """Return the number of tracked keys (for monitoring)."""
        return len(self._buckets)

    def total_keys(self) -> int:
        """Return the number of tracked keys (alias for ``len()``)."""
        return len(self._buckets)
