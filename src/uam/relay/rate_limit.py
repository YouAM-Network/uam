"""Sliding-window rate limiter for the UAM relay server (RELAY-05).

Per-sender limit: 60 msg/min.
Per-recipient limit: 100 msg/min.

Uses ``time.monotonic()`` for timestamps -- immune to wall-clock adjustments.

T4.2 (Phase 44 Plan 02): ``check``, ``remaining``, and ``cleanup`` are all
async and acquire a per-instance ``asyncio.Lock`` for the duration of their
read-modify-write body. The same instance is shared across every WS recv
loop, every ``/api/v1/send``, and the federation retry loop — atomicity is
hot-path-critical. ``cleanup`` snapshots ``list(self._buckets.items())``
inside the lock so a concurrent ``check`` reassigning ``self._buckets[key]``
cannot raise ``RuntimeError: dictionary changed size during iteration``.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class SlidingWindowCounter:
    """In-memory sliding-window counter with per-instance asyncio.Lock (T4.2).

    All public methods (check, remaining, cleanup) are async and acquire
    the lock for the duration of their read-modify-write body. The same
    instance is shared across every WS recv loop, every /api/v1/send,
    and the federation retry loop, so atomicity is hot-path-critical.

    ``cleanup`` snapshots ``list(self._buckets.items())`` inside the lock
    so a concurrent ``check`` reassigning ``self._buckets[key]`` cannot
    raise ``RuntimeError: dictionary changed size during iteration``.
    """

    limit: int
    window_seconds: float
    _buckets: dict[str, list[float]] = field(
        default_factory=lambda: defaultdict(list),
        repr=False,
    )
    # T4.2: per-instance lock created at instance construction. Python ≥3.10
    # asyncio.Lock is loop-agnostic at construction time (it binds to the
    # running loop on first acquire), so dataclass field default_factory is safe.
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False, init=False)

    async def check(self, key: str, limit: int | None = None) -> bool:
        """Return True if *key* is under the rate limit, else False.

        Prunes stale timestamps, then checks count. If under limit,
        records a new timestamp and returns True.

        An optional *limit* overrides the instance default for this
        single call, enabling adaptive per-sender rate limiting.

        T4.2: read-modify-write is fully serialized by ``self._lock``.
        """
        effective_limit = limit if limit is not None else self.limit
        now = time.monotonic()
        cutoff = now - self.window_seconds
        async with self._lock:
            bucket = self._buckets[key]
            # Prune expired entries
            self._buckets[key] = bucket = [ts for ts in bucket if ts > cutoff]
            if len(bucket) >= effective_limit:
                return False
            bucket.append(now)
            return True

    async def remaining(self, key: str, limit: int | None = None) -> int:
        """Return the number of requests remaining for *key*.

        An optional *limit* overrides the instance default, matching
        the adaptive behaviour of :meth:`check`.
        """
        effective_limit = limit if limit is not None else self.limit
        now = time.monotonic()
        cutoff = now - self.window_seconds
        async with self._lock:
            bucket = self._buckets.get(key, [])
            current = sum(1 for ts in bucket if ts > cutoff)
            return max(0, effective_limit - current)

    async def cleanup(self) -> None:
        """Remove keys with no recent events (prevents memory leak).

        T4.2: snapshots ``list(self._buckets.items())`` BEFORE iterating
        so a concurrent ``check`` reassigning ``self._buckets[key]`` cannot
        trigger ``RuntimeError: dictionary changed size during iteration``.
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds
        async with self._lock:
            # T4.2: snapshot BEFORE iterating — defaultdict(list) mutation
            # by a concurrent check() would otherwise raise during iteration.
            items_snapshot = list(self._buckets.items())
            empty_keys = [
                key
                for key, bucket in items_snapshot
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
