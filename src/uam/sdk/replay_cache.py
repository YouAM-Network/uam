"""In-process TTL cache for SDK-side envelope replay protection (T3.1).

Used by ``src/uam/sdk/agent.py::_process_inbound`` to drop envelopes whose
``(from_address, message_id)`` pair has been seen within the TTL window.

Design notes
------------
* **In-process only.** One cache per ``Agent`` instance. Lost on ``agent.close()``;
  long-running agents reconnecting do NOT lose cache state. Short-lived CLI
  invocations (``uam send`` etc.) don't need persistence -- the timestamp-window
  check (``MAX_ENVELOPE_AGE``) caps the replay window even with an empty cache.
  See RESEARCH § Open Question 3.
* **One ``asyncio.Lock`` around dict ops.** Mirrors the
  ``PeerKeyCache`` pattern (``src/uam/relay/peer_key_cache.py``) verified
  working in production since Phase 43 ``44d8867d``.
* **OrderedDict-LRU eviction at capacity.** Bounded to ~100k entries by default;
  override via ``UAM_REPLAY_CACHE_CAPACITY`` env var.
* **Auto-purge on read.** TTL-expired entries are treated as new (not replays).
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict


class EnvelopeReplayCache:
    """In-process TTL cache for inbound (from_address, message_id) pairs.

    Drops replays of envelopes seen within ``ttl`` seconds.
    Bounded to ``capacity`` entries via OrderedDict-LRU eviction.
    """

    def __init__(self, *, capacity: int = 100_000, ttl: int = 300) -> None:
        self._data: OrderedDict[tuple[str, str], float] = OrderedDict()
        self._lock = asyncio.Lock()
        self._capacity = capacity
        self._ttl = ttl

    async def seen_or_record(self, from_address: str, message_id: str) -> bool:
        """Return True iff this pair was already in the cache (replay).

        Otherwise record it and return False.
        """
        key = (from_address, message_id)
        now = time.monotonic()
        async with self._lock:
            entry = self._data.get(key)
            if entry is not None and now - entry < self._ttl:
                self._data.move_to_end(key)  # LRU touch
                return True
            self._data[key] = now
            self._data.move_to_end(key)
            while len(self._data) > self._capacity:
                self._data.popitem(last=False)
            return False
