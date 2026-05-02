"""In-memory TTL cache for peer-relay agent public keys (T1.4).

Used by ``src/uam/relay/routes/federation.py::_resolve_remote_sender_key`` to
avoid hammering the home relay's ``/api/v1/agents/{address}/public-key``
endpoint on every inbound federated envelope.

Design notes
------------
* **In-process only.** Each uvicorn worker holds its own cache. For an N-worker
  deploy this means up to N peer-relay calls per ``(worker, key, TTL)``. The
  ``/public-key`` endpoint is cheap (a single indexed SELECT) and the TTL bounds
  the blast radius of a poisoned cache to ``≤ UAM_FEDERATION_PEER_KEY_TTL``
  seconds (default 300). See ``43-RESEARCH.md`` § A5.
* **One ``asyncio.Lock`` around dict ops.** Mirrors the rate_limit
  ``SlidingWindowCounter`` pattern — simple, predictable, no lock contention
  hotspots at our request volume.
* **Auto-purge on read.** ``get()`` removes expired entries when it observes
  them. There is no background sweep (acceptable for a small, bounded cache).
* **Failed lookups are NOT cached.** ``_resolve_remote_sender_key`` only calls
  ``set()`` on a successful response, so a transient home-relay outage does
  not get pinned for ``ttl`` seconds.
"""

from __future__ import annotations

import asyncio
import time


class PeerKeyCache:
    """In-memory TTL cache for peer-relay agent public keys.

    Not shared across processes — each uvicorn worker has its own cache.
    For multi-worker deploys this means up to N peer-relay calls per
    (worker, key, TTL). Acceptable for v4-hardening: peer-relay
    ``/public-key`` is cheap and TTL bounds the blast radius of a poisoned
    cache to ``UAM_FEDERATION_PEER_KEY_TTL`` seconds.
    """

    def __init__(self) -> None:
        self._data: dict[str, tuple[str, float]] = {}
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> str | None:
        """Return the cached value, or ``None`` if missing / expired.

        Auto-purges expired entries on access.
        """
        async with self._lock:
            entry = self._data.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.monotonic() > expires_at:
                self._data.pop(key, None)
                return None
            return value

    async def set(self, key: str, value: str, ttl: int) -> None:
        """Cache *value* under *key* for *ttl* seconds."""
        async with self._lock:
            self._data[key] = (value, time.monotonic() + ttl)

    async def invalidate(self, key: str) -> None:
        """Drop *key* from the cache, if present."""
        async with self._lock:
            self._data.pop(key, None)


# Module-level singleton (mirrors how SlidingWindowCounter is constructed
# on app.state — but the cache is process-global so we can hold one instance
# at module import time).
peer_key_cache = PeerKeyCache()
