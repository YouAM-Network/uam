"""Envelope replay protection for the SDK (T3.1).

Used by ``src/uam/sdk/agent.py::_process_inbound`` to drop envelopes whose
``(from_address, message_id)`` pair has been seen before.

``PersistentReplayCache`` is what the Agent uses: a SQLite file under the
agent's data dir, shared by every process using that dir, that keeps each
pair for ``RETENTION_SECONDS``.  Stored mail can arrive days after it was
signed, so the window an envelope can be accepted in is longer than one
process lives.

* **Never evicts inside the window.** Rows go only when they are older than
  ``RETENTION_SECONDS``.  When the file holds ``capacity`` rows it fails
  closed: an envelope signed within ``MAX_ENVELOPE_AGE`` is still accepted
  (and deduplicated in memory); anything older is refused.
* **Knows its age.** ``created_at`` is written once, so a caller can refuse
  old stored mail signed before the cache existed (it could have been seen
  by an earlier in-memory cache).

``EnvelopeReplayCache`` below is the in-memory cache it falls back on when
full.

EnvelopeReplayCache design notes
--------------------------------
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
import logging
import sqlite3
import time
from collections import OrderedDict
from pathlib import Path
from typing import Callable

import aiosqlite

from uam.protocol.types import MAX_ENVELOPE_AGE
from uam.sdk.freshness import STORED_MAIL_MAX_AGE

logger = logging.getLogger(__name__)

# Seven days of stored mail, plus the freshness window on either side of
# the signed timestamp (clock skew between sender, relay and recipient).
RETENTION_SECONDS = STORED_MAIL_MAX_AGE + 2 * MAX_ENVELOPE_AGE

# How often expired rows are purged, at most.
_PURGE_INTERVAL = 60.0

_WAL_ATTEMPTS = 100

_SCHEMA = """
CREATE TABLE IF NOT EXISTS seen_envelopes (
    from_address TEXT NOT NULL,
    message_id   TEXT NOT NULL,
    seen_at      REAL NOT NULL,
    PRIMARY KEY (from_address, message_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS seen_envelopes_seen_at ON seen_envelopes (seen_at);
CREATE TABLE IF NOT EXISTS replay_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


async def _enable_wal(db: aiosqlite.Connection) -> None:
    """Switch *db* to WAL, waiting out another process doing the same.

    SQLite doesn't apply the busy timeout to this switch: two processes
    opening a new file together get "database is locked" at once.
    """
    for _ in range(_WAL_ATTEMPTS - 1):
        try:
            await db.execute("PRAGMA journal_mode=WAL")
            return
        except sqlite3.OperationalError:
            await asyncio.sleep(0.1)
    await db.execute("PRAGMA journal_mode=WAL")


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

    async def has(self, from_address: str, message_id: str) -> bool:
        """True if this pair is in the cache and within its TTL."""
        entry = self._data.get((from_address, message_id))
        return entry is not None and time.monotonic() - entry < self._ttl


class PersistentReplayCache:
    """Inbound (from_address, message_id) pairs kept in a SQLite file.

    Opens itself on first use, so an Agent driven without ``connect()``
    still has replay protection.  Safe to share between processes: the
    insert is the check (``INSERT OR IGNORE``), in WAL mode.
    """

    def __init__(
        self,
        path: Path | str,
        *,
        capacity: int = 1_000_000,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if capacity <= 0:
            raise ValueError("capacity must be positive")
        self._path = Path(path)
        self._capacity = capacity
        self._clock = clock
        self._db: aiosqlite.Connection | None = None
        self._open_lock = asyncio.Lock()
        self._count = 0
        self._last_purge = 0.0
        self._created_at = 0.0
        # Holds what arrives while the file is full.  An envelope signed
        # MAX_ENVELOPE_AGE ahead stays acceptable for twice that.
        self._overflow = EnvelopeReplayCache(capacity=10_000, ttl=2 * MAX_ENVELOPE_AGE)

    async def _ensure_open(self) -> aiosqlite.Connection:
        if self._db is not None:
            return self._db
        async with self._open_lock:
            if self._db is None:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                db = await aiosqlite.connect(str(self._path), timeout=30)
                try:
                    await self._prepare(db)
                except BaseException:
                    # An open connection's thread would keep the process alive.
                    await db.close()
                    raise
                self._db = db
                await self._purge()
        return self._db

    async def _prepare(self, db: aiosqlite.Connection) -> None:
        await _enable_wal(db)
        await db.executescript(_SCHEMA)
        await db.execute(
            "INSERT OR IGNORE INTO replay_meta (key, value) VALUES ('created_at', ?)",
            (repr(self._clock()),),
        )
        await db.commit()
        async with db.execute(
            "SELECT value FROM replay_meta WHERE key = 'created_at'"
        ) as cur:
            self._created_at = float((await cur.fetchone())[0])

    async def _purge(self) -> None:
        now = self._clock()
        await self._db.execute(
            "DELETE FROM seen_envelopes WHERE seen_at < ?", (now - RETENTION_SECONDS,)
        )
        await self._db.commit()
        async with self._db.execute("SELECT COUNT(*) FROM seen_envelopes") as cur:
            self._count = (await cur.fetchone())[0]
        self._last_purge = now

    async def seen_or_record(
        self, from_address: str, message_id: str, *, signed_at: float
    ) -> bool:
        """Return True if the envelope must be dropped as a replay.

        Otherwise record the pair and return False.  ``signed_at`` is the
        envelope's signed timestamp (seconds since the epoch); it matters
        only when the cache is full.
        """
        db = await self._ensure_open()
        now = self._clock()
        if now - self._last_purge >= _PURGE_INTERVAL:
            await self._purge()

        # Before the file: a purge can free room while an id is held here.
        if await self._overflow.has(from_address, message_id):
            return True

        if self._count < self._capacity:
            cur = await db.execute(
                "INSERT OR IGNORE INTO seen_envelopes (from_address, message_id, seen_at) "
                "VALUES (?, ?, ?)",
                (from_address, message_id, now),
            )
            await db.commit()
            if cur.rowcount == 1:
                self._count += 1
                return False
            return True

        # Full: never evict inside the window.  Known pairs are replays,
        # fresh envelopes are deduplicated in memory, older ones refused.
        async with db.execute(
            "SELECT 1 FROM seen_envelopes WHERE from_address = ? AND message_id = ?",
            (from_address, message_id),
        ) as cur:
            if await cur.fetchone() is not None:
                return True
        if abs(now - signed_at) <= MAX_ENVELOPE_AGE:
            return await self._overflow.seen_or_record(from_address, message_id)
        logger.warning(
            "Replay cache full (%d ids); refused envelope %s from %s signed %ds ago",
            self._count,
            message_id,
            from_address,
            int(now - signed_at),
        )
        return True

    async def created_at(self) -> float:
        """When this cache file was first created (seconds since the epoch)."""
        await self._ensure_open()
        return self._created_at

    async def signed_before_cache(self, signed_at: float) -> bool:
        """True if an envelope signed at ``signed_at`` predates this cache."""
        return signed_at < await self.created_at()

    async def count(self) -> int:
        """Number of ids currently held on disk."""
        db = await self._ensure_open()
        async with db.execute("SELECT COUNT(*) FROM seen_envelopes") as cur:
            return (await cur.fetchone())[0]

    async def close(self) -> None:
        """Close the file; the next call opens it again."""
        if self._db is not None:
            await self._db.close()
            self._db = None
