"""PersistentReplayCache: inbound (sender, message id) pairs kept on disk.

Stored mail can reach an agent days after it was sent, so the replay cache
has to outlive the process and hold ids for the whole window an envelope
can be accepted in.  These tests pin what the cache promises:

* a pair seen once is a replay the second time, across instances and
  processes sharing the file;
* nothing is evicted inside the retention window;
* when full it fails closed: only envelopes signed within MAX_ENVELOPE_AGE
  are still accepted (and deduplicated in memory);
* it knows when it was created, so older stored mail can be refused.
"""

from __future__ import annotations

import asyncio
import multiprocessing
import sqlite3
import threading
import time
from unittest.mock import patch

import pytest

from uam.protocol.types import MAX_ENVELOPE_AGE
from uam.sdk.replay_cache import RETENTION_SECONDS, PersistentReplayCache

ALICE = "alice::test.local"


def _path(tmp_path):
    return tmp_path / "replay" / "replay.db"


async def test_first_sighting_is_new_second_is_replay(tmp_path):
    cache = PersistentReplayCache(_path(tmp_path))
    try:
        now = time.time()
        assert await cache.seen_or_record(ALICE, "m1", signed_at=now) is False
        assert await cache.seen_or_record(ALICE, "m1", signed_at=now) is True
        assert await cache.seen_or_record("carol::test.local", "m1", signed_at=now) is False
    finally:
        await cache.close()


async def test_replay_survives_a_new_instance(tmp_path):
    first = PersistentReplayCache(_path(tmp_path))
    await first.seen_or_record(ALICE, "m1", signed_at=time.time())
    await first.close()

    second = PersistentReplayCache(_path(tmp_path))
    try:
        assert await second.seen_or_record(ALICE, "m1", signed_at=time.time()) is True
    finally:
        await second.close()


def _record_in_child(path: str, message_id: str, out) -> None:
    async def run() -> bool:
        cache = PersistentReplayCache(path)
        try:
            return await cache.seen_or_record(ALICE, message_id, signed_at=time.time())
        finally:
            await cache.close()

    out.put(asyncio.run(run()))


def test_two_processes_see_one_new_and_one_replay(tmp_path):
    path = str(_path(tmp_path))
    ctx = multiprocessing.get_context("spawn")
    out = ctx.Queue()
    procs = [ctx.Process(target=_record_in_child, args=(path, "m1", out)) for _ in range(2)]
    for p in procs:
        p.start()
    try:
        results = sorted(out.get(timeout=30) for _ in procs)
    finally:
        for p in procs:
            p.join(5)
            p.kill()
    assert results == [False, True]


async def test_a_failed_open_leaves_no_thread_behind(tmp_path):
    cache = PersistentReplayCache(_path(tmp_path))
    before = threading.active_count()

    with patch("uam.sdk.replay_cache._enable_wal", side_effect=sqlite3.OperationalError("locked")):
        with pytest.raises(sqlite3.OperationalError):
            await cache.seen_or_record(ALICE, "m1", signed_at=time.time())

    assert threading.active_count() == before


async def test_ids_are_kept_for_the_whole_retention_window(tmp_path):
    clock = [1_000_000.0]
    cache = PersistentReplayCache(_path(tmp_path), clock=lambda: clock[0])
    try:
        await cache.seen_or_record(ALICE, "m1", signed_at=clock[0])
        clock[0] += RETENTION_SECONDS - 1
        assert await cache.seen_or_record(ALICE, "m1", signed_at=clock[0]) is True
    finally:
        await cache.close()


async def test_ids_past_retention_are_purged(tmp_path):
    clock = [1_000_000.0]
    cache = PersistentReplayCache(_path(tmp_path), clock=lambda: clock[0])
    try:
        await cache.seen_or_record(ALICE, "old", signed_at=clock[0])
        clock[0] += RETENTION_SECONDS + 1
        await cache.seen_or_record(ALICE, "new", signed_at=clock[0])
        assert await cache.count() == 1
    finally:
        await cache.close()


def test_retention_covers_seven_days_and_both_clock_windows():
    assert RETENTION_SECONDS >= 7 * 86400 + 2 * MAX_ENVELOPE_AGE


async def test_full_cache_never_evicts_and_accepts_only_fresh(tmp_path):
    clock = [1_000_000.0]
    cache = PersistentReplayCache(_path(tmp_path), capacity=2, clock=lambda: clock[0])
    try:
        await cache.seen_or_record(ALICE, "m1", signed_at=clock[0])
        await cache.seen_or_record(ALICE, "m2", signed_at=clock[0])

        # Full: an old (stored) envelope is refused rather than evicting.
        old = clock[0] - (MAX_ENVELOPE_AGE + 60)
        assert await cache.seen_or_record(ALICE, "m3", signed_at=old) is True
        # The recorded ids are still there.
        assert await cache.seen_or_record(ALICE, "m1", signed_at=clock[0]) is True

        # A fresh envelope is accepted once, and its repeat is still caught.
        assert await cache.seen_or_record(ALICE, "m4", signed_at=clock[0]) is False
        assert await cache.seen_or_record(ALICE, "m4", signed_at=clock[0]) is True
        assert await cache.count() == 2
    finally:
        await cache.close()


async def test_created_at_is_kept_across_instances(tmp_path):
    clock = [1_000_000.0]
    first = PersistentReplayCache(_path(tmp_path), clock=lambda: clock[0])
    created = await first.created_at()
    await first.close()

    clock[0] += 3600
    second = PersistentReplayCache(_path(tmp_path), clock=lambda: clock[0])
    try:
        assert await second.created_at() == created == 1_000_000.0
        assert await second.signed_before_cache(created - 1) is True
        assert await second.signed_before_cache(created + 1) is False
    finally:
        await second.close()


async def test_opens_lazily_and_creates_its_directory(tmp_path):
    path = _path(tmp_path)
    cache = PersistentReplayCache(path)
    assert not path.exists()
    try:
        await cache.seen_or_record(ALICE, "m1", signed_at=time.time())
        assert path.exists()
    finally:
        await cache.close()


async def test_close_is_idempotent(tmp_path):
    cache = PersistentReplayCache(_path(tmp_path))
    await cache.close()
    await cache.seen_or_record(ALICE, "m1", signed_at=time.time())
    await cache.close()
    await cache.close()


@pytest.mark.parametrize("capacity", [0, -1])
def test_capacity_must_be_positive(tmp_path, capacity):
    with pytest.raises(ValueError):
        PersistentReplayCache(_path(tmp_path), capacity=capacity)


async def test_a_repeat_stays_a_replay_for_as_long_as_it_could_be_accepted(tmp_path):
    """Signed MAX_ENVELOPE_AGE ahead, an envelope stays acceptable for twice that."""
    now = [time.time()]
    cache = PersistentReplayCache(_path(tmp_path), capacity=1, clock=lambda: now[0])
    try:
        assert await cache.seen_or_record(ALICE, "fills", signed_at=now[0]) is False
        signed_at = now[0] + MAX_ENVELOPE_AGE
        assert await cache.seen_or_record(ALICE, "m", signed_at=signed_at) is False
        with patch("uam.sdk.replay_cache.time.monotonic", return_value=time.monotonic() + 400):
            now[0] += 400
            assert await cache.seen_or_record(ALICE, "m", signed_at=signed_at) is True
    finally:
        await cache.close()


async def test_a_repeat_seen_while_full_is_a_replay_after_room_frees_up(tmp_path):
    now = [time.time()]
    cache = PersistentReplayCache(_path(tmp_path), capacity=1, clock=lambda: now[0])
    try:
        assert await cache.seen_or_record(ALICE, "old", signed_at=now[0]) is False
        now[0] += RETENTION_SECONDS - 1
        assert await cache.seen_or_record(ALICE, "m", signed_at=now[0]) is False
        now[0] += 61  # "old" has expired and a purge is due
        assert await cache.seen_or_record(ALICE, "m", signed_at=now[0]) is True
    finally:
        await cache.close()
