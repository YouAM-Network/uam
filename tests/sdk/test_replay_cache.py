"""T3.1 — EnvelopeReplayCache unit tests (Wave 0, failing-by-design).

These tests will RED until Plan 45-01 lands ``src/uam/sdk/replay_cache.py``
with an ``EnvelopeReplayCache`` class exposing:

  - ``__init__(capacity: int, ttl: int)``
  - ``async seen_or_record(from_address: str, message_id: str) -> bool``
      returns True if the (from, msg_id) pair was seen within TTL,
      False if it's new (and records it for future calls).

Per RESEARCH § Pattern 1 the cache is LRU-bounded + TTL-bounded so a
flood of fake addresses cannot exhaust memory and so a long-quiescent
contact whose message_id later collides with a fresh one isn't flagged
as a replay forever.
"""

from __future__ import annotations

import pytest


@pytest.mark.asyncio
async def test_seen_or_record_first_call_returns_false():
    """First time a (from, msg_id) is recorded, it's not a replay."""
    from uam.sdk.replay_cache import EnvelopeReplayCache  # type: ignore[import-not-found]
    cache = EnvelopeReplayCache(capacity=100, ttl=60)
    seen = await cache.seen_or_record("alice::test.local", "msg-1")
    assert seen is False


@pytest.mark.asyncio
async def test_seen_or_record_second_call_returns_true():
    """Second time a (from, msg_id) is recorded within TTL, it IS a replay."""
    from uam.sdk.replay_cache import EnvelopeReplayCache  # type: ignore[import-not-found]
    cache = EnvelopeReplayCache(capacity=100, ttl=60)
    await cache.seen_or_record("alice::test.local", "msg-1")
    seen = await cache.seen_or_record("alice::test.local", "msg-1")
    assert seen is True


@pytest.mark.asyncio
async def test_different_keys_independent():
    """Different (from, msg_id) pairs are independent."""
    from uam.sdk.replay_cache import EnvelopeReplayCache  # type: ignore[import-not-found]
    cache = EnvelopeReplayCache(capacity=100, ttl=60)
    await cache.seen_or_record("alice::test.local", "msg-1")
    seen = await cache.seen_or_record("bob::test.local", "msg-1")
    assert seen is False  # different sender
    seen = await cache.seen_or_record("alice::test.local", "msg-2")
    assert seen is False  # different message_id


@pytest.mark.asyncio
async def test_lru_eviction_at_capacity():
    """When capacity is exceeded, oldest entries are evicted (LRU).

    Plan 45-01 contract: cache holds at most ``capacity`` entries.  Pushing a
    fourth entry into a 3-slot cache evicts the oldest.  Re-recording the
    evicted key returns False (treated as new), and the freshest entry still
    flags as seen.
    """
    from uam.sdk.replay_cache import EnvelopeReplayCache  # type: ignore[import-not-found]
    cache = EnvelopeReplayCache(capacity=3, ttl=60)
    await cache.seen_or_record("a", "1")
    await cache.seen_or_record("a", "2")
    await cache.seen_or_record("a", "3")
    await cache.seen_or_record("a", "4")  # evicts ("a","1")
    # ("a","1") is gone — re-recording it should NOT be a replay
    seen = await cache.seen_or_record("a", "1")
    assert seen is False
    # ("a","4") just recorded — IS a replay
    seen = await cache.seen_or_record("a", "4")
    assert seen is True


@pytest.mark.asyncio
async def test_ttl_expiry(monkeypatch):
    """Entries older than TTL are treated as new (not replays).

    Plan 45-01 contract: the cache uses ``time.monotonic()`` for TTL math
    so monkeypatching it lets us advance time without sleeping.
    """
    from uam.sdk.replay_cache import EnvelopeReplayCache  # type: ignore[import-not-found]
    fake_time = [0.0]
    monkeypatch.setattr("time.monotonic", lambda: fake_time[0])
    cache = EnvelopeReplayCache(capacity=100, ttl=1)
    # Record at t=0
    await cache.seen_or_record("a", "1")
    # Advance past TTL
    fake_time[0] = 2.0
    seen = await cache.seen_or_record("a", "1")
    assert seen is False  # TTL expired → treated as new
