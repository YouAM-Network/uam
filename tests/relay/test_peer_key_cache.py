"""Unit tests for PeerKeyCache (T1.4).

The peer-key cache is the in-memory TTL-bounded store backing the federation
route's home-relay public-key resolution. These tests pin the TTL behaviour
so a future refactor cannot silently extend the blast-radius of a poisoned
cache entry.
"""

from __future__ import annotations

import time

import pytest

from uam.relay.peer_key_cache import PeerKeyCache


pytestmark = pytest.mark.asyncio


async def test_set_get_returns_value():
    """A freshly-set key returns its value."""
    c = PeerKeyCache()
    await c.set("alice::test.local", "key_b64", ttl=60)
    assert await c.get("alice::test.local") == "key_b64"


async def test_get_returns_none_on_miss():
    """An unset key returns None (NOT raising)."""
    c = PeerKeyCache()
    assert await c.get("never_set") is None


async def test_ttl_expiry(monkeypatch):
    """After TTL elapses, get() returns None and the entry is purged."""
    c = PeerKeyCache()
    await c.set("k", "v", ttl=1)
    # Fast-forward monotonic clock by 2 seconds
    real_monotonic = time.monotonic
    monkeypatch.setattr(
        "uam.relay.peer_key_cache.time.monotonic",
        lambda: real_monotonic() + 2,
    )
    assert await c.get("k") is None
    # And the expired entry is purged from the underlying dict.
    assert "k" not in c._data


async def test_invalidate():
    """Invalidate removes a key without waiting for TTL."""
    c = PeerKeyCache()
    await c.set("k", "v", ttl=300)
    await c.invalidate("k")
    assert await c.get("k") is None


async def test_invalidate_missing_key_is_noop():
    """Invalidating a key that was never set is a no-op (no KeyError)."""
    c = PeerKeyCache()
    # Should not raise
    await c.invalidate("never_set")
    assert await c.get("never_set") is None
