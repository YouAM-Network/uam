"""Tests for Federation CRUD operations."""

from __future__ import annotations

from uam.db.crud.federation import (
    add_relay_blocklist,
    enqueue_federation,
    get_known_relay,
    get_pending_queue,
    is_relay_blocked,
    log_federation,
    record_relay_failure,
    record_relay_success,
    remove_relay_blocklist,
    upsert_known_relay,
)


# ---------------------------------------------------------------------------
# Known Relays
# ---------------------------------------------------------------------------


async def test_upsert_known_relay_new(session):
    relay = await upsert_known_relay(
        session,
        domain="relay.youam.network",
        federation_url="https://relay.youam.network/federation",
        public_key="pk_relay",
    )
    assert relay.domain == "relay.youam.network"
    assert relay.federation_url == "https://relay.youam.network/federation"
    assert relay.public_key == "pk_relay"
    assert relay.status == "active"


async def test_upsert_known_relay_update(session):
    await upsert_known_relay(
        session,
        domain="relay.youam.network",
        federation_url="https://old.url/federation",
        public_key="pk_old",
    )
    updated = await upsert_known_relay(
        session,
        domain="relay.youam.network",
        federation_url="https://new.url/federation",
        public_key="pk_new",
    )
    assert updated.federation_url == "https://new.url/federation"
    assert updated.public_key == "pk_new"


async def test_get_known_relay(session):
    await upsert_known_relay(
        session,
        domain="relay.youam.network",
        federation_url="https://relay.youam.network/federation",
        public_key="pk_relay",
    )
    found = await get_known_relay(session, "relay.youam.network")
    assert found is not None
    assert found.domain == "relay.youam.network"

    missing = await get_known_relay(session, "nonexistent.network")
    assert missing is None


# ---------------------------------------------------------------------------
# Federation Log
# ---------------------------------------------------------------------------


async def test_log_federation(session):
    entry = await log_federation(
        session,
        message_id="msg-001",
        from_relay="relay-a.network",
        to_relay="relay-b.network",
        direction="outbound",
        hop_count=1,
        status="delivered",
    )
    assert entry.message_id == "msg-001"
    assert entry.from_relay == "relay-a.network"
    assert entry.to_relay == "relay-b.network"
    assert entry.direction == "outbound"
    assert entry.hop_count == 1
    assert entry.status == "delivered"
    assert entry.created_at is not None


# ---------------------------------------------------------------------------
# Federation Queue
# ---------------------------------------------------------------------------


async def test_enqueue_and_get_pending(session):
    entry = await enqueue_federation(
        session,
        target_domain="remote.network",
        envelope='{"encrypted": "data"}',
    )
    assert entry.status == "pending"
    assert entry.target_domain == "remote.network"

    pending = await get_pending_queue(session)
    assert len(pending) == 1
    assert pending[0].id == entry.id


# ---------------------------------------------------------------------------
# Relay Blocklist
# ---------------------------------------------------------------------------


async def test_relay_blocklist_add_check(session):
    await add_relay_blocklist(session, "evil.network", reason="spam")
    assert await is_relay_blocked(session, "evil.network") is True
    assert await is_relay_blocked(session, "good.network") is False


async def test_relay_blocklist_remove(session):
    await add_relay_blocklist(session, "evil.network", reason="spam")
    removed = await remove_relay_blocklist(session, "evil.network")
    assert removed is True
    assert await is_relay_blocked(session, "evil.network") is False


# ---------------------------------------------------------------------------
# Relay Reputation
# ---------------------------------------------------------------------------


async def test_relay_reputation_success_failure(session):
    # Record success (+1 from default 50)
    rep = await record_relay_success(session, "relay.youam.network")
    assert rep.score == 51
    assert rep.messages_forwarded == 1
    assert rep.last_success is not None

    # Record failure (-5)
    rep2 = await record_relay_failure(session, "relay.youam.network")
    assert rep2.score == 46
    assert rep2.messages_rejected == 1
    assert rep2.last_failure is not None


# ---------------------------------------------------------------------------
# Phase 44 Wave 0 — failing-by-design concurrency tests (T4.7)
# ---------------------------------------------------------------------------


import asyncio  # noqa: E402 — local import keeps Phase 44 additions visually grouped

import pytest  # noqa: E402

from uam.db.crud.federation import (  # noqa: E402
    enqueue_federation as _enqueue_federation,
    get_pending_queue as _get_pending_queue,
    update_queue_entry as _update_queue_entry,
    record_relay_success as _record_relay_success,
)


@pytest.mark.asyncio
async def test_concurrent_queue_update_atomic(session_factory, monkeypatch):
    """T4.7: 10 concurrent ``update_queue_entry`` calls on one entry
    transitioning pending→in_progress → exactly one wins; losers return None.

    Today (Wave 0): update_queue_entry is SELECT → mutate → commit (no
    pre-state WHERE filter). Two concurrent workers can both pick up the
    same pending row and both flip it to 'in_progress'. The second wins
    silently.

    Plan 44-05 contract:
      - update_queue_entry uses ``UPDATE ... WHERE id=? AND status='pending'
        ... RETURNING *`` (or rowcount==1) so the second writer's WHERE
        clause matches no rows and the call returns None.
    """
    from tests._concurrency_helpers import inject_sleep_after

    # The bug is in the SELECT-then-mutate pattern. update_queue_entry
    # internally does `result = await session.execute(stmt)` then mutates
    # the entry. We can't sleep on a CRUD-internal SELECT directly, so we
    # use the public `get_pending_queue` route as a proxy by injecting on
    # the most relevant SUT — the bug surface is the gap between the row
    # fetch and the commit, which is observable across N concurrent
    # update_queue_entry calls without sleep injection on a slow box. To
    # keep the test deterministic we sleep on session.execute via a thin
    # wrapper... but that's invasive. Simpler: rely on asyncio.gather's
    # natural interleaving and a generous attempt count, then let the
    # atomic-UPDATE fix in Plan 44-05 be the one to make this pass.

    # Setup: one pending queue entry.
    async with session_factory() as session:
        entry = await _enqueue_federation(
            session,
            target_domain="remote.network",
            envelope='{"encrypted": "data"}',
        )
        entry_id = entry.id

    async def attempt():
        async with session_factory() as session:
            try:
                return await _update_queue_entry(
                    session, entry_id, status="in_progress"
                )
            except Exception:
                return None

    # 10 concurrent transitions — exactly one should win.
    results = await asyncio.gather(
        *[attempt() for _ in range(10)], return_exceptions=True
    )
    winners = [
        r
        for r in results
        if r is not None
        and not isinstance(r, BaseException)
        # The bug today: every caller gets a non-None entry back even when
        # the underlying row was already mutated by another writer.
        # The fix's contract: only the caller whose UPDATE matched a row
        # gets a non-None response.
    ]

    assert len(winners) == 1, (
        f"T4.7: expected exactly 1 winner from 10 concurrent "
        f"update_queue_entry(pending→in_progress) calls, got "
        f"{len(winners)}. The SELECT-then-mutate pattern silently "
        f"overwrites — multiple workers all pick up the same pending row. "
        f"Plan 44-05 must use `UPDATE ... WHERE id=? AND status='pending' "
        f"RETURNING *` so the loser observes no row and returns None."
    )


@pytest.mark.asyncio
async def test_concurrent_relay_reputation_no_lost_updates(
    session_factory, monkeypatch
):
    """T4.7 H2: 50 concurrent ``record_relay_success`` calls →
    ``messages_forwarded`` reflects every increment (no lost updates).

    Today (Wave 0): record_relay_success reads via upsert_relay_reputation,
    increments in Python, commits. Concurrent calls overwrite each other.

    Plan 44-05: ``UPDATE RelayReputation SET messages_forwarded =
    messages_forwarded + 1, score = MIN(100, score + 1) WHERE domain = ?``.
    """
    from tests._concurrency_helpers import inject_sleep_after

    inject_sleep_after(
        monkeypatch,
        "uam.db.crud.federation.upsert_relay_reputation",
        sleep_ms=5,
    )

    domain = "relay.youam.network"
    # Pre-init the reputation row so we don't race on the upsert.
    async with session_factory() as session:
        await _record_relay_success(session, domain)

    async def attempt():
        async with session_factory() as session:
            try:
                await _record_relay_success(session, domain)
            except Exception:
                pass

    await asyncio.gather(*[attempt() for _ in range(50)])

    async with session_factory() as session:
        from uam.db.crud.federation import get_relay_reputation

        rep = await get_relay_reputation(session, domain)
        assert rep is not None
        # Pre-init=1, +50 increments = 51.
        assert rep.messages_forwarded == 51, (
            f"T4.7 H2: lost updates — expected messages_forwarded=51 "
            f"(1 pre-init + 50 increments), got {rep.messages_forwarded}. "
            f"Plan 44-05 must collapse to `UPDATE ... SET "
            f"messages_forwarded = messages_forwarded + 1 WHERE domain = ?`."
        )
