"""Phase 44 Wave 0 — failing-by-design concurrency tests for reputation CRUD.

Covers:
  T4.7 H1   REPUTATION-COUNTER  — record_sent counters are exact under N concurrent calls
  T4.7 H6   REPUTATION-SCORE    — update_score(delta) is lossless under concurrency

Today (Wave 0):
  - ``record_sent``  : SELECT row → ``rep.messages_sent += 1`` in Python →
    UPDATE → commit.  Two concurrent calls can both read messages_sent=N,
    both write messages_sent=N+1, lose one increment.
  - ``update_score`` : same pattern — SELECT → ``rep.score = clamp(score+delta)``
    → UPDATE → commit. Two concurrent +1 calls land at score=N+1 instead
    of score=N+2.

Plan 44-05 contract (per RESEARCH Pattern 4):
  - record_sent collapses to ``UPDATE Reputation
        SET messages_sent = messages_sent + 1, updated_at = now
      WHERE address = ?``
    (arithmetic in SQL is atomic on Postgres + SQLite)
  - update_score uses the same arithmetic-in-SQL pattern with a SQL-level
    CLAMP via ``MIN(100, MAX(0, score + ?))``

NEW FILE created by Plan 44-00.
"""

from __future__ import annotations

import asyncio

import pytest

from uam.db.crud import reputation


# ---------------------------------------------------------------------------
# T4.7 H1 — REPUTATION-COUNTER: record_sent exact-count enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_record_sent_exact_count(session_factory, monkeypatch):
    """T4.7 H1: 100 concurrent ``record_sent`` calls →
    ``messages_sent == 100`` (no lost updates).

    Per RESEARCH Pitfall 4, force the SELECT/UPDATE race window open via
    sleep injection on ``get_reputation_with_default`` so the read-modify-
    write race is reliably exhibited even on a fast in-memory SQLite test
    fixture.

    Today (Wave 0): record_sent reads messages_sent into Python, increments
    in Python, writes back. Concurrent calls overwrite each other's writes.
    This test FAILS with ``messages_sent`` < 100.

    Plan 44-05 collapses to ``UPDATE … SET messages_sent = messages_sent + 1
    WHERE address = ?`` — arithmetic in SQL is atomic.
    """
    from tests._concurrency_helpers import inject_sleep_after

    # Force the gap between SELECT (in get_reputation_with_default) and the
    # subsequent UPDATE in record_sent. Sleep 5ms — enough to deterministically
    # open the race window without slowing the suite.
    inject_sleep_after(
        monkeypatch,
        "uam.db.crud.reputation.get_reputation_with_default",
        sleep_ms=5,
    )

    address = "alice::test.local"
    async with session_factory() as session:
        await reputation.init_reputation(session, address)

    async def attempt():
        async with session_factory() as session:
            await reputation.record_sent(session, address)

    await asyncio.gather(*[attempt() for _ in range(100)])

    async with session_factory() as session:
        rep = await reputation.get_reputation(session, address)
        assert rep is not None
        assert rep.messages_sent == 100, (
            f"T4.7 H1: lost updates — expected messages_sent=100, got "
            f"{rep.messages_sent}. The SELECT-then-write pattern in "
            f"record_sent races: multiple coroutines read N, all write N+1. "
            f"Plan 44-05 must collapse to `UPDATE ... SET messages_sent = "
            f"messages_sent + 1 WHERE address = ?` so the arithmetic happens "
            f"atomically in SQL."
        )


# ---------------------------------------------------------------------------
# T4.7 H6 — REPUTATION-SCORE: update_score lossless under concurrency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_update_score_no_lost_updates(
    session_factory, monkeypatch
):
    """T4.7 H6: 50 concurrent ``update_score(addr, +1)`` calls →
    final score reflects every increment (clamped to 100).

    With a baseline of 30 (init_reputation default) and 50 increments of +1,
    the expected final score is min(100, 30+50) = 80. With the lost-update
    bug today, the final score is < 80 (multiple coroutines all read N,
    all write N+1).

    Today (Wave 0): update_score is SELECT → ``rep.score = clamp(score+delta)``
    in Python → UPDATE → commit. The Python-side arithmetic races.

    Plan 44-05: ``UPDATE ... SET score = MIN(100, MAX(0, score + ?)) WHERE ...``
    — the clamp + arithmetic happen in SQL.
    """
    from tests._concurrency_helpers import inject_sleep_after

    # Force the SELECT/write race window in update_score. update_score uses
    # get_reputation (not get_reputation_with_default), so inject on that.
    inject_sleep_after(
        monkeypatch,
        "uam.db.crud.reputation.get_reputation",
        sleep_ms=5,
    )

    address = "bob::test.local"
    async with session_factory() as session:
        await reputation.init_reputation(session, address)
        rep = await reputation.get_reputation(session, address)
        assert rep is not None
        initial = rep.score  # default 30 per init_reputation
    expected_final = min(100, initial + 50)

    async def attempt():
        async with session_factory() as session:
            await reputation.update_score(session, address, 1)

    await asyncio.gather(*[attempt() for _ in range(50)])

    async with session_factory() as session:
        rep = await reputation.get_reputation(session, address)
        assert rep is not None
        assert rep.score == expected_final, (
            f"T4.7 H6: lost updates — expected score={expected_final} "
            f"(initial={initial}, +50 increments clamped at 100), got "
            f"{rep.score}. Plan 44-05 must use atomic UPDATE with arithmetic "
            f"in SQL: `UPDATE ... SET score = MIN(100, MAX(0, score + ?)) "
            f"WHERE address = ?`."
        )
