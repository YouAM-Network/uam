"""Phase 44 Wave 0 — failing-by-design concurrency test for respond_handshake.

Covers:
  T4.7 H11  HANDSHAKE-STATE  — respond_handshake exactly-once state transition

Today (Wave 0): respond_handshake reads the row via get_handshake_by_id,
mutates ``hs.status`` in Python, commits. Two concurrent calls (one
approve, one deny) can both:
  1. SELECT the row with status='pending'
  2. Mutate Python state to their respective new status
  3. UPDATE — the second commit silently overwrites the first

There's NO winner — both calls return a Handshake object claiming success,
but only one of the status values lands. This is the "silent overwrite"
defect.

Plan 44-05 contract:
  - respond_handshake collapses to ``UPDATE Handshake
        SET status = ?, resolved_at = now
      WHERE id = ? AND status = 'pending' AND deleted_at IS NULL
    RETURNING *``
  - The first caller wins (their UPDATE flips status to non-'pending');
    the loser's WHERE clause matches no rows; the loser's call returns None.

NEW FILE created by Plan 44-00.
"""

from __future__ import annotations

import asyncio

import pytest

from uam.db.crud.handshakes import create_handshake, respond_handshake


# ---------------------------------------------------------------------------
# T4.7 H11 — HANDSHAKE-STATE: exactly-one winner on concurrent respond
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_respond_one_winner(session_factory, monkeypatch):
    """T4.7 H11: concurrent ``respond_handshake(approve)`` +
    ``respond_handshake(deny)`` → exactly one wins; the loser returns None.

    Today (Wave 0): both callers read status='pending', both mutate the
    in-memory object to their respective new status, both commit. The
    second commit silently overwrites the first — there's no failure
    signal to the loser. The test asserts the SECURE behaviour: exactly
    one winner observed via return value, and the row's final status
    matches that winner's intended status (not last-writer-wins).

    Plan 44-05: atomic ``UPDATE Handshake SET status=?, resolved_at=now
    WHERE id=? AND status='pending' AND deleted_at IS NULL RETURNING *``.
    The first commit flips status away from 'pending'; the second's WHERE
    clause matches no rows and the call returns None.
    """
    from tests._concurrency_helpers import inject_sleep_after

    # Force the SELECT/UPDATE race window in respond_handshake. The bug is
    # in get_handshake_by_id → mutate → commit, so inject sleep AFTER the
    # SELECT so both coroutines hold a fetched row before either commits.
    inject_sleep_after(
        monkeypatch,
        "uam.db.crud.handshakes.get_handshake_by_id",
        sleep_ms=10,
    )

    # Setup: one pending handshake row.
    async with session_factory() as session:
        hs = await create_handshake(
            session,
            from_addr="alice::test.local",
            to_addr="bob::test.local",
            contact_card={"display_name": "Alice"},
        )
        hs_id = hs.id

    async def respond(status: str):
        async with session_factory() as session:
            try:
                return await respond_handshake(session, hs_id, status)
            except Exception:
                # Loser may raise (depending on DB error semantics) — treat
                # as None so the test still observes "exactly one winner".
                return None

    # Two concurrent conflicting responses on the same handshake.
    results = await asyncio.gather(
        respond("approved"),
        respond("denied"),
        return_exceptions=True,
    )
    winners = [
        r for r in results if r is not None and not isinstance(r, BaseException)
    ]

    assert len(winners) == 1, (
        f"T4.7 H11: expected exactly 1 winner from concurrent "
        f"respond_handshake(approve) + respond_handshake(deny), got "
        f"{len(winners)} (results={results!r}). The SELECT-mutate-UPDATE "
        f"pattern in respond_handshake silently overwrites — both callers "
        f"observe status='pending' and both report success. Plan 44-05 must "
        f"collapse to `UPDATE Handshake SET status=?, resolved_at=now "
        f"WHERE id=? AND status='pending' RETURNING *` so the loser's "
        f"WHERE clause matches no rows and the call returns None."
    )

    # The row's final status MUST match the (single) winner's intended status.
    winner = winners[0]
    async with session_factory() as session:
        from uam.db.crud.handshakes import get_handshake_by_id

        final = await get_handshake_by_id(session, hs_id)
        assert final is not None
        assert final.status == winner.status, (
            f"T4.7 H11: row's final status {final.status!r} does not match "
            f"the winner's reported status {winner.status!r}. This is "
            f"last-writer-wins — the loser silently overwrote the winner."
        )
