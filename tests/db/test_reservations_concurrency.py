"""Phase 44 Wave 0 — failing-by-design concurrency tests for claim_reservation.

Covers:
  T4.4  CLAIM-RESERVATION-ATOMIC  — exactly one winner from N concurrent claims
  T4.4  CLAIM-EXPIRY-RACE         — never claim a row past its expires_at

Today (Wave 0): ``claim_reservation`` is SELECT-then-UPDATE without
serialization (src/uam/db/crud/reservations.py:128-154):

    reservation = await get_reservation_by_token(session, claim_token)
    if reservation is None: return None
    now = datetime.utcnow()
    if reservation.status != "reserved" or reservation.expires_at <= now:
        return None
    reservation.status = "claimed"
    reservation.claimed_at = now
    ...
    await session.commit()

Two concurrent claims on the same token can BOTH read status='reserved'
between the SELECT and the UPDATE — and both observe success.

After Plan 44-03 (atomic UPDATE … WHERE pre-state … RETURNING):
exactly one winner; the rest get None. The sleep-injection helper
forces the race window open so the bug reliably exhibits even on a
fast in-memory SQLite test fixture.

NEW FILE created by Plan 44-00.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta

import pytest

from uam.db.crud.reservations import claim_reservation, create_reservation


# ---------------------------------------------------------------------------
# T4.4 CLAIM-RESERVATION-ATOMIC: exactly one winner under N concurrent claims
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_claim_one_winner(session_factory, monkeypatch):
    """T4.4: 50 concurrent ``claim_reservation`` calls on one token →
    exactly 1 winner, 49 None.

    Plan 44-03 contract:
      - claim_reservation collapses to one atomic SQL statement:
          UPDATE reservations
             SET status='claimed', claimed_at=now
           WHERE claim_token=? AND status='reserved' AND expires_at>now
        RETURNING *
      - SQL UPDATE is serialized at the database layer → exactly one row
        flips from 'reserved' to 'claimed'; the rest see no rows match
        and return None

    Today (Wave 0) the SELECT-then-UPDATE pattern races: multiple
    coroutines can both read ``status='reserved'`` between the SELECT
    and the UPDATE. Per RESEARCH Pitfall 4 we inject a sleep AFTER
    ``get_reservation_by_token`` so the race window is FORCED open
    regardless of machine speed.
    """
    from tests._concurrency_helpers import inject_sleep_after

    # Force a 10ms gap between SELECT and UPDATE inside claim_reservation.
    # The bug is that two coroutines can both pass the status check before
    # either commits the UPDATE. Sleep injection guarantees the window opens.
    inject_sleep_after(
        monkeypatch,
        "uam.db.crud.reservations.get_reservation_by_token",
        sleep_ms=10,
    )

    # Setup: one reserved row.
    async with session_factory() as session:
        await create_reservation(
            session,
            address="alice::test.local",
            claim_token="t-12345",
            ip_address="1.1.1.1",
            expires_at=datetime.utcnow() + timedelta(hours=1),
        )

    async def attempt():
        async with session_factory() as session:
            return await claim_reservation(session, "t-12345")

    # Fire 50 concurrent claims on the same token.
    results = await asyncio.gather(
        *[attempt() for _ in range(50)], return_exceptions=True
    )
    successes = [
        r for r in results if r is not None and not isinstance(r, BaseException)
    ]

    assert len(successes) == 1, (
        f"T4.4: expected exactly 1 winner from 50 concurrent claims, got "
        f"{len(successes)}. Multiple coroutines observed status='reserved' "
        f"between SELECT and UPDATE — the read-modify-write needs to be "
        f"collapsed into a single atomic UPDATE … WHERE pre-state … RETURNING."
    )
    # All winners must report claimed status.
    assert successes[0].status == "claimed"


# ---------------------------------------------------------------------------
# T4.4 CLAIM-EXPIRY-RACE: never claim past expires_at
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_claim_reservation_rejects_expired_atomically(
    session_factory, monkeypatch
):
    """T4.4: Concurrent claims that span the expiry boundary must NEVER
    produce a winner whose ``claimed_at > expires_at``.

    Setup: reservation expires 50ms from now. Spawn 10 attempts spaced
    across 100ms via ``asyncio.sleep(i*0.01)``. Some happen before
    expiry, some after.

    Today (Wave 0): the Python-side check
        ``if reservation.expires_at <= now: return None``
    runs against the SELECTed row's ``expires_at``. A coroutine can
    pass the check, then sleep on commit, and successfully write
    ``claimed_at = <now-after-expiry>``. The atomic UPDATE in Plan 44-03
    folds the expiry check into the WHERE clause — the database refuses
    to update a row whose expires_at has passed.

    Assertion: of all winners (if any), every winner's claimed_at
    must be ≤ its expires_at. (The reservation is also created with a
    near-future expiry so SOME attempts may succeed before expiry —
    that's fine; the assertion is about the post-expiry attempts.)
    """
    from tests._concurrency_helpers import inject_sleep_after

    # Force a sleep AFTER the SELECT so coroutines parked in the sleep
    # observe a stale `expires_at` while the wall clock advances past it.
    inject_sleep_after(
        monkeypatch,
        "uam.db.crud.reservations.get_reservation_by_token",
        sleep_ms=80,  # > 50ms expiry → guaranteed post-expiry commits
    )

    expiry = datetime.utcnow() + timedelta(milliseconds=50)
    async with session_factory() as session:
        await create_reservation(
            session,
            address="bob::test.local",
            claim_token="t-expiry",
            ip_address="2.2.2.2",
            expires_at=expiry,
        )

    async def attempt(i: int):
        await asyncio.sleep(i * 0.01)  # spread over 100ms
        async with session_factory() as session:
            return await claim_reservation(session, "t-expiry")

    results = await asyncio.gather(
        *[attempt(i) for i in range(10)], return_exceptions=True
    )
    winners = [
        r for r in results if r is not None and not isinstance(r, BaseException)
    ]

    # Every winner — if any — must have claimed_at ≤ expires_at. The atomic
    # UPDATE … WHERE expires_at > now in the fix guarantees this; the
    # SELECT-then-UPDATE bug today can violate it.
    for w in winners:
        assert w.claimed_at is not None, (
            "T4.4: winner has no claimed_at — claim should have set it"
        )
        assert w.claimed_at <= w.expires_at, (
            f"T4.4 expiry race: claimed_at={w.claimed_at} > "
            f"expires_at={w.expires_at}. The Python-side expiry check ran "
            f"against a stale SELECTed row; the atomic UPDATE in Plan 44-03 "
            f"folds the check into the SQL WHERE clause."
        )
