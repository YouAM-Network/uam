"""Tests for WebhookDelivery CRUD operations."""

from __future__ import annotations

from uam.db.crud.webhooks import (
    complete_delivery,
    create_delivery,
    record_attempt,
)


async def test_create_delivery(session):
    d = await create_delivery(
        session,
        agent_address="alice::youam.network",
        message_id="msg-001",
        envelope='{"encrypted": "data"}',
    )
    assert d.status == "pending"
    assert d.agent_address == "alice::youam.network"
    assert d.message_id == "msg-001"
    assert d.attempt_count == 0
    assert d.completed_at is None


async def test_record_attempt(session):
    d = await create_delivery(
        session,
        agent_address="alice::youam.network",
        message_id="msg-001",
        envelope='{"encrypted": "data"}',
    )
    updated = await record_attempt(session, d.id, status_code=502, error="Bad Gateway")
    assert updated is not None
    assert updated.attempt_count == 1
    assert updated.last_status_code == 502
    assert updated.last_error == "Bad Gateway"
    assert updated.status == "in_progress"


async def test_complete_delivery_succeeded(session):
    d = await create_delivery(
        session,
        agent_address="alice::youam.network",
        message_id="msg-001",
        envelope='{"encrypted": "data"}',
    )
    completed = await complete_delivery(session, d.id, status="succeeded")
    assert completed is not None
    assert completed.status == "succeeded"
    assert completed.completed_at is not None
    assert completed.last_error is None


async def test_complete_delivery_failed(session):
    d = await create_delivery(
        session,
        agent_address="alice::youam.network",
        message_id="msg-001",
        envelope='{"encrypted": "data"}',
    )
    completed = await complete_delivery(
        session, d.id, status="failed", error="Max retries exceeded"
    )
    assert completed is not None
    assert completed.status == "failed"
    assert completed.completed_at is not None
    assert completed.last_error == "Max retries exceeded"


# ---------------------------------------------------------------------------
# Phase 44 Wave 0 — failing-by-design concurrency test (T4.7)
# ---------------------------------------------------------------------------


import asyncio  # noqa: E402

import pytest  # noqa: E402


@pytest.mark.asyncio
async def test_concurrent_state_transitions(session_factory, monkeypatch):
    """T4.7: concurrent ``record_attempt`` + ``complete_delivery`` on one
    delivery row → state machine transitions exactly once per row, no lost
    updates on ``attempt_count``.

    Today (Wave 0): both record_attempt and complete_delivery are
    SELECT → mutate → commit. Concurrent calls overwrite each other —
    in particular, ``attempt_count += 1`` is racy across N record_attempt
    calls; and a complete_delivery commit can be silently overwritten by
    a concurrent record_attempt that already had a stale row in memory.

    Plan 44-05 contract:
      - record_attempt uses ``UPDATE WebhookDelivery SET
          attempt_count = attempt_count + 1, last_status_code = ?,
          last_error = ?, status = 'in_progress'
        WHERE id = ?`` — increment in SQL is atomic
      - complete_delivery uses ``UPDATE ... WHERE id=? AND status IN
        ('pending', 'in_progress')`` so a completed row cannot be
        re-completed by a stale concurrent caller
    """
    from tests._concurrency_helpers import inject_sleep_after

    # Force the SELECT/UPDATE race window in record_attempt.
    # Both record_attempt and complete_delivery do their own session.execute
    # for the SELECT; we can't easily inject between them. Instead inject on
    # the public CRUD API that's used during setup so both concurrent calls
    # have time to enter their critical sections before either commits.
    # The simplest race trigger: gather many record_attempt calls with no
    # sleep — the asyncio scheduler interleaves them naturally.

    from uam.db.crud.webhooks import (
        complete_delivery,
        create_delivery,
        record_attempt,
    )

    # Setup: one pending delivery row.
    async with session_factory() as session:
        d = await create_delivery(
            session,
            agent_address="alice::test.local",
            message_id="msg-concurrent-001",
            envelope='{"encrypted": "data"}',
        )
        delivery_id = d.id

    n_attempts = 20

    async def attempt():
        async with session_factory() as session:
            try:
                await record_attempt(
                    session, delivery_id, status_code=502, error="retry"
                )
            except Exception:
                pass

    await asyncio.gather(*[attempt() for _ in range(n_attempts)])

    # Now read back attempt_count — it MUST equal n_attempts (no lost
    # increments from the SELECT-then-write race).
    async with session_factory() as session:
        from sqlmodel import select
        from uam.db.models import WebhookDelivery

        result = await session.execute(
            select(WebhookDelivery).where(WebhookDelivery.id == delivery_id)
        )
        delivery = result.scalar_one()
        assert delivery.attempt_count == n_attempts, (
            f"T4.7: lost updates on attempt_count — expected {n_attempts}, "
            f"got {delivery.attempt_count}. The SELECT-mutate-UPDATE pattern "
            f"in record_attempt races: multiple coroutines read N, all write "
            f"N+1. Plan 44-05 must collapse to `UPDATE ... SET attempt_count "
            f"= attempt_count + 1, status = 'in_progress' WHERE id = ?`."
        )
