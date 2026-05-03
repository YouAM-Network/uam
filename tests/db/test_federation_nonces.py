"""T3.2 — federation_nonces CRUD failing-by-design tests (Wave 0).

Tests will RED until Plan 45-02 lands:
  - alembic migration that creates the ``federation_nonces`` table
  - ``src/uam/db/models.py`` ``FederationNonce`` SQLModel
  - ``src/uam/db/crud/federation_nonces.py`` with:
      * ``async record_nonce(session, from_relay, nonce) -> bool``
        returns True iff the row was newly inserted (per-relay scope),
        False if the (from_relay, nonce) pair already exists (replay).
      * ``async sweep_old_nonces(session, max_age_seconds) -> int``
        deletes nonces older than ``now - max_age_seconds`` and returns
        the deleted-row count.

Per RESEARCH § Pattern 2 the dedup key is the COMPOSITE (from_relay, nonce),
not the nonce alone — relay A and relay B may legitimately both emit the
same random 22-char string and neither is replaying the other.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest


@pytest.mark.asyncio
async def test_record_nonce_first_call_returns_true(session_factory):
    """First record of a (from_relay, nonce) pair returns True (new)."""
    from uam.db.crud.federation_nonces import record_nonce  # type: ignore[import-not-found]
    async with session_factory() as session:
        is_new = await record_nonce(session, "relay-a.test", "nonce-1")
    assert is_new is True


@pytest.mark.asyncio
async def test_record_nonce_replay_returns_false(session_factory):
    """Recording the same (from_relay, nonce) twice — second returns False."""
    from uam.db.crud.federation_nonces import record_nonce  # type: ignore[import-not-found]
    async with session_factory() as session:
        await record_nonce(session, "relay-a.test", "nonce-1")
    async with session_factory() as session:
        is_new = await record_nonce(session, "relay-a.test", "nonce-1")
    assert is_new is False, "second insert of the same (from_relay, nonce) is a replay"


@pytest.mark.asyncio
async def test_record_nonce_per_relay_scope(session_factory):
    """Different from_relay can use the same nonce string (per-relay scope).

    The dedup key is the COMPOSITE — relay-A using ``nonce-shared`` does NOT
    block relay-B from also using ``nonce-shared``.
    """
    from uam.db.crud.federation_nonces import record_nonce  # type: ignore[import-not-found]
    async with session_factory() as session:
        await record_nonce(session, "relay-a.test", "nonce-shared")
    async with session_factory() as session:
        is_new = await record_nonce(session, "relay-b.test", "nonce-shared")
    assert is_new is True, (
        "different from_relay using the same nonce must NOT be flagged as replay"
    )


@pytest.mark.asyncio
async def test_concurrent_record_atomic(session_factory):
    """20 concurrent record_nonce calls for the same key — exactly 1 returns True.

    Atomicity contract: the unique constraint on (from_relay, nonce) +
    INSERT-OR-IGNORE-style handling means exactly one caller wins, regardless
    of how many race in.  This mirrors the pattern in
    ``src/uam/db/crud/dedup.py::record_message_id``.
    """
    from uam.db.crud.federation_nonces import record_nonce  # type: ignore[import-not-found]

    async def attempt():
        async with session_factory() as session:
            return await record_nonce(session, "relay-a.test", "nonce-race")

    results = await asyncio.gather(
        *[attempt() for _ in range(20)], return_exceptions=True
    )
    wins = sum(1 for r in results if r is True)
    assert wins == 1, (
        f"expected exactly 1 winner under 20 concurrent inserts; got {wins}. "
        f"results={results}"
    )


@pytest.mark.asyncio
async def test_sweep_deletes_old(session_factory):
    """sweep_old_nonces deletes rows older than the cutoff.

    Plan 45-02 contract: the sweep loop runs periodically (e.g. every hour)
    and deletes rows whose ``seen_at`` is older than ``2 ×
    federation_timestamp_max_age``.  This test backdates a row and confirms
    the sweep removes it.
    """
    from uam.db.crud.federation_nonces import (  # type: ignore[import-not-found]
        record_nonce,
        sweep_old_nonces,
    )
    from uam.db.models import FederationNonce  # type: ignore[attr-defined]
    from sqlalchemy import select, update

    async with session_factory() as session:
        await record_nonce(session, "relay-a.test", "nonce-old")
        # Manually backdate seen_at
        await session.execute(
            update(FederationNonce)
            .where(FederationNonce.from_relay == "relay-a.test")
            .where(FederationNonce.nonce == "nonce-old")
            .values(seen_at=datetime.now(timezone.utc) - timedelta(seconds=1000))
        )
        await session.commit()

    async with session_factory() as session:
        deleted = await sweep_old_nonces(session, max_age_seconds=600)
    assert deleted >= 1, "sweep must delete the backdated row"

    async with session_factory() as session:
        remaining = (
            await session.execute(
                select(FederationNonce).where(FederationNonce.nonce == "nonce-old")
            )
        ).first()
    assert remaining is None, "backdated row must be gone after sweep"
