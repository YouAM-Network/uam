"""Tests for Reputation CRUD operations."""

from __future__ import annotations

from uam.db.crud.reputation import (
    get_reputation,
    init_reputation,
    record_rejected,
    record_sent,
    set_score,
    update_score,
)


async def test_init_reputation(session):
    rep = await init_reputation(session, "alice::youam.network")
    assert rep.address == "alice::youam.network"
    assert rep.score == 30  # default
    assert rep.messages_sent == 0
    assert rep.messages_rejected == 0


async def test_init_idempotent(session):
    rep1 = await init_reputation(session, "alice::youam.network", score=30)
    rep2 = await init_reputation(session, "alice::youam.network", score=99)
    # Second call should return existing, not create new with score=99
    assert rep2.address == rep1.address
    assert rep2.score == 30  # original score preserved


async def test_update_score_positive(session):
    await init_reputation(session, "alice::youam.network", score=30)
    updated = await update_score(session, "alice::youam.network", delta=20)
    assert updated is not None
    assert updated.score == 50


async def test_update_score_clamp_max(session):
    await init_reputation(session, "alice::youam.network", score=90)
    updated = await update_score(session, "alice::youam.network", delta=50)
    assert updated is not None
    assert updated.score == 100  # clamped at 100


async def test_update_score_clamp_min(session):
    await init_reputation(session, "alice::youam.network", score=10)
    updated = await update_score(session, "alice::youam.network", delta=-50)
    assert updated is not None
    assert updated.score == 0  # clamped at 0


async def test_set_score(session):
    await init_reputation(session, "alice::youam.network", score=30)
    updated = await set_score(session, "alice::youam.network", 75)
    assert updated is not None
    assert updated.score == 75


async def test_record_sent(session):
    rep = await record_sent(session, "alice::youam.network")
    assert rep is not None
    assert rep.messages_sent == 1
    # Call again
    rep2 = await record_sent(session, "alice::youam.network")
    assert rep2.messages_sent == 2


async def test_record_rejected(session):
    rep = await record_rejected(session, "alice::youam.network")
    assert rep is not None
    assert rep.messages_rejected == 1
    # Call again
    rep2 = await record_rejected(session, "alice::youam.network")
    assert rep2.messages_rejected == 2
