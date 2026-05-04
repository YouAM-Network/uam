"""Failing-by-design concurrency tests for ``ReputationManager`` (T6.4 Wave 0).

The current ``update_score`` and ``record_message_sent`` implementations do a
read-modify-write WITHOUT any DB-level row lock or per-address asyncio.Lock —
under ``asyncio.gather``, multiple tasks can read the same starting score, each
compute ``score + delta``, and each commit the same final value. Lost updates.

These tests RED at HEAD because the race is real. They GREEN after Plan 46-04
lands one of:
  - a ``with_for_update`` SELECT followed by UPDATE in the same transaction, OR
  - a per-address asyncio.Lock guarding the read-modify-write region, OR
  - a single SQL UPDATE expression that does the clamp in one statement
    (e.g. ``UPDATE ... SET score = MAX(0, MIN(100, score + :delta))``).

Anti-pattern guard (per 46-00-PLAN action notes):
  Concurrency tests MUST run with REAL atomic semantics — not Mock — because
  the bug only surfaces against a real concurrency surface (asyncio.gather +
  shared session_factory + actual SQL).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
from sqlmodel import select

from uam.db import engine as engine_module
from uam.db import session as session_module
from uam.db.crud.reputation import init_reputation
from uam.db.engine import init_engine
from uam.db.models import Reputation
from uam.db.session import create_tables, init_session_factory
from uam.relay.reputation import ReputationManager

ADDR = "race-victim::test.example.com"


@pytest.fixture
async def manager(tmp_path, monkeypatch) -> AsyncIterator[ReputationManager]:
    """Provision an isolated SQLite + ReputationManager seeded at score=50."""
    db_path = str(tmp_path / "test.db")
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("UAM_DB_PATH", db_path)

    # Reset singletons so this test gets a fresh engine/session factory.
    engine_module._engine = None
    session_module._session_factory = None

    eng = await init_engine()
    factory = await init_session_factory(eng)
    await create_tables(eng)

    # Phase 48-00 (inherited from 47-11): seed parent agent BEFORE
    # ``init_reputation`` runs. The Phase 47 alembic 0006 migration added a
    # FK from ``reputation.address`` to ``agents.address``; the autouse
    # ``_install_sqlite_fk_listener`` (tests/db/conftest.py) turns
    # PRAGMA foreign_keys=ON for SQLite so the FK actually fires. Without
    # this seed the reputation INSERT fails with IntegrityError.
    from sqlalchemy import text
    async with eng.begin() as conn:
        await conn.execute(text(
            "INSERT OR IGNORE INTO agents "
            "(address, public_key, token_hash, status, "
            " created_at, updated_at) "
            "VALUES (:addr, 'fixture-pk', :hsh, 'active', "
            "        datetime('now'), datetime('now'))"
        ), {"addr": ADDR, "hsh": f"fixture-hash-{ADDR}"})

    async with factory() as session:
        await init_reputation(session, ADDR, score=50)
        await session.commit()

    mgr = ReputationManager(factory)
    await mgr.load_cache()

    yield mgr

    # Reset singletons on teardown
    engine_module._engine = None
    session_module._session_factory = None


async def _read_score_db(factory, address: str) -> int:
    """Bypass the in-memory cache and read the persisted score directly."""
    async with factory() as session:
        result = await session.execute(
            select(Reputation.score).where(Reputation.address == address)
        )
        return int(result.scalar_one())


async def _read_messages_sent_db(factory, address: str) -> int:
    """Bypass cache; read messages_sent counter directly."""
    async with factory() as session:
        result = await session.execute(
            select(Reputation.messages_sent).where(Reputation.address == address)
        )
        return int(result.scalar_one())


async def test_concurrent_update_score_no_lost_updates(manager):
    """100 concurrent ``update_score(-1)`` calls -> final score must equal
    ``max(0, initial + 100 * delta)`` (clamped at 0).

    At HEAD: read-modify-write race causes most updates to be lost; final
    score lands well above the expected clamped value.
    """
    initial = 50
    delta = -1
    n_tasks = 100
    expected_final = max(0, initial + n_tasks * delta)  # = 0 (clamped)

    await asyncio.gather(*[manager.update_score(ADDR, delta) for _ in range(n_tasks)])

    final = await _read_score_db(manager._session_factory, ADDR)
    assert final == expected_final, (
        f"Lost updates: expected {expected_final}, got {final}. "
        f"Each of {n_tasks} concurrent update_score({delta}) calls should "
        f"have applied; today's read-modify-write loses most of them."
    )


async def test_concurrent_record_message_sent_exact_count(manager):
    """50 concurrent ``record_message_sent`` -> counter must equal exactly 50."""
    n = 50
    await asyncio.gather(*[manager.record_message_sent(ADDR) for _ in range(n)])

    counter = await _read_messages_sent_db(manager._session_factory, ADDR)
    assert counter == n, (
        f"Lost increments: expected {n}, got {counter}. "
        f"record_message_sent has the same read-modify-write race as update_score."
    )


async def test_concurrent_mixed_score_clamping(manager):
    """Mixed +1/-1 deltas under concurrency -> final score == sum of deltas
    (clamped to [0, 100]).

    deltas = 60 * +1 + 40 * -1 = net +20; from 50 -> 70.
    """
    deltas = [+1] * 60 + [-1] * 40
    expected = 70

    await asyncio.gather(*[manager.update_score(ADDR, d) for d in deltas])

    final = await _read_score_db(manager._session_factory, ADDR)
    assert final == expected, (
        f"Mixed-delta drift: expected {expected}, got {final}. "
        f"Net deltas should sum to +20; concurrent races wash out increments."
    )
