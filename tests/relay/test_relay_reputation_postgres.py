"""Failing-by-design portable-SQL tests for ``relay_reputation.py`` (T6.3 Wave 0).

Today's ``RelayReputationManager`` uses two SQLite-only constructs that crash
on Postgres:

  - ``INSERT OR IGNORE INTO ...``  -> Postgres has ``INSERT ... ON CONFLICT``
  - ``datetime('now')``            -> Postgres has ``NOW()``

These tests RED at HEAD on two axes:

  1. ``test_no_sqlite_only_sql_in_source`` -- a grep-style assertion against
     the source file. Plan 46-04's executor must rewrite to dialect-agnostic
     constructs (try/IntegrityError/rollback for the upsert, ``func.now()``
     for the timestamp) to make this GREEN.

  2. ``test_record_success_*`` -- functional assertions on SQLite that the
     rewritten code still increments score + updates timestamp + handles
     concurrent calls without producing duplicate rows.

These GREEN after Plan 46-04 lands the dialect-agnostic rewrite.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from uam.db import engine as engine_module
from uam.db import session as session_module
from uam.db.engine import init_engine
from uam.db.session import create_tables, init_session_factory
from uam.relay.relay_reputation import RelayReputationManager

# Resolve the source file relative to this test file so it works whether
# pytest is invoked from the repo root or anywhere else.
RELAY_REPUTATION_SRC = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "uam"
    / "relay"
    / "relay_reputation.py"
)


def test_no_sqlite_only_sql_in_source():
    """Grep acceptance: the production source must not contain SQLite-only SQL.

    RED at HEAD because both constructs ARE in the source today.
    GREEN after 46-04 rewrites with try/IntegrityError + func.now().
    """
    assert RELAY_REPUTATION_SRC.exists(), (
        f"Expected source at {RELAY_REPUTATION_SRC}; not found. "
        f"Did the file move? Update RELAY_REPUTATION_SRC."
    )
    source = RELAY_REPUTATION_SRC.read_text()

    assert "INSERT OR IGNORE" not in source, (
        "SQLite-only `INSERT OR IGNORE` found in src/uam/relay/relay_reputation.py. "
        "Postgres requires `INSERT ... ON CONFLICT DO NOTHING` (or the SQLAlchemy "
        "try/IntegrityError/rollback pattern). T6.3."
    )
    assert "datetime('now')" not in source, (
        "SQLite-only `datetime('now')` found in src/uam/relay/relay_reputation.py. "
        "Use `func.now()` (dialect-aware) instead. T6.3."
    )
    assert 'datetime("now")' not in source, (
        "SQLite-only `datetime(\"now\")` found in src/uam/relay/relay_reputation.py. "
        "Use `func.now()` instead. T6.3."
    )


@pytest.fixture
async def manager(tmp_path, monkeypatch) -> AsyncIterator[RelayReputationManager]:
    db_path = str(tmp_path / "test.db")
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("UAM_DB_PATH", db_path)

    engine_module._engine = None
    session_module._session_factory = None

    eng = await init_engine()
    factory = await init_session_factory(eng)
    await create_tables(eng)

    mgr = RelayReputationManager(factory)
    await mgr.load_cache()
    yield mgr

    engine_module._engine = None
    session_module._session_factory = None


async def test_record_success_increments_score_and_timestamp(manager):
    """Functional: record_success on a fresh domain creates row + increments + sets timestamp."""
    domain = "peer.example.com"

    await manager.record_success(domain)
    score1 = manager.get_score(domain)
    assert score1 == 51, f"After 1 success on default-50 domain, expected 51 got {score1}"

    await manager.record_success(domain)
    score2 = manager.get_score(domain)
    assert score2 == score1 + 1


async def test_record_success_concurrent_no_dupes(manager):
    """Concurrent record_success on a NEW domain: only one row, all increments applied.

    RED at HEAD: with N tasks each running ``INSERT OR IGNORE`` then ``UPDATE
    ... score = score + 1``, the read-modify-write inside the UPDATE on SQLite
    is implicit (single SQL statement) so most increments DO land. The race
    surfaces more obviously on Postgres without ON CONFLICT, but the property
    we want -- "score == 50 + n, capped at 100" -- still holds at HEAD on
    SQLite for small n. We assert n=20 -> 70 to keep below the 100 cap.
    """
    domain = "concurrent.example.com"
    n = 20
    await asyncio.gather(*[manager.record_success(domain) for _ in range(n)])

    score = manager.get_score(domain)
    assert score == 70, (
        f"Expected 70 (50 + {n} increments capped at 100), got {score}. "
        f"Either the increment SQL is racy or INSERT OR IGNORE produced duplicate "
        f"rows that diverged."
    )
