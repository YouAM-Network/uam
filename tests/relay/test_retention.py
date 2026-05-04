"""Q5 — Per-category retention sweeps (Phase 48).

Wave 0 shipped this file as RED stubs (``pytest.fail``); Wave 2 (48-04) ships
:mod:`uam.relay.retention` and converts the stubs into real assertions.

Each sweep is exercised against a file-backed SQLite engine via the
``session_factory`` fixture in ``tests/relay/conftest.py``. Cutoffs are
overridden via the ``now=`` kwarg so the tests don't depend on wall-clock.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text


def _import_retention():
    """Import the symbol surface under test.

    Kept as a helper to mirror the Wave 0 lazy-import pattern: if the module
    is ever moved or renamed, every test fails at the import line with one
    clear error rather than producing N obscure errors elsewhere.
    """
    from uam.relay.retention import (
        run_retention_sweep,
        RETENTION_DELIVERED_DAYS,
        RETENTION_UNDELIVERED_DAYS,
        RETENTION_FED_NONCE_HOURS,
        RETENTION_DEMO_HOURS,
        RETENTION_CHALLENGE_MINUTES,
    )
    return {
        "run_retention_sweep": run_retention_sweep,
        "RETENTION_DELIVERED_DAYS": RETENTION_DELIVERED_DAYS,
        "RETENTION_UNDELIVERED_DAYS": RETENTION_UNDELIVERED_DAYS,
        "RETENTION_FED_NONCE_HOURS": RETENTION_FED_NONCE_HOURS,
        "RETENTION_DEMO_HOURS": RETENTION_DEMO_HOURS,
        "RETENTION_CHALLENGE_MINUTES": RETENTION_CHALLENGE_MINUTES,
    }


# ---------------------------------------------------------------------------
# Helpers — seed parent agent + insert a message row directly via SQL.
# Bypasses the CRUD layer so the test stays agnostic to changes in
# ``store_message`` defaults (e.g. status, expires_at handling).
# ---------------------------------------------------------------------------


async def _seed_agent(session_factory, address: str = "alice::test.local") -> str:
    async with session_factory() as session:
        await session.execute(
            text(
                "INSERT OR IGNORE INTO agents "
                "(address, public_key, token_hash, status, "
                " created_at, updated_at) "
                "VALUES (:addr, 'fixture-pk', :hsh, 'active', "
                "        datetime('now'), datetime('now'))"
            ),
            {"addr": address, "hsh": f"fixture-hash-{address}"},
        )
        await session.commit()
    return address


async def _insert_message(
    session_factory,
    *,
    message_id: str,
    from_addr: str,
    to_addr: str,
    created_at: datetime,
    delivered_at: datetime | None = None,
    status: str = "queued",
) -> None:
    async with session_factory() as session:
        await session.execute(
            text(
                "INSERT INTO messages "
                "(message_id, from_addr, to_addr, envelope, status, "
                " retry_count, created_at, delivered_at) "
                "VALUES (:mid, :fa, :ta, :env, :st, 0, :ca, :da)"
            ),
            {
                "mid": message_id,
                "fa": from_addr,
                "ta": to_addr,
                "env": "{}",
                "st": status,
                "ca": created_at.isoformat(),
                "da": delivered_at.isoformat() if delivered_at else None,
            },
        )
        await session.commit()


async def _count_messages(session_factory) -> int:
    async with session_factory() as session:
        result = await session.execute(text("SELECT COUNT(*) FROM messages"))
        return int(result.scalar_one())


async def _insert_fed_nonce(
    session_factory, *, from_relay: str, nonce: str, seen_at: datetime
) -> None:
    async with session_factory() as session:
        await session.execute(
            text(
                "INSERT INTO federation_nonces "
                "(from_relay, nonce, seen_at) "
                "VALUES (:fr, :n, :sa)"
            ),
            {"fr": from_relay, "n": nonce, "sa": seen_at.isoformat()},
        )
        await session.commit()


async def _count_fed_nonces(session_factory) -> int:
    async with session_factory() as session:
        result = await session.execute(text("SELECT COUNT(*) FROM federation_nonces"))
        return int(result.scalar_one())


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delivered_pruned_when_older_than_window(session_factory):
    """A delivered message older than RETENTION_DELIVERED_DAYS is pruned."""
    syms = _import_retention()
    now = datetime.now(tz=timezone.utc)
    addr = await _seed_agent(session_factory)

    # Delivered 5 days ago (well past the 1-day default window).
    await _insert_message(
        session_factory,
        message_id="old-delivered",
        from_addr=addr,
        to_addr=addr,
        created_at=now - timedelta(days=5),
        delivered_at=now - timedelta(days=5),
        status="delivered",
    )

    results = await syms["run_retention_sweep"](session_factory, now=now)

    assert results["delivered"] == 1
    assert await _count_messages(session_factory) == 0


@pytest.mark.asyncio
async def test_recent_delivered_kept(session_factory):
    """A delivered message younger than the window is preserved."""
    syms = _import_retention()
    now = datetime.now(tz=timezone.utc)
    addr = await _seed_agent(session_factory)

    # Delivered 1 hour ago — within any reasonable RETENTION_DELIVERED_DAYS window.
    await _insert_message(
        session_factory,
        message_id="fresh-delivered",
        from_addr=addr,
        to_addr=addr,
        created_at=now - timedelta(hours=1),
        delivered_at=now - timedelta(hours=1),
        status="delivered",
    )

    results = await syms["run_retention_sweep"](session_factory, now=now)

    assert results["delivered"] == 0
    assert await _count_messages(session_factory) == 1


@pytest.mark.asyncio
async def test_undelivered_pruned_when_older_than_window(session_factory):
    """An undelivered message older than RETENTION_UNDELIVERED_DAYS is pruned."""
    syms = _import_retention()
    now = datetime.now(tz=timezone.utc)
    addr = await _seed_agent(session_factory)

    # Created 30 days ago, never delivered (delivered_at IS NULL) —
    # past the 7-day default undelivered window.
    await _insert_message(
        session_factory,
        message_id="old-undelivered",
        from_addr=addr,
        to_addr=addr,
        created_at=now - timedelta(days=30),
        delivered_at=None,
        status="queued",
    )
    # And a fresh undelivered to confirm only the old one is pruned.
    await _insert_message(
        session_factory,
        message_id="fresh-undelivered",
        from_addr=addr,
        to_addr=addr,
        created_at=now - timedelta(hours=1),
        delivered_at=None,
        status="queued",
    )

    results = await syms["run_retention_sweep"](session_factory, now=now)

    assert results["undelivered"] == 1
    assert await _count_messages(session_factory) == 1


@pytest.mark.asyncio
async def test_fed_nonce_pruned_when_older_than_window(session_factory):
    """A federation nonce older than RETENTION_FED_NONCE_HOURS is pruned.

    Verifies the table is ``federation_nonces`` with a ``seen_at`` column
    (Phase 45 schema).
    """
    syms = _import_retention()
    now = datetime.now(tz=timezone.utc)

    # Old nonce (24 h ago, past the 1-hour default window) and a fresh one.
    await _insert_fed_nonce(
        session_factory,
        from_relay="peer.example",
        nonce="old-nonce-12345",
        seen_at=now - timedelta(hours=24),
    )
    await _insert_fed_nonce(
        session_factory,
        from_relay="peer.example",
        nonce="fresh-nonce-67890",
        seen_at=now - timedelta(minutes=5),
    )

    results = await syms["run_retention_sweep"](session_factory, now=now)

    assert results["fed_nonce"] == 1
    assert await _count_fed_nonces(session_factory) == 1


@pytest.mark.asyncio
async def test_demo_session_pruned_when_older_than_window(session_factory):
    """The demo sweep is a forward-compat placeholder.

    ``demo_sessions`` is currently held in-memory by
    :class:`uam.relay.demo_sessions.SessionManager` (pruned by
    ``_demo_session_cleanup_loop``), so no DB table exists. The per-category
    exception handler swallows the missing-table error and returns 0 — the
    sweep does NOT abort. This test pins that contract so a future operator
    who creates a ``demo_sessions`` table will get DB-side pruning for free.
    """
    syms = _import_retention()
    now = datetime.now(tz=timezone.utc)

    results = await syms["run_retention_sweep"](session_factory, now=now)

    assert results["demo"] == 0  # missing table -> 0, not an exception
    # And the sweep continued past it: the other categories produced keys.
    assert "delivered" in results
    assert "undelivered" in results
    assert "fed_nonce" in results
    assert "challenge" in results


@pytest.mark.asyncio
async def test_challenge_pruned_when_older_than_window(session_factory):
    """The auth-challenge sweep is a forward-compat placeholder.

    ``auth_challenges`` lives in the registrar's separate aiosqlite database
    (``src/uam/registrar/database.py``), not the relay's SQLAlchemy DB. The
    per-category exception handler returns 0 here. Pinned so a future
    relocation of the table onto the relay engine gives DB-side pruning
    automatically.
    """
    syms = _import_retention()
    now = datetime.now(tz=timezone.utc)

    results = await syms["run_retention_sweep"](session_factory, now=now)

    assert results["challenge"] == 0  # missing table -> 0, not an exception
    # Sweep did not abort: every category contributed a key.
    assert set(results.keys()) == {
        "delivered",
        "undelivered",
        "fed_nonce",
        "demo",
        "challenge",
    }


def test_default_windows_match_research():
    """RESEARCH defaults: delivered=1d, undelivered=7d, fed_nonce=1h,
    demo=1h, challenge=5m. A future implementer who picks shorter windows
    fails here.
    """
    syms = _import_retention()
    assert syms["RETENTION_DELIVERED_DAYS"] >= 1
    assert syms["RETENTION_UNDELIVERED_DAYS"] >= 7
    assert syms["RETENTION_FED_NONCE_HOURS"] >= 1
    assert syms["RETENTION_DEMO_HOURS"] >= 1
    assert syms["RETENTION_CHALLENGE_MINUTES"] >= 5
