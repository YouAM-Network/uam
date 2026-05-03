"""Phase 44 Wave 0 — failing-by-design tests for engine + session-factory singletons.

Covers:
  T4.5  ENGINE-SINGLETON   — init_engine returns same instance under N concurrent calls
  T4.5  DISPOSE-FACTORY    — dispose_engine clears _session_factory
  T4.5  DISPOSE-EXISTS     — dispose_session_factory function exists in uam.db.session

Today (Wave 0):
  - ``init_engine`` is sync — concurrent callers can both check ``_engine is None``,
    both create a fresh engine, and the second one wins (TOCTOU)
  - ``dispose_engine`` clears ``_engine`` but leaves ``_session_factory``
    bound to the now-disposed engine
  - ``dispose_session_factory`` does not exist

Plan 44-04 contract:
  - convert ``init_engine`` to ``async def`` with an asyncio.Lock + double-check
  - add ``dispose_session_factory()`` to ``uam.db.session``
  - have ``dispose_engine`` call it

NEW FILE created by Plan 44-00.
"""

from __future__ import annotations

import asyncio
import inspect

import pytest


# ---------------------------------------------------------------------------
# T4.5 — ENGINE-SINGLETON: concurrent init returns same engine
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_init_returns_same_engine(tmp_path):
    """T4.5: 20 concurrent ``init_engine()`` calls return the SAME instance.

    Plan 44-04 contract:
      - init_engine becomes ``async def``
      - module-level ``_engine_lock = asyncio.Lock()`` serializes the init
      - double-check pattern: fast path returns cached value; lock-protected
        slow path constructs once

    Today (Wave 0): ``init_engine`` is a sync ``def``. Concurrent callers
    can both pass the ``if _engine is None`` guard and each create a fresh
    AsyncEngine. The TOCTOU race is masked on a single thread because the
    sync function never yields control mid-init — but the test still FAILS
    with TypeError (``cannot be used in 'await' expression``) because the
    contract REQUIRES the async conversion.
    """
    from uam.db import engine as eng_mod
    from uam.db import session as sess_mod

    eng_mod._engine = None
    sess_mod._session_factory = None

    url = f"sqlite+aiosqlite:///{tmp_path}/test_init.db"

    async def init():
        # Wave-0 contract: init_engine MUST be async after Plan 44-04.
        # Today it's sync — `await` raises TypeError, which is itself the
        # failing-by-design signal.
        result = eng_mod.init_engine(url=url)
        if inspect.iscoroutine(result):
            return await result
        # Sync today — wrap in async-friendly noop so the gather still works
        return result

    engines = await asyncio.gather(*[init() for _ in range(20)])
    assert all(e is engines[0] for e in engines), (
        f"T4.5: concurrent init_engine() calls returned different instances. "
        f"Got {len({id(e) for e in engines})} distinct engines from 20 calls. "
        f"Plan 44-04 must add asyncio.Lock + double-check to serialize init."
    )

    # The contract test — must be async after Plan 44-04.
    assert inspect.iscoroutinefunction(eng_mod.init_engine), (
        "T4.5 contract: init_engine must be `async def` so it can `async with "
        "self._engine_lock:` to serialize concurrent init. Today it's sync."
    )


# ---------------------------------------------------------------------------
# T4.5 — DISPOSE-FACTORY: dispose_engine must also clear _session_factory
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispose_clears_session_factory(tmp_path):
    """T4.5: ``dispose_engine()`` MUST also clear ``_session_factory``.

    Without this, a re-init returns a fresh engine bound to a stale session
    factory — every subsequent session uses the disposed engine and fails
    on first commit.

    Plan 44-04 contract:
      - ``uam.db.session`` exposes ``dispose_session_factory()``
      - ``dispose_engine()`` calls it under the lock

    Today (Wave 0): dispose_engine clears ``_engine`` but ``_session_factory``
    remains pinned to the disposed engine. This test FAILS because either:
      (a) ``init_engine`` is sync (TypeError on await), OR
      (b) after dispose, ``sess_mod._session_factory`` is still not None
    """
    from uam.db import engine as eng_mod
    from uam.db import session as sess_mod

    eng_mod._engine = None
    sess_mod._session_factory = None

    url = f"sqlite+aiosqlite:///{tmp_path}/test_dispose.db"

    # init_engine + init_session_factory: today sync, after fix async.
    # Tolerate both shapes so this test is durable across the API conversion.
    e1_result = eng_mod.init_engine(url=url)
    e1 = await e1_result if inspect.iscoroutine(e1_result) else e1_result
    f1_result = sess_mod.init_session_factory(e1)
    f1 = await f1_result if inspect.iscoroutine(f1_result) else f1_result
    assert sess_mod._session_factory is f1

    await eng_mod.dispose_engine()

    # After dispose, _session_factory MUST be None — otherwise re-init returns
    # a factory bound to the disposed engine and every session call explodes.
    assert sess_mod._session_factory is None, (
        f"T4.5: dispose_engine() did not clear _session_factory. "
        f"Got {sess_mod._session_factory!r} — should be None. "
        f"Plan 44-04 must have dispose_engine() also call "
        f"dispose_session_factory() (under the same lock)."
    )

    # Re-init should produce a fresh engine + factory bound to it.
    e2_result = eng_mod.init_engine(url=url)
    e2 = await e2_result if inspect.iscoroutine(e2_result) else e2_result
    f2_result = sess_mod.init_session_factory(e2)
    f2 = await f2_result if inspect.iscoroutine(f2_result) else f2_result
    assert f2 is not f1, (
        "T4.5: re-init produced the same session factory instance — "
        "the cached factory was not properly cleared on dispose."
    )


# ---------------------------------------------------------------------------
# T4.5 — DISPOSE-EXISTS: dispose_session_factory function must exist
# ---------------------------------------------------------------------------


def test_dispose_session_factory_exists():
    """T4.5: a ``dispose_session_factory()`` function MUST exist in
    ``uam.db.session`` and be callable.

    Today (Wave 0): the function does not exist — this test FAILS at the
    ``hasattr`` assertion. Plan 44-04 must add it (and have
    ``dispose_engine`` call it).
    """
    from uam.db import session as sess_mod

    assert hasattr(sess_mod, "dispose_session_factory"), (
        "T4.5: dispose_session_factory() missing from uam.db.session. "
        "Plan 44-04 must add `async def dispose_session_factory()` that "
        "clears the module-level _session_factory under the same lock as "
        "init_session_factory."
    )
    assert callable(sess_mod.dispose_session_factory), (
        "T4.5: dispose_session_factory exists but is not callable."
    )


# ---------------------------------------------------------------------------
# Phase 47 R-47-10-01 — PRAGMA foreign_keys=ON enforcement (engine-level)
#
# REVIEW-phase47.md L153-205 documented that the relay's production engine
# never ran ``PRAGMA foreign_keys=ON``, so all 11 FKs added by alembic
# 0006_foreign_keys were silently unenforced on SQLite. The fix in
# src/uam/db/engine.py installs a SQLAlchemy connect-event listener at
# module import time that mirrors tests/db/conftest.py:_enable_sqlite_fk.
#
# These regression tests boot a real engine via ``init_engine(url=...)``
# (the same code path the FastAPI lifespan uses) and assert
# ``PRAGMA foreign_keys = 1`` on a freshly-checked-out connection — both
# on the first checkout AND across N sequential checkouts (because SQLite
# PRAGMA is per-connection, not persisted).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sqlite_engine_enforces_pragma_foreign_keys(tmp_path):
    """R-47-10-01 regression: any SQLite engine created via the project
    factory MUST report ``PRAGMA foreign_keys = 1`` on a checked-out
    connection.

    Background: SQLite's default is foreign_keys=OFF and the PRAGMA is
    per-connection (not persisted). Without the engine-level connect
    listener in src/uam/db/engine.py, all FKs declared by alembic
    0006_foreign_keys are silently unenforced in production.

    This test is a production-path equivalent of
    tests/db/conftest.py::_install_sqlite_fk_listener (which is the test-
    only fixture). After this regression test passes, the conftest
    autouse fixture is defence-in-depth, not the sole enforcement.
    """
    from sqlalchemy import text
    from uam.db import engine as eng_mod

    # Reset singleton so we exercise the factory fresh.
    eng_mod._engine = None
    url = f"sqlite+aiosqlite:///{tmp_path}/test_pragma_fk.db"
    engine = await eng_mod.init_engine(url=url)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("PRAGMA foreign_keys"))
            value = result.scalar()
        assert value == 1, (
            f"R-47-10-01: SQLite engine reports PRAGMA foreign_keys={value}, "
            "expected 1. Engine-level connect listener in "
            "src/uam/db/engine.py is missing or broken — production "
            "deployments would silently skip all FK enforcement."
        )
    finally:
        await eng_mod.dispose_engine()


@pytest.mark.asyncio
async def test_sqlite_pragma_fk_persists_across_pool_checkouts(tmp_path):
    """R-47-10-01 defence-in-depth: every NEW connection (not just the
    first) must get PRAGMA foreign_keys=ON.

    SQLite's PRAGMA is per-connection, so a single "set on first connect"
    pattern is insufficient. The connect-event listener fires on every
    pool connection — verify by forcing N fresh checkouts.
    """
    from sqlalchemy import text
    from uam.db import engine as eng_mod

    eng_mod._engine = None
    url = f"sqlite+aiosqlite:///{tmp_path}/test_pragma_fk_pool.db"
    engine = await eng_mod.init_engine(url=url)
    try:
        # 5 sequential checkouts — the aiosqlite pool may reuse or rotate;
        # either way, every connection should have FKs ON.
        for i in range(5):
            async with engine.connect() as conn:
                value = (await conn.execute(text("PRAGMA foreign_keys"))).scalar()
                assert value == 1, (
                    f"Checkout #{i}: PRAGMA foreign_keys={value}, expected 1."
                )
    finally:
        await eng_mod.dispose_engine()
