"""Failing-by-design tests for alembic/env.py dialect-gating logic (T7.2).

Per RESEARCH Pattern 2: render_as_batch must be True for SQLite (move-and-copy
required for ALTER) but False for Postgres (use real ALTER, avoid leaving
_alembic_tmp_* / _bk backup tables).

These RED at HEAD because alembic/env.py declares render_as_batch=True
unconditionally; 47-02 will refactor it to expose a `_render_as_batch_for(url)`
helper so dialect-gating can be unit-tested.
"""

from __future__ import annotations

import pytest


def test_render_as_batch_sqlite_true():
    """For sqlite URLs, render_as_batch must be True (move-and-copy required for ALTER)."""
    from alembic import env as alembic_env  # type: ignore[import-not-found]
    if not hasattr(alembic_env, "_render_as_batch_for"):
        pytest.fail(
            "T7.2 contract: 47-02 must expose a helper (e.g. `_render_as_batch_for(url)`) "
            "in alembic/env.py so dialect-gating can be unit-tested. Currently missing."
        )
    assert alembic_env._render_as_batch_for("sqlite+aiosqlite:///./x.db") is True
    assert alembic_env._render_as_batch_for("sqlite:///x.db") is True


def test_render_as_batch_postgres_false():
    """For postgres URLs, render_as_batch must be False (use real ALTER)."""
    from alembic import env as alembic_env
    if not hasattr(alembic_env, "_render_as_batch_for"):
        pytest.fail("T7.2 contract: helper missing (see test_render_as_batch_sqlite_true).")
    assert alembic_env._render_as_batch_for("postgresql+asyncpg://u:p@h/d") is False
    assert alembic_env._render_as_batch_for("postgresql://u:p@h/d") is False
