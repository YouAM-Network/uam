"""Alembic environment configuration for UAM relay database.

Supports both PostgreSQL (asyncpg) and SQLite (aiosqlite) backends
via DATABASE_URL environment variable.  Uses async engine pattern
to run migrations.
"""

from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig

# ---------------------------------------------------------------------------
# Phase 47 T7.2 — Dialect-gated batch mode helper.
#
# Defined BEFORE any alembic-context work so the helper is importable even
# when env.py is loaded outside an alembic invocation (e.g. by
# tests/db/test_alembic_env.py via importlib).
# ---------------------------------------------------------------------------


def _render_as_batch_for(url: str) -> bool:
    """Whether to enable Alembic's batch-mode for the given DB URL.

    Phase 47 T7.2: SQLite REQUIRES batch mode for ALTER TABLE (move-and-copy
    pattern emulates ALTER COLUMN since SQLite lacks native ALTER COLUMN).
    PostgreSQL supports ALTER COLUMN natively and gains nothing from batch
    mode; in fact, a future migration passing ``recreate='always'`` would be
    destructive on Postgres if batch mode were enabled. Gating defense-in-
    depth at the env layer prevents that class of footgun.

    Returns:
        True for sqlite URLs (any dialect prefix: sqlite, sqlite+aiosqlite, etc.)
        False otherwise (postgresql, postgresql+asyncpg, mysql, etc.)

    See: .planning/phases/47-.../47-RESEARCH.md § Pattern 2.
    """
    return url.startswith("sqlite")


# Self-register as ``alembic.env`` so a later ``from alembic import env``
# resolves to this module. Idempotent + harmless. The test conftest also
# explicitly loads this file under that name to make the helper unit-testable.
# Skip when Alembic loads env.py via its own loader (``__name__`` is then
# ``env_py``, not present in ``sys.modules``) — the migration runner doesn't
# need this self-registration anyway.
_self_mod = sys.modules.get(__name__)
if _self_mod is not None:
    sys.modules.setdefault("alembic.env", _self_mod)


from alembic import context  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402
from sqlmodel import SQLModel  # noqa: E402

# ---------------------------------------------------------------------------
# Ensure all 17 table classes register on SQLModel.metadata
# ---------------------------------------------------------------------------
from uam.db.models import *  # noqa: F401, F403, E402

# ---------------------------------------------------------------------------
# Alembic Config
# ---------------------------------------------------------------------------

config = context.config

if config.config_file_name is not None:
    # Phase 48 (Q2): pass ``disable_existing_loggers=False`` so the
    # alembic.ini ``[loggers]`` section does not silently disable every
    # already-imported logger (the default fileConfig behavior). Without
    # this, calling ``create_app()`` -> alembic migrations during a test
    # fixture leaves ``uam.protocol.*`` loggers ``disabled=True``, which
    # breaks pytest ``caplog`` capture for any subsequent test in the same
    # session. See tests/test_contact.py::
    # test_card_without_not_after_warns_and_uses_imported_at for the
    # reproducer that exposed this.
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = SQLModel.metadata


# ---------------------------------------------------------------------------
# URL normalisation (mirrors uam.db.engine.create_async_engine_from_url)
# ---------------------------------------------------------------------------


def _normalize_url(url: str) -> str:
    """Ensure the URL has the correct async driver prefix."""
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    if url.startswith("postgresql://") and "+" not in url.split("://")[0]:
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("sqlite://") and "+aiosqlite" not in url:
        return url.replace("sqlite://", "sqlite+aiosqlite://", 1)
    return url


def _get_url() -> str:
    """Read DATABASE_URL from environment."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL environment variable is required.  "
            "Set it to postgresql+asyncpg://... or sqlite+aiosqlite:///..."
        )
    return _normalize_url(url)


# ---------------------------------------------------------------------------
# Offline migrations (SQL script generation)
# ---------------------------------------------------------------------------


def run_migrations_offline() -> None:
    """Generate SQL migration script without a live connection."""
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=_render_as_batch_for(url),
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online migrations (async engine)
# ---------------------------------------------------------------------------


def _do_run_migrations(connection) -> None:  # noqa: ANN001
    """Configure context with a live connection and run migrations."""
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=_render_as_batch_for(str(connection.engine.url)),
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_async_migrations() -> None:
    """Create a disposable async engine and run migrations."""
    url = _get_url()

    kwargs: dict = {"echo": False}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}

    connectable = create_async_engine(url, **kwargs)

    async def do_migrations() -> None:
        async with connectable.connect() as connection:
            await connection.run_sync(_do_run_migrations)
        await connectable.dispose()

    asyncio.run(do_migrations())


def run_migrations_online() -> None:
    """Run migrations in online mode using async engine."""
    run_async_migrations()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
