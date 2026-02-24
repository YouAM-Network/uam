"""Alembic environment configuration for UAM relay database.

Supports both PostgreSQL (asyncpg) and SQLite (aiosqlite) backends
via DATABASE_URL environment variable.  Uses async engine pattern
to run migrations.
"""

from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel

# ---------------------------------------------------------------------------
# Ensure all 17 table classes register on SQLModel.metadata
# ---------------------------------------------------------------------------
from uam.db.models import *  # noqa: F401, F403

# ---------------------------------------------------------------------------
# Alembic Config
# ---------------------------------------------------------------------------

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

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
        render_as_batch=True,
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
        render_as_batch=True,
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
