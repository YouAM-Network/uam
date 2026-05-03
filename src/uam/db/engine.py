"""Async engine factory with dual-backend support.

Creates SQLAlchemy ``AsyncEngine`` instances from a ``DATABASE_URL`` that may
point to either **PostgreSQL** (via ``asyncpg``) or **SQLite** (via
``aiosqlite``).  Backend-specific connection defaults are applied
automatically.

Usage::

    from uam.db.engine import create_async_engine_from_env, init_engine

    # One-shot creation from env
    engine = create_async_engine_from_env()

    # Or singleton pattern for app lifecycle (T4.5: init is async)
    engine = await init_engine()      # creates & caches under asyncio.Lock
    engine = get_engine()             # retrieves cached (sync)
    await dispose_engine()            # cleanup (also clears session factory)
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    create_async_engine as _create_async_engine,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Phase 47 R-47-10-01 — SQLite FK enforcement (production parity with tests)
#
# SQLite's ``PRAGMA foreign_keys`` defaults to OFF, and the setting is
# **per-connection** (not persisted). Prior to this fix the relay's lifespan
# (``src/uam/relay/app.py:317-322``) set the PRAGMA exactly once at startup
# against a single connection, which had ZERO effect on every subsequent
# pool checkout. Production therefore silently disabled all 11 FKs added by
# alembic ``0006_foreign_keys`` on SQLite deployments — the exact bypass
# documented in REVIEW-phase47.md L153-205 (Phase 48 blocker R-47-10-01).
#
# Fix: register a SQLAlchemy connect-event listener at module import time so
# every new SQLite DBAPI connection (relay app, CLI, alembic runner, test
# suite — anything that creates an engine via this module) executes
# ``PRAGMA foreign_keys=ON`` before SQLAlchemy hands it back to the pool.
#
# Dialect detection MUST happen BEFORE issuing the PRAGMA. Running a
# SQLite-only PRAGMA on a Postgres connection puts psycopg2 into
# ``InFailedSqlTransaction``, which surfaces later as a hard error during
# SQLAlchemy's on_connect probes (e.g. hstore OID lookup). The
# ``type(dbapi_conn).__module__`` check returns ``sqlite3``, ``aiosqlite``,
# or ``pysqlite3`` for SQLite drivers and never matches asyncpg / psycopg2.
#
# This mirrors ``tests/db/conftest.py:_enable_sqlite_fk`` so the test
# fixture and production share the same enforcement primitive.
# ---------------------------------------------------------------------------

from sqlalchemy import event as _sa_event
from sqlalchemy.engine import Engine as _SyncEngine


def _enable_sqlite_foreign_keys(dbapi_conn, _conn_record):  # type: ignore[no-untyped-def]
    """Per-connection PRAGMA: enforce SQLite foreign keys.

    Fires for SQLite DBAPI connections only; non-SQLite drivers
    (asyncpg, psycopg2) short-circuit before the PRAGMA executes.
    """
    module_name = type(dbapi_conn).__module__.lower()
    if "sqlite" not in module_name:
        return
    try:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    except Exception:  # pragma: no cover -- defensive
        # Never break engine creation over a PRAGMA hiccup; the FK gap
        # would surface as a regression-test failure long before prod.
        pass


_FK_LISTENER_INSTALLED: bool = False


def _install_sqlite_fk_listener_once() -> None:
    """Idempotent install of the connect listener on the global Engine class.

    Multiple imports within the same process (common in test-runner
    sessions) MUST NOT stack listeners — that would cause N PRAGMA
    executions per connection and skew test counts.
    """
    global _FK_LISTENER_INSTALLED  # noqa: PLW0603
    if _FK_LISTENER_INSTALLED:
        return
    _sa_event.listen(_SyncEngine, "connect", _enable_sqlite_foreign_keys)
    _FK_LISTENER_INSTALLED = True


# Install at import time so the relay app, CLI, alembic runner, and test
# suite all share the same enforcement primitive.
_install_sqlite_fk_listener_once()


# ---------------------------------------------------------------------------
# Singleton cache
# ---------------------------------------------------------------------------

_engine: AsyncEngine | None = None
# T4.5 (Phase 44 Plan 04): module-level lock serializes concurrent
# ``init_engine()`` callers so they all observe the SAME singleton instance.
# Python >=3.10 makes ``asyncio.Lock()`` loop-agnostic at module load
# (see RESEARCH Pitfall 5), so creating it at import time is safe.
_engine_lock: asyncio.Lock = asyncio.Lock()

# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------


def create_async_engine_from_url(url: str, **kwargs: Any) -> AsyncEngine:
    """Create an ``AsyncEngine`` from a database URL.

    Detects the backend from the URL scheme and applies sensible defaults:

    - **PostgreSQL** (``postgresql://`` or ``postgres://``): asyncpg with
      connection-pool tuning.
    - **SQLite** (``sqlite://``): aiosqlite with ``check_same_thread=False``.

    Parameters
    ----------
    url:
        A SQLAlchemy-compatible async database URL.
    **kwargs:
        Additional keyword arguments forwarded to
        ``sqlalchemy.ext.asyncio.create_async_engine``.  They override any
        defaults set by this function.

    Returns
    -------
    AsyncEngine
        A configured async engine ready for session binding.

    Raises
    ------
    ValueError
        If the URL scheme is not supported.
    """
    merged: dict[str, Any] = {"echo": False}

    if url.startswith("postgresql") or url.startswith("postgres://"):
        # Heroku / Railway use postgres:// which asyncpg doesn't accept
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql+asyncpg://", 1)
        elif "+" not in url.split("://")[0]:
            # postgresql://... -> postgresql+asyncpg://...
            url = url.replace("postgresql://", "postgresql+asyncpg://", 1)

        pool_size = int(os.environ.get("DB_POOL_SIZE", "5"))
        max_overflow = int(os.environ.get("DB_MAX_OVERFLOW", "10"))
        pool_timeout = int(os.environ.get("DB_POOL_TIMEOUT", "30"))
        pool_recycle = int(os.environ.get("DB_POOL_RECYCLE", "1800"))
        merged.update(
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
            pool_recycle=pool_recycle,
        )
        logger.info(
            "Pool config: size=%d, overflow=%d, timeout=%d, recycle=%d",
            pool_size, max_overflow, pool_timeout, pool_recycle,
        )
        backend = "postgresql (asyncpg)"

    elif url.startswith("sqlite"):
        # SQLite uses NullPool/StaticPool -- pool_size/max_overflow are
        # not applicable and would raise if passed.
        # Ensure the async driver is specified
        if "+aiosqlite" not in url:
            url = url.replace("sqlite://", "sqlite+aiosqlite://", 1)

        merged.setdefault("connect_args", {})
        merged["connect_args"]["check_same_thread"] = False
        # Set a timeout so concurrent writers don't fail immediately
        merged["connect_args"].setdefault("timeout", 30)
        # Pre-ping connections before use to detect stale connections
        merged.setdefault("pool_pre_ping", True)
        backend = "sqlite (aiosqlite)"

    else:
        raise ValueError(f"Unsupported DATABASE_URL scheme: {url}")

    # User-supplied kwargs take precedence
    merged.update(kwargs)

    logger.info("Creating async engine for %s backend", backend)
    return _create_async_engine(url, **merged)


def create_async_engine_from_env(**kwargs: Any) -> AsyncEngine:
    """Create an ``AsyncEngine`` from the ``DATABASE_URL`` environment variable.

    Raises
    ------
    RuntimeError
        If ``DATABASE_URL`` is not set.
    """
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError(
            "DATABASE_URL environment variable is required. "
            "Set it to postgresql+asyncpg://... or sqlite+aiosqlite:///..."
        )
    return create_async_engine_from_url(database_url, **kwargs)


# ---------------------------------------------------------------------------
# Singleton helpers
# ---------------------------------------------------------------------------


def get_engine() -> AsyncEngine:
    """Return the cached engine singleton.

    Raises
    ------
    RuntimeError
        If ``init_engine`` has not been called yet.
    """
    if _engine is None:
        raise RuntimeError(
            "Engine not initialized. Call init_engine() first."
        )
    return _engine


async def init_engine(url: str | None = None, **kwargs: Any) -> AsyncEngine:
    """Create (or return existing) engine singleton (T4.5 atomic).

    Double-check pattern: the fast path returns the cached ``_engine`` if
    one already exists, without acquiring the lock. Otherwise the slow path
    acquires ``_engine_lock`` and re-checks under the lock before creating.
    Concurrent callers therefore all observe the SAME instance — no
    orphaned connection pools (Threat T-44-04-01).

    Parameters
    ----------
    url:
        Optional explicit URL.  Falls back to ``DATABASE_URL`` env var.
    **kwargs:
        Forwarded to the engine factory.

    Returns
    -------
    AsyncEngine
        The cached engine instance (idempotent).
    """
    global _engine  # noqa: PLW0603

    if _engine is not None:
        return _engine  # fast path -- no lock needed once cached

    async with _engine_lock:
        # Double-check under the lock: another coroutine may have populated
        # ``_engine`` while we were waiting on lock acquisition.
        if _engine is not None:
            return _engine
        if url is not None:
            _engine = create_async_engine_from_url(url, **kwargs)
        else:
            _engine = create_async_engine_from_env(**kwargs)
        return _engine


async def dispose_engine() -> None:
    """Dispose of the cached engine and reset the singleton (T4.5).

    Also clears the cached session factory so a subsequent ``init_engine``
    call doesn't return a fresh engine bound to a stale factory pointing at
    the disposed engine (Threat T-44-04-02).
    """
    global _engine  # noqa: PLW0603

    async with _engine_lock:
        if _engine is not None:
            await _engine.dispose()
            _engine = None
            logger.info("Async engine disposed")
            # Lazy import: avoids a circular dependency at module load time
            # (uam.db.session imports get_engine from this module).
            from uam.db.session import dispose_session_factory

            await dispose_session_factory()
