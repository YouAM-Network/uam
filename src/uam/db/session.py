"""AsyncSession factory and FastAPI dependency.

Provides the session layer that sits on top of the async engine.  The
``get_session`` async generator is designed to be used with
``fastapi.Depends`` so each HTTP request gets its own ``AsyncSession``
with automatic cleanup.

Usage::

    from fastapi import Depends
    from sqlalchemy.ext.asyncio import AsyncSession
    from uam.db.session import get_session

    @app.get("/agents")
    async def list_agents(session: AsyncSession = Depends(get_session)):
        ...
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlmodel import SQLModel

from uam.db.engine import get_engine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Singleton cache
# ---------------------------------------------------------------------------

_session_factory: async_sessionmaker[AsyncSession] | None = None

# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------


def async_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create a new ``async_sessionmaker`` bound to *engine*.

    Parameters
    ----------
    engine:
        The ``AsyncEngine`` to bind sessions to.

    Returns
    -------
    async_sessionmaker[AsyncSession]
        A session factory that produces ``AsyncSession`` instances with
        ``expire_on_commit=False`` (safe for returning data after commit).
    """
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def init_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create (or return existing) session factory singleton.

    Parameters
    ----------
    engine:
        The ``AsyncEngine`` to bind sessions to.

    Returns
    -------
    async_sessionmaker[AsyncSession]
        The cached session factory (idempotent).
    """
    global _session_factory  # noqa: PLW0603

    if _session_factory is not None:
        return _session_factory

    _session_factory = async_session_factory(engine)
    logger.info("Session factory initialized")
    return _session_factory


# ---------------------------------------------------------------------------
# FastAPI dependency
# ---------------------------------------------------------------------------


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that yields a per-request ``AsyncSession``.

    The session is automatically closed when the request finishes (even on
    error) thanks to the ``async with`` context manager.

    Raises
    ------
    RuntimeError
        If ``init_session_factory()`` has not been called yet.

    Yields
    ------
    AsyncSession
        A fresh session for the duration of one request.
    """
    if _session_factory is None:
        raise RuntimeError(
            "Session factory not initialized. Call init_session_factory() first."
        )
    try:
        async with _session_factory() as session:
            yield session
    except OperationalError as exc:
        from uam.db.retry import is_transient_error

        if is_transient_error(exc):
            logger.warning("Transient DB error during session: %s", exc)
        raise


# ---------------------------------------------------------------------------
# Table management (dev / testing)
# ---------------------------------------------------------------------------


async def create_tables(engine: AsyncEngine) -> None:
    """Create all SQLModel tables in the database.

    This is intended for **development and testing** only.  Production
    deployments should use Alembic migrations (Phase 34).

    Parameters
    ----------
    engine:
        The ``AsyncEngine`` whose database will receive the tables.
    """
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    logger.info("All SQLModel tables created")
