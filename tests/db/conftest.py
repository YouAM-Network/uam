"""Shared test fixtures for UAM database CRUD tests.

Provides an in-memory SQLite async engine and per-test AsyncSession.

Phase 44 Wave 0 additions:
  - ``file_engine`` — file-backed SQLite engine so multiple sessions can
    share state for adversarial concurrency tests (in-memory engines use
    a private DB per connection)
  - ``session_factory`` — async_sessionmaker bound to ``file_engine`` so
    tests can do ``async with session_factory() as session:`` from
    multiple concurrent coroutines and have them see each other's writes
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlmodel import SQLModel

import uam.db.models  # noqa: F401 -- registers all tables with SQLModel.metadata


@pytest.fixture
async def engine():
    """Create an in-memory SQLite async engine with all tables."""
    eng = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture
async def session(engine):
    """Provide an AsyncSession for each test, rolled back after."""
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as sess:
        yield sess


# ---------------------------------------------------------------------------
# Phase 44 — fixtures for adversarial concurrency tests
# ---------------------------------------------------------------------------


@pytest.fixture
async def file_engine(tmp_path):
    """Create a FILE-BACKED SQLite async engine with all tables.

    Concurrency tests need multiple sessions (and therefore multiple
    connections) to share the same database. An in-memory ``sqlite://``
    engine gives each connection its own private DB, so writes from one
    coroutine are invisible to another. A file-backed DB makes the writes
    visible across connections — necessary for adversarial concurrency
    tests that fire ``asyncio.gather(*[attempt() for _ in range(N)])``.
    """
    db_path = tmp_path / "concurrency.db"
    eng = create_async_engine(
        f"sqlite+aiosqlite:///{db_path}",
        echo=False,
        # Allow concurrent connections from multiple coroutines
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    async with eng.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture
def session_factory(file_engine):
    """Provide an ``async_sessionmaker`` callable for concurrency tests.

    Usage::

        async def attempt():
            async with session_factory() as session:
                return await some_crud_op(session, ...)

        results = await asyncio.gather(*[attempt() for _ in range(50)])
    """
    return async_sessionmaker(
        file_engine, class_=AsyncSession, expire_on_commit=False
    )
