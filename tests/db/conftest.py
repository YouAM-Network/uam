"""Shared test fixtures for UAM database CRUD tests.

Provides an in-memory SQLite async engine and per-test AsyncSession.
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
