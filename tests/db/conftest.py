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


# Phase 47 T7.3a: with FOREIGN KEY constraints now enforced (PRAGMA
# foreign_keys=ON via the autouse fixture below), child-row tests must have
# their parent ``agents`` rows present BEFORE the child INSERT runs. The
# ``seed_agents`` helper below is exposed to test modules that need to bulk-
# insert parent agents for FK-target use; tests that manage their own agent
# lifecycle (e.g. ``test_agents.py``, ``test_reservations.py``) do NOT use
# this helper and start with an empty agents table.
async def seed_agents(eng_or_session, addresses) -> None:
    """Insert fixture-scope agents so child-table tests can FK-resolve.

    Uses raw SQL via the engine/session to avoid pulling in CRUD layer
    assumptions (Settings, hash_token, etc.). Idempotent on (address)
    primary key via ``INSERT OR IGNORE``.
    """
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncEngine

    async def _do(conn):
        for addr in addresses:
            # Phase 47 T7.5: agents.token column was dropped in alembic 0007;
            # only token_hash is persisted now. The fixture hash is a marker
            # string (not a real HMAC) so tests can match against it if they
            # need to assert on the value.
            await conn.execute(text(
                "INSERT OR IGNORE INTO agents "
                "(address, public_key, token_hash, status, "
                " created_at, updated_at) "
                "VALUES (:addr, 'fixture-pk', :hsh, 'active', "
                "        datetime('now'), datetime('now'))"
            ), {
                "addr": addr,
                "hsh": f"fixture-hash-{addr}",
            })

    if isinstance(eng_or_session, AsyncEngine):
        async with eng_or_session.begin() as conn:
            await _do(conn)
    else:
        # AsyncSession: use the underlying connection
        await _do(eng_or_session)
        await eng_or_session.commit()


_COMMON_FIXTURE_AGENTS = (
    "alice::youam.network", "bob::youam.network", "carol::youam.network",
    "dave::youam.network", "eve::youam.network", "frank::youam.network",
    "admin::youam.network", "active::youam.network",
    "expired::youam.network", "gone::youam.network", "other::youam.network",
    "reserved::youam.network", "claimme::youam.network",
    "taken::youam.network", "test::youam.network", "bytoken::youam.network",
    "alice::test.local", "bob::test.local",
)

# Test modules whose tests manage agent lifecycle themselves and therefore
# must NOT receive pre-seeded agents (those would conflict with the test's
# own ``create_agent`` calls via UNIQUE constraint).
_AGENT_LIFECYCLE_MODULES = frozenset({
    "test_agents", "test_reservations", "test_reservations_concurrency",
})


def _module_needs_seed(request) -> bool:
    """True iff the test module is NOT in ``_AGENT_LIFECYCLE_MODULES``.

    Drives whether the engine fixture pre-seeds parent agent rows for
    FK-resolution. Tests that manage their own agent lifecycle opt out so
    their ``create_agent`` calls don't hit UNIQUE constraint violations.
    """
    module = request.node.module
    return getattr(module, "__name__", "").rsplit(".", 1)[-1] not in _AGENT_LIFECYCLE_MODULES


@pytest.fixture
async def engine(request):
    """Create an in-memory SQLite async engine with all tables.

    Pre-seeds fixture-scope parent agents for FK-resolution UNLESS the test
    module is in ``_AGENT_LIFECYCLE_MODULES`` (those tests manage agents
    themselves; pre-seeding would cause UNIQUE constraint violations).
    """
    eng = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with eng.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    if _module_needs_seed(request):
        await seed_agents(eng, _COMMON_FIXTURE_AGENTS)
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
async def file_engine(tmp_path, request):
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
    if _module_needs_seed(request):
        await seed_agents(eng, _COMMON_FIXTURE_AGENTS)
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


# ---------------------------------------------------------------------------
# Phase 47 Wave 0 — Postgres testcontainer fixtures + SQLite FK enforcement
#
# Per RESEARCH Pattern 6 (testcontainers fixture) + Pitfall 2 (PRAGMA
# foreign_keys=ON for SQLite) + Pitfall 4 (testcontainers URL rewrite for
# asyncpg).
# ---------------------------------------------------------------------------

import os as _os  # noqa: E402  -- module-local alias to avoid colliding above
from pathlib import Path as _Path  # noqa: E402
from alembic.config import Config as _AlembicConfig  # noqa: E402

try:
    from testcontainers.postgres import PostgresContainer as _PostgresContainer
    _HAS_TC = True
except ImportError:
    _PostgresContainer = None  # type: ignore[assignment]
    _HAS_TC = False


@pytest.fixture(scope="session")
def postgres_url():
    """Session-scoped Postgres container for migration tests.

    Skip cleanly if:
      - ``UAM_TEST_POSTGRES_URL`` env var is NOT set, AND
      - ``testcontainers[postgres]`` is not installed OR Docker is unavailable.

    URL is rewritten to ``postgresql+asyncpg://`` (testcontainers default is
    psycopg2 — RESEARCH Pitfall 4).
    """
    override = _os.environ.get("UAM_TEST_POSTGRES_URL")
    if override:
        yield override
        return
    if not _HAS_TC:
        pytest.skip("testcontainers not installed; pip install -e '.[dev]'")
    try:
        with _PostgresContainer("postgres:16-alpine") as pg:
            url = pg.get_connection_url()
            url = url.replace("postgresql+psycopg2://", "postgresql+asyncpg://")
            url = url.replace("postgresql://", "postgresql+asyncpg://")
            yield url
    except Exception as exc:  # Docker unavailable, image pull failure, etc.
        pytest.skip(f"Docker unavailable for testcontainers: {exc}")


@pytest.fixture
def postgres_alembic_cfg(postgres_url, tmp_path):
    """Alembic config bound to the Postgres testcontainer.

    Function-scoped so each test gets a clean DATABASE_URL env, but the
    underlying container is session-scoped (it's expensive to spin up).
    """
    prev = _os.environ.get("DATABASE_URL")
    _os.environ["DATABASE_URL"] = postgres_url
    project_root = _Path(__file__).resolve().parents[2]
    cfg = _AlembicConfig(str(project_root / "alembic.ini"))
    yield cfg
    if prev is None:
        _os.environ.pop("DATABASE_URL", None)
    else:
        _os.environ["DATABASE_URL"] = prev


# ---------------------------------------------------------------------------
# Phase 47 T7.2 — make ``from alembic import env`` resolve to the project's
# alembic/env.py so test_alembic_env.py can unit-test the dialect-gate helper.
#
# The installed Alembic library shadows the project's env.py on the import
# path; we explicitly load it under ``alembic.env`` with a stubbed context so
# the entry-point block at the bottom of env.py is a no-op during tests.
# ---------------------------------------------------------------------------

import importlib.util as _importlib_util  # noqa: E402
import sys as _sys  # noqa: E402


def _load_project_alembic_env() -> None:
    if "alembic.env" in _sys.modules and hasattr(
        _sys.modules["alembic.env"], "_render_as_batch_for"
    ):
        return
    project_root = _Path(__file__).resolve().parents[2]
    env_path = project_root / "alembic" / "env.py"
    if not env_path.exists():  # pragma: no cover -- defensive
        return

    import alembic as _alembic_pkg
    _real_context = getattr(_alembic_pkg, "context", None)

    class _StubContext:
        config = type("_C", (), {"config_file_name": None})()

        @staticmethod
        def is_offline_mode() -> bool:
            # Pick offline so the load triggers run_migrations_offline (which
            # would otherwise spin up an async engine). With the no-op
            # configure/run_migrations below, the entry point is harmless.
            return True

        @staticmethod
        def configure(**_kw):  # noqa: ANN003
            return None

        @staticmethod
        def begin_transaction():
            class _Ctx:
                def __enter__(self):
                    return self

                def __exit__(self, *_a):
                    return False

            return _Ctx()

        @staticmethod
        def run_migrations() -> None:
            return None

    prev_db_url = _os.environ.get("DATABASE_URL")
    _os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    _alembic_pkg.context = _StubContext()  # type: ignore[attr-defined]
    try:
        spec = _importlib_util.spec_from_file_location("alembic.env", str(env_path))
        if spec is None or spec.loader is None:  # pragma: no cover -- defensive
            return
        mod = _importlib_util.module_from_spec(spec)
        _sys.modules["alembic.env"] = mod
        spec.loader.exec_module(mod)
    finally:
        if _real_context is not None:
            _alembic_pkg.context = _real_context  # type: ignore[attr-defined]
        else:  # pragma: no cover
            try:
                delattr(_alembic_pkg, "context")
            except AttributeError:
                pass
        if prev_db_url is None:
            _os.environ.pop("DATABASE_URL", None)
        else:
            _os.environ["DATABASE_URL"] = prev_db_url


_load_project_alembic_env()


# T7.3 + Pitfall 2: ensure PRAGMA foreign_keys=ON for any SQLite test engine.
# This applies globally to SQLAlchemy sync engines created in this test session.
#
# 47-09 fix: the original implementation tried PRAGMA on every connection and
# relied on a try/except to swallow the failure on non-SQLite. That worked in
# the sense that it didn't raise, BUT psycopg2 leaves the transaction in a
# poisoned state after a failed statement (InFailedSqlTransaction). When
# SQLAlchemy then runs its postgres on_connect probe (hstore OID lookup), the
# poisoned transaction surfaces as a hard sqlalchemy.exc.InternalError. The
# fix is to dialect-detect BEFORE issuing the PRAGMA so Postgres connections
# never see the SQLite-only statement.
def _enable_sqlite_fk(dbapi_conn, _conn_record):
    cls_name = type(dbapi_conn).__module__.lower()
    # Match sqlite3 stdlib + aiosqlite + pysqlite3 — exclude psycopg2/asyncpg/etc.
    if "sqlite" not in cls_name:
        return
    try:
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()
    except Exception:
        # Defensive: never break test setup over a PRAGMA hiccup.
        pass


@pytest.fixture(autouse=True)
def _install_sqlite_fk_listener():
    """Hook PRAGMA foreign_keys=ON onto every new SQLite connection in the test process.

    This is autouse because per-test FK enforcement on SQLite is the documented
    requirement from RESEARCH Pitfall 2. Postgres connections short-circuit (the
    PRAGMA statement is harmless on non-SQLite via the try/except above).
    """
    from sqlalchemy import event
    from sqlalchemy.engine import Engine
    if not getattr(_install_sqlite_fk_listener, "_installed", False):
        event.listen(Engine, "connect", _enable_sqlite_fk)
        _install_sqlite_fk_listener._installed = True  # type: ignore[attr-defined]
    yield
