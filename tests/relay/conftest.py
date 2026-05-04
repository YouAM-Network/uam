"""Shared fixtures for UAM relay tests."""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlmodel import SQLModel

import uam.db.models  # noqa: F401 -- registers tables with SQLModel.metadata

from uam.protocol import (
    MessageType,
    create_envelope,
    generate_keypair,
    serialize_verify_key,
    to_wire_dict,
)
from uam.relay.app import create_app


# ---------------------------------------------------------------------------
# Phase 48 Q5 (48-04) — local ``session_factory`` fixture for retention tests
#
# The ``session_factory`` fixture in ``tests/db/conftest.py`` is not visible
# to ``tests/relay/`` (pytest only loads conftest.py files from ancestor
# directories). Wave 0 of Phase 48 noted this gap in 48-00-SUMMARY.md and
# left the retention contract tests as ``pytest.fail`` stubs. Wave 2 (this
# plan) ships a sibling fixture so the retention sweep can be exercised
# against a real file-backed SQLite engine without depending on the
# ``tests/db/`` ancestry.
# ---------------------------------------------------------------------------


@pytest.fixture
async def relay_file_engine(tmp_path):
    """File-backed SQLite async engine with all SQLModel tables created.

    File-backed (not in-memory) so the session_factory below can hand out
    multiple sessions that see each other's writes — required by the
    retention sweep, which opens its own session via the factory while the
    test's setup session has already committed.
    """
    db_path = tmp_path / "retention.db"
    eng = create_async_engine(
        f"sqlite+aiosqlite:///{db_path}",
        echo=False,
        connect_args={"check_same_thread": False, "timeout": 30},
    )
    async with eng.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture
def session_factory(relay_file_engine):
    """``async_sessionmaker`` callable bound to ``relay_file_engine``.

    Mirrors the ``tests/db/conftest.py`` fixture of the same name so the
    retention contract tests can call ``run_retention_sweep(session_factory)``
    just like production code calls ``run_retention_sweep(app.state.session_factory)``.
    """
    return async_sessionmaker(
        relay_file_engine, class_=AsyncSession, expire_on_commit=False
    )


@pytest.fixture()
def app(tmp_path):
    """Create a relay app backed by a temporary database."""
    db_path = str(tmp_path / "test.db")
    os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{db_path}"
    os.environ["UAM_DB_PATH"] = db_path  # backward compat with Settings
    os.environ["UAM_RELAY_DOMAIN"] = "test.local"

    # Reset engine/session singletons so each test gets a fresh DB
    import uam.db.engine as _eng
    import uam.db.session as _sess
    _eng._engine = None
    _sess._session_factory = None

    yield create_app()

    # Cleanup env
    os.environ.pop("DATABASE_URL", None)
    os.environ.pop("UAM_DB_PATH", None)
    os.environ.pop("UAM_RELAY_DOMAIN", None)

    # Reset singletons for next test
    _eng._engine = None
    _sess._session_factory = None


@pytest.fixture()
def client(app):
    """Return a TestClient for the relay app with lifespan triggered."""
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def registered_agent(client):
    """Register a single agent and return its details.

    Returns dict with keys: address, token, signing_key, verify_key, public_key_str.
    """
    sk, vk = generate_keypair()
    pk_str = serialize_verify_key(vk)
    resp = client.post("/api/v1/register", json={
        "agent_name": "testbot",
        "public_key": pk_str,
    })
    assert resp.status_code == 200, resp.text
    data = resp.json()
    return {
        "address": data["address"],
        "token": data["token"],
        "signing_key": sk,
        "verify_key": vk,
        "public_key_str": pk_str,
    }


@pytest.fixture()
def registered_agent_pair(client):
    """Register two agents (alice and bob) and return their details.

    Returns tuple of two agent dicts.
    """
    agents = []
    for name in ("alice", "bob"):
        sk, vk = generate_keypair()
        pk_str = serialize_verify_key(vk)
        resp = client.post("/api/v1/register", json={
            "agent_name": name,
            "public_key": pk_str,
        })
        assert resp.status_code == 200, resp.text
        data = resp.json()
        agents.append({
            "address": data["address"],
            "token": data["token"],
            "signing_key": sk,
            "verify_key": vk,
            "public_key_str": pk_str,
        })
    return agents[0], agents[1]


def _make_envelope(from_agent: dict, to_agent: dict) -> dict:
    """Create a signed envelope as a wire dict using the protocol library.

    Takes two agent dicts (from registered_agent fixtures).
    """
    envelope = create_envelope(
        from_address=from_agent["address"],
        to_address=to_agent["address"],
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"Hello from tests!",
        signing_key=from_agent["signing_key"],
        recipient_verify_key=to_agent["verify_key"],
    )
    return to_wire_dict(envelope)


@pytest.fixture()
def make_envelope():
    """Fixture that returns the make_envelope helper function."""
    return _make_envelope
