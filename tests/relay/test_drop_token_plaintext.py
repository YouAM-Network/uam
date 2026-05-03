"""Failing-by-design tests for T7.5: drop agents.token plaintext column.

These pin the post-T7.5 invariants:
  * Migration 0007 drops agents.token (column gone post-upgrade).
  * crud.agents.create_agent has no `token` parameter (only token_hash).
  * Agent SQLModel has no `token` field.
  * webhook.py HMAC signing path uses agent.token_hash, never agent.token.

RED at HEAD because the column, parameter, and field still exist; webhook.py
still reads ``agent.token``.
"""

from __future__ import annotations

import inspect
import os
import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


@pytest.fixture
def db_at_head(tmp_path):
    db_path = tmp_path / "drop_token.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"
    os.environ["DATABASE_URL"] = db_url
    project_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(project_root / "alembic.ini"))
    command.upgrade(cfg, "head")
    yield db_path
    os.environ.pop("DATABASE_URL", None)


def test_agents_table_no_token_column(db_at_head):
    """T7.5: post-migration, agents table MUST NOT have a `token` column.

    RED at HEAD because alembic head is 0004; agents.token still exists.
    GREEN after 47-08 lands 0007_drop_token_plaintext.
    """
    conn = sqlite3.connect(str(db_at_head))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(agents)").fetchall()]
    conn.close()
    assert "token" not in cols, (
        f"T7.5 contract: agents.token must be dropped post-0007. Cols: {cols}"
    )
    assert "token_hash" in cols, "token_hash must remain (authoritative)"


def test_create_agent_signature_no_token_param():
    """T7.5: CRUD create_agent must NOT accept a `token` parameter post-T7.5."""
    from uam.db.crud.agents import create_agent
    sig = inspect.signature(create_agent)
    assert "token" not in sig.parameters, (
        f"T7.5 contract: create_agent(token=...) parameter must be removed. "
        f"Current params: {list(sig.parameters)}"
    )
    assert "token_hash" in sig.parameters, "token_hash param must remain"


def test_agent_model_no_token_field():
    """T7.5: SQLModel Agent must NOT have a `token` attribute post-T7.5."""
    from uam.db.models import Agent
    fields = list(Agent.model_fields.keys())
    assert "token" not in fields, (
        f"T7.5 contract: Agent.token field must be removed. Fields: {fields}"
    )
    assert "token_hash" in fields, "token_hash field must remain"


def test_webhook_signing_works_without_plaintext_token():
    """T7.5 + RESEARCH OQ1: webhook HMAC signing must work post-token-drop.

    Recommendation (a): use agent.token_hash as signing key (high-entropy,
    never leaves the server). 47-08 must update src/uam/relay/webhook.py
    accordingly.
    """
    src_path = Path(__file__).resolve().parents[2] / "src" / "uam" / "relay" / "webhook.py"
    source = src_path.read_text()
    # Strip the legitimate ".token_hash" references so we can detect raw "agent.token" usage.
    sanitized = source.replace(".token_hash", "")
    assert "agent.token" not in sanitized, (
        "T7.5 contract: webhook.py must not read agent.token (column dropped). "
        "Recommended fix: use agent.token_hash as signing key (RESEARCH OQ1 option a)."
    )
    assert "token_hash" in source, (
        "T7.5 contract: webhook.py must use agent.token_hash for HMAC signing key."
    )


# ---------------------------------------------------------------------------
# Phase 47 R-47-10-02 — demo agent must persist HMAC, not plaintext token
#
# REVIEW-phase47.md L350-407: src/uam/relay/routes/demo.py:64 was passing
# session.token (plaintext from secrets.token_urlsafe(32)) as the 4th
# positional arg to create_agent — which is now token_hash per the
# post-47-08 signature. Demo agents persisted plaintext bearer tokens in
# the agents.token_hash column, defeating T7.5's snapshot-leak protection
# on the public-facing magic-moment entry point.
# ---------------------------------------------------------------------------


@pytest.fixture()
def demo_app(tmp_path, monkeypatch):
    """Minimal relay app for testing the demo session route end-to-end."""
    db_path = str(tmp_path / "demo_token_hash.db")
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("UAM_DB_PATH", db_path)
    monkeypatch.setenv("UAM_RELAY_DOMAIN", "youam.network")
    monkeypatch.setenv("UAM_TOKEN_PEPPER", "test-pepper-1234567890")
    # Reset engine/session singletons so each test gets a fresh DB.
    import uam.db.engine as _eng
    import uam.db.session as _sess
    _eng._engine = None
    _sess._session_factory = None
    from uam.relay.app import create_app
    yield create_app()
    _eng._engine = None
    _sess._session_factory = None


@pytest.fixture()
async def demo_client(demo_app):
    """httpx client with lifespan triggered, yielding (client, app)."""
    import httpx
    async with demo_app.router.lifespan_context(demo_app):
        transport = httpx.ASGITransport(app=demo_app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            yield client, demo_app


@pytest.mark.asyncio
async def test_demo_agent_stores_hashed_token(demo_client):
    """R-47-10-02 regression: demo session creation MUST persist the HMAC
    of session.token in agents.token_hash — never the plaintext.

    Background: src/uam/relay/routes/demo.py previously called
    ``create_agent(db_session, session.address, session.verify_key_b64,
    session.token)`` — the 4th positional is ``token_hash`` per the
    post-47-08 signature, so this wrote PLAINTEXT into the hash column,
    defeating T7.5's snapshot-leak protection for every demo agent.

    This test:
      1. Creates a demo session via POST /api/v1/demo/session.
      2. Looks up the in-memory SessionManager to recover the plaintext
         session.token (only the relay knows it; the HTTP response only
         returns session_id + address).
      3. Reads agents.token_hash from the DB for the new address.
      4. Asserts token_hash != plaintext token.
      5. Asserts token_hash == hash_token(plaintext, settings.token_pepper).
    """
    from sqlalchemy import text as sql_text
    from uam.db.engine import get_engine
    from uam.relay.token_hashing import hash_token

    client, app = demo_client

    resp = await client.post("/api/v1/demo/session")
    assert resp.status_code == 200, resp.text
    data = resp.json()
    session_id = data["session_id"]
    address = data["address"]

    # Recover the plaintext token from the in-memory SessionManager
    # (the HTTP response intentionally does NOT expose it).
    session_mgr = app.state.demo_sessions
    session = await session_mgr.get(session_id)
    assert session is not None, "demo session was not stored"
    plaintext_token = session.token
    assert plaintext_token, "session.token should be a non-empty string"

    settings = app.state.settings
    expected_hash = hash_token(plaintext_token, settings.token_pepper)

    # Read the persisted token_hash directly from the agents table.
    engine = get_engine()
    async with engine.connect() as conn:
        row = (await conn.execute(
            sql_text("SELECT token_hash FROM agents WHERE address = :addr"),
            {"addr": address},
        )).fetchone()

    assert row is not None, f"demo agent {address} not persisted"
    persisted_hash = row[0]

    assert persisted_hash != plaintext_token, (
        "R-47-10-02: agents.token_hash equals the PLAINTEXT session.token. "
        "demo.py is persisting plaintext into the hash column — DB snapshot "
        "leak now exposes raw bearer tokens for every demo agent. "
        "Fix: hash_token(session.token, settings.token_pepper) before "
        "passing to create_agent (mirror reserve.py:196-201)."
    )
    assert persisted_hash == expected_hash, (
        f"R-47-10-02: agents.token_hash != HMAC(session.token, pepper). "
        f"Got {persisted_hash!r}, expected {expected_hash!r}. "
        f"demo.py must use hash_token(session.token, settings.token_pepper)."
    )
