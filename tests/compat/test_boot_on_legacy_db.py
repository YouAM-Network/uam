"""The current relay boots on a database an installed youam 1.0.1 built.

Relays without migrations (an installed youam on SQLite, such as Swarmify's
local relay) build their tables with ``create_tables``, which only adds
missing tables. So every release must work on the tables an older release
created: new tables only, never a changed one.

CI builds the database with the real 1.0.1 (``build_legacy_db.py``) and points
this test at it with ``UAM_LEGACY_DB`` and ``UAM_LEGACY_JSON``. Without them
the test is skipped.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlmodel import SQLModel

import uam.db.models  # noqa: F401  (registers every table)
from uam.protocol import MessageType, create_envelope, to_wire_dict
from uam.protocol.crypto import deserialize_signing_key, deserialize_verify_key

LEGACY_DB = os.environ.get("UAM_LEGACY_DB")
LEGACY_JSON = os.environ.get("UAM_LEGACY_JSON")

pytestmark = pytest.mark.skipif(
    not (LEGACY_DB and LEGACY_JSON),
    reason="UAM_LEGACY_DB / UAM_LEGACY_JSON not set (CI builds them with youam 1.0.1)",
)


def _wheel_alembic_lookup(_database_url):
    # What an installed youam does: the wheel has no alembic.ini, and the
    # lookup exits.
    raise SystemExit(1)


@pytest.fixture(params=["checkout", "installed"])
def legacy_client(request, tmp_path, monkeypatch):
    db_path = tmp_path / "legacy.db"
    shutil.copy(LEGACY_DB, db_path)
    legacy = json.loads(Path(LEGACY_JSON).read_text())

    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("UAM_DB_PATH", str(db_path))
    monkeypatch.setenv("UAM_RELAY_DOMAIN", "test.local")
    monkeypatch.setenv("UAM_RELAY_KEY_PATH", str(tmp_path / "relay_key.pem"))
    if request.param == "installed":
        import uam.cli.main
        monkeypatch.setattr(uam.cli.main, "_get_alembic_config", _wheel_alembic_lookup)

    import uam.db.engine as _eng
    import uam.db.session as _sess
    _eng._engine = None
    _sess._session_factory = None
    from uam.relay.app import create_app

    with TestClient(create_app()) as client:
        yield client, legacy, db_path

    _eng._engine = None
    _sess._session_factory = None


def _auth(agent: dict) -> dict:
    return {"Authorization": f"Bearer {agent['token']}"}


def test_the_relay_starts_and_has_every_current_table(legacy_client):
    client, legacy, db_path = legacy_client
    assert legacy["version"] == "1.0.1"

    assert client.get("/health").status_code == 200
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        tables = set(sa.inspect(engine).get_table_names())
    finally:
        engine.dispose()
    assert set(SQLModel.metadata.tables) <= tables


def test_mail_and_tokens_from_1_0_1_still_work(legacy_client):
    client, legacy, _ = legacy_client
    alice, bob = legacy["agents"]["alice"], legacy["agents"]["bob"]

    inbox = client.get(f"/api/v1/inbox/{bob['address']}", headers=_auth(bob))
    assert inbox.status_code == 200, inbox.text
    assert legacy["message_id"] in [m["message_id"] for m in inbox.json()["messages"]]

    envelope = create_envelope(
        from_address=alice["address"],
        to_address=bob["address"],
        message_type=MessageType.MESSAGE,
        payload_plaintext=b"sent by the current relay",
        signing_key=deserialize_signing_key(alice["signing_key"]),
        recipient_verify_key=deserialize_verify_key(bob["public_key"]),
    )
    sent = client.post(
        "/api/v1/send", json={"envelope": to_wire_dict(envelope)}, headers=_auth(alice)
    )
    assert sent.status_code == 200, sent.text
