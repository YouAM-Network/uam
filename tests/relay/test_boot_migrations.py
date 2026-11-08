"""A relay on a real database doesn't start on a schema it couldn't migrate."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from uam.relay.app import create_app


@pytest.fixture()
def failing_migration():
    with patch("alembic.command.upgrade", side_effect=RuntimeError("migration failed")):
        yield


def test_a_failed_migration_stops_the_boot_on_postgres(
    tmp_path, monkeypatch, failing_migration
):
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://u:p@127.0.0.1:1/none")
    monkeypatch.setenv("UAM_RELAY_DOMAIN", "test.local")
    monkeypatch.setenv("UAM_RELAY_KEY_PATH", str(tmp_path / "relay_key.pem"))

    with patch("uam.db.session.create_tables", AsyncMock()) as create_tables:
        with pytest.raises(RuntimeError, match="migration failed"):
            with TestClient(create_app()):
                pass

    create_tables.assert_not_awaited()


def test_sqlite_still_falls_back_to_create_tables(
    tmp_path, monkeypatch, failing_migration
):
    db_path = tmp_path / "relay.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{db_path}")
    monkeypatch.setenv("UAM_DB_PATH", str(db_path))
    monkeypatch.setenv("UAM_RELAY_DOMAIN", "test.local")
    monkeypatch.setenv("UAM_RELAY_KEY_PATH", str(tmp_path / "relay_key.pem"))

    with TestClient(create_app()) as client:
        assert client.get("/health").status_code == 200
