"""Tests for Alembic migration idempotency and downgrade behavior."""

import os
import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


@pytest.fixture
def alembic_cfg(tmp_path):
    """Create Alembic config pointing to a temp SQLite database."""
    db_path = tmp_path / "test_migration.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"
    os.environ["DATABASE_URL"] = db_url

    # Find alembic.ini from project root
    project_root = Path(__file__).resolve().parents[2]
    ini_path = project_root / "alembic.ini"
    assert ini_path.exists(), f"alembic.ini not found at {ini_path}"

    cfg = Config(str(ini_path))
    yield cfg, db_path

    # Cleanup
    os.environ.pop("DATABASE_URL", None)


def _get_tables(db_path: Path) -> list[str]:
    """Get sorted list of user tables from SQLite database."""
    conn = sqlite3.connect(str(db_path))
    tables = sorted(
        r[0]
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name != 'alembic_version'"
        ).fetchall()
    )
    conn.close()
    return tables


def _get_current_rev(db_path: Path) -> str | None:
    """Get current Alembic revision from database."""
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute("SELECT version_num FROM alembic_version").fetchall()
        return rows[0][0] if rows else None
    except sqlite3.OperationalError:
        return None
    finally:
        conn.close()


class TestMigrationUpgrade:
    """MIG-02: Initial migration creates all tables."""

    def test_upgrade_creates_17_tables(self, alembic_cfg):
        cfg, db_path = alembic_cfg
        command.upgrade(cfg, "head")

        tables = _get_tables(db_path)
        assert len(tables) == 17, f"Expected 17 tables, got {len(tables)}: {tables}"

    def test_upgrade_creates_expected_tables(self, alembic_cfg):
        cfg, db_path = alembic_cfg
        command.upgrade(cfg, "head")

        tables = _get_tables(db_path)
        expected = sorted([
            "agents", "messages", "handshakes", "contacts", "audit_log",
            "seen_message_ids", "domain_verifications", "webhook_deliveries",
            "reputation", "blocklist", "allowlist", "known_relays",
            "federation_log", "relay_blocklist", "relay_allowlist",
            "relay_reputation", "federation_queue",
        ])
        assert tables == expected

    def test_upgrade_sets_revision(self, alembic_cfg):
        cfg, db_path = alembic_cfg
        command.upgrade(cfg, "head")

        rev = _get_current_rev(db_path)
        assert rev is not None, "alembic_version should have a revision after upgrade"
        assert rev == "0001", f"Expected revision '0001', got '{rev}'"


class TestMigrationIdempotent:
    """MIG-03: Double upgrade is a no-op."""

    def test_upgrade_idempotent(self, alembic_cfg):
        cfg, db_path = alembic_cfg

        # First upgrade
        command.upgrade(cfg, "head")
        tables_first = _get_tables(db_path)
        rev_first = _get_current_rev(db_path)

        # Second upgrade (should be no-op)
        command.upgrade(cfg, "head")
        tables_second = _get_tables(db_path)
        rev_second = _get_current_rev(db_path)

        assert tables_first == tables_second
        assert rev_first == rev_second


class TestMigrationDowngrade:
    """MIG-04: Downgrade cleanly drops all tables."""

    def test_downgrade_drops_all_tables(self, alembic_cfg):
        cfg, db_path = alembic_cfg

        # Upgrade first
        command.upgrade(cfg, "head")
        assert len(_get_tables(db_path)) == 17

        # Downgrade
        command.downgrade(cfg, "-1")
        tables = _get_tables(db_path)
        assert len(tables) == 0, f"Expected 0 tables after downgrade, got {len(tables)}: {tables}"

    def test_downgrade_clears_revision(self, alembic_cfg):
        cfg, db_path = alembic_cfg

        command.upgrade(cfg, "head")
        command.downgrade(cfg, "-1")

        rev = _get_current_rev(db_path)
        # After downgrade to base, alembic_version should be empty or None
        assert rev is None, f"Expected no revision after downgrade, got '{rev}'"

    def test_upgrade_after_downgrade(self, alembic_cfg):
        """Verify upgrade -> downgrade -> upgrade cycle works."""
        cfg, db_path = alembic_cfg

        command.upgrade(cfg, "head")
        command.downgrade(cfg, "-1")
        command.upgrade(cfg, "head")

        tables = _get_tables(db_path)
        assert len(tables) == 17
