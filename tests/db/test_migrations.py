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


# ===========================================================================
# Phase 43 — Theme 2.1: Token-hash migration test (T2.1)
# ===========================================================================
#
# This test is FAILING-BY-DESIGN as of Wave 0. Plan 04 will turn it green by
# creating alembic/versions/0003_token_hash.py adding the token_hash column
# (NOT NULL after backfill) and a deterministic backfill step.
#
# References:
#   - 43-VALIDATION.md row T2.1 (migration)
#   - 43-RESEARCH.md Pattern 1 (Token Hashing) + phase_requirements T2.1 +
#     Pitfall 1 (Token Backfill Race)
#   - REVIEW-routes.md C3
# ===========================================================================


class TestTokenHashMigration:
    """T2.1: alembic 0003 adds agents.token_hash and backfills."""

    def test_0003_token_hash(self, alembic_cfg):
        """T2.1: alembic upgrade to revision 0003 must add agents.token_hash
        and backfill it via deterministic HMAC. After upgrade, no row may
        have token_hash IS NULL.

        Pre-condition: at revision 0002 (current head as of Wave 0),
        an agents row exists with `token = 'plaintext_xyz'`.
        Post-condition: after upgrade to 0003, token_hash is non-NULL and
        equals hash_token(plaintext_xyz, settings.token_pepper).

        Expected behaviour after Plan 04: the migration exists, runs
        cleanly, and leaves no NULL rows.
        Today (Wave 0): the alembic head is '0002' so `command.upgrade(cfg, "0003")`
        raises CommandError. The test FAILS at that line, naming the
        missing artifact in the assertion message.
        """
        cfg, db_path = alembic_cfg

        # Upgrade to 0002 (current head); insert a test row
        command.upgrade(cfg, "0002")

        conn = sqlite3.connect(str(db_path))
        try:
            # 0001 declares created_at/updated_at NOT NULL with no SQLite-side
            # server default; supply explicit values so the row inserts cleanly
            # before we exercise the 0003 backfill logic.
            conn.execute(
                "INSERT INTO agents "
                "(address, public_key, token, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))",
                ("alice::test.local", "pk_b64", "plaintext_xyz", "active"),
            )
            conn.commit()
        finally:
            conn.close()

        # Attempt to upgrade to 0003. Today this is a CommandError because
        # alembic does not know about revision 0003 yet.
        try:
            command.upgrade(cfg, "0003")
        except Exception as exc:
            pytest.fail(
                f"T2.1 contract: Plan 04 must add alembic/versions/0003_token_hash.py "
                f"adding agents.token_hash (TEXT NOT NULL UNIQUE INDEX after backfill) "
                f"and a deterministic HMAC backfill step. Today the migration does "
                f"not exist, so command.upgrade(cfg, '0003') raises: {exc!r}"
            )

        # If 0003 exists and upgrade succeeded, assert backfill worked
        conn = sqlite3.connect(str(db_path))
        try:
            rows = conn.execute(
                "SELECT token, token_hash FROM agents WHERE address = ?",
                ("alice::test.local",),
            ).fetchall()
        finally:
            conn.close()

        assert len(rows) == 1
        token, token_hash = rows[0]
        assert token_hash is not None, (
            "After 0003 upgrade, token_hash must be backfilled non-NULL "
            "for every existing row (Pitfall 1: backfill race)."
        )
        # Determinism check: token_hash must equal HMAC(token, pepper)
        from uam.relay.token_hashing import hash_token
        from uam.relay.config import settings
        pepper = getattr(settings, "token_pepper", None)
        assert pepper, "Settings.token_pepper must be configured (UAM_TOKEN_PEPPER env)"
        assert token_hash == hash_token("plaintext_xyz", pepper), (
            "Backfilled token_hash does not match the deterministic HMAC of "
            "the plaintext token; backfill is not reproducible."
        )
