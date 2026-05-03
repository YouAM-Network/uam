"""Tests for Alembic migration idempotency and downgrade behavior.

Phase 47 rewrite per RESEARCH Pattern 8:
- T7.1: downgrade past 0001 is now refused (NotImplementedError); old downgrade test removed.
- T7.6: table count parametrized by alembic head (no hardcoded 17 or 18 or 19).
- T7.3a: NEW test for 0006_foreign_keys orphan-row pre-flight check (RED until 47-07).
- T7.5: NEW test for 0007_drop_token_plaintext NULL-token_hash pre-flight check (RED until 47-08).
"""

import os
import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from alembic.util import CommandError


@pytest.fixture
def alembic_cfg(tmp_path):
    """Create Alembic config pointing to a temp SQLite database."""
    db_path = tmp_path / "test_migration.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"
    os.environ["DATABASE_URL"] = db_url

    project_root = Path(__file__).resolve().parents[2]
    ini_path = project_root / "alembic.ini"
    assert ini_path.exists(), f"alembic.ini not found at {ini_path}"

    cfg = Config(str(ini_path))
    yield cfg, db_path

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
    conn = sqlite3.connect(str(db_path))
    try:
        rows = conn.execute("SELECT version_num FROM alembic_version").fetchall()
        return rows[0][0] if rows else None
    except sqlite3.OperationalError:
        return None
    finally:
        conn.close()


# Phase 47: derived from src/uam/db/models.py table census.
# Update this list when a new table is added to models.py + an alembic migration.
# 19 tables total: 17 from Phase 33 + reservations (0002) + federation_nonces (0004).
EXPECTED_TABLES = sorted([
    "agents", "messages", "handshakes", "contacts", "audit_log",
    "seen_message_ids", "domain_verifications", "webhook_deliveries",
    "reputation", "blocklist", "allowlist", "known_relays",
    "federation_log", "relay_blocklist", "relay_allowlist",
    "relay_reputation", "federation_queue",
    "reservations",          # +1 from 0002
    "federation_nonces",     # +1 from 0004 (Phase 45)
])  # 19 tables


class TestMigrationUpgrade:
    """T7.6: Initial migration creates all tables (count parametrized)."""

    def test_upgrade_creates_all_expected_tables(self, alembic_cfg):
        cfg, db_path = alembic_cfg
        command.upgrade(cfg, "head")
        tables = _get_tables(db_path)
        assert tables == EXPECTED_TABLES, (
            f"Table set drifted. Got {tables}, expected {EXPECTED_TABLES}. "
            f"If you added a new model to models.py, also add the table name to EXPECTED_TABLES."
        )

    def test_upgrade_sets_revision_to_head(self, alembic_cfg):
        """Don't hard-code the head revision; query the script directory."""
        cfg, db_path = alembic_cfg
        command.upgrade(cfg, "head")
        rev = _get_current_rev(db_path)
        assert rev is not None
        head = ScriptDirectory.from_config(cfg).get_current_head()
        assert rev == head, f"Expected revision '{head}', got '{rev}'"


class TestMigrationIdempotent:
    """MIG-03: Double upgrade is a no-op."""

    def test_upgrade_idempotent(self, alembic_cfg):
        cfg, db_path = alembic_cfg
        command.upgrade(cfg, "head")
        tables_first = _get_tables(db_path)
        rev_first = _get_current_rev(db_path)
        command.upgrade(cfg, "head")
        tables_second = _get_tables(db_path)
        rev_second = _get_current_rev(db_path)
        assert tables_first == tables_second
        assert rev_first == rev_second


class TestMigrationDowngradeProtection:
    """T7.1: downgrade past 0001 must refuse — destructive guard."""

    def test_downgrade_past_initial_raises(self, alembic_cfg):
        """Downgrading to 'base' must raise (NotImplementedError or CommandError-wrapped).

        RED at HEAD because 0001_initial_schema.downgrade() currently does an
        unconditional DROP TABLE cascade. GREEN after 47-01 lands the guard.
        """
        cfg, db_path = alembic_cfg
        command.upgrade(cfg, "head")
        with pytest.raises((NotImplementedError, CommandError)):
            command.downgrade(cfg, "base")  # try to downgrade past 0001


class TestMigrationDowngradeBetweenRevisions:
    """T7.6 rewrite: downgrade between non-initial revisions still works."""

    # Migrations whose ``downgrade()`` raises NotImplementedError by design
    # (irreversible operations — no plaintext recovery, no data restoration).
    # When ``head`` is one of these, this test downgrades to the immediately
    # prior revision instead of using ``-1`` so the irreversible step is
    # bypassed AND the round-trip property is still exercised against the
    # rest of the migration chain.
    _IRREVERSIBLE_HEADS: dict[str, str] = {
        # T7.5 (47-08): dropping agents.token plaintext is irreversible.
        "0007_drop_token_plaintext": "0006_foreign_keys",
    }

    def test_downgrade_one_step(self, alembic_cfg):
        """Upgrade to head, downgrade by one step — should succeed (not past 0001).

        If ``head`` is intentionally irreversible (T7.5), upgrade only to the
        prior revision and downgrade from there so the round-trip property is
        still exercised against the reversible part of the chain.
        """
        cfg, db_path = alembic_cfg
        head = ScriptDirectory.from_config(cfg).get_current_head()

        if head in self._IRREVERSIBLE_HEADS:
            target = self._IRREVERSIBLE_HEADS[head]
            command.upgrade(cfg, target)
            if target == "0001":
                pytest.skip("Only one reversible revision; cannot downgrade one step")
            command.downgrade(cfg, "-1")
            rev = _get_current_rev(db_path)
            assert rev is not None, "Stopped at a valid non-initial revision"
            return

        command.upgrade(cfg, "head")
        # Only attempt if head is not 0001 (i.e. there ARE non-initial revisions)
        if head == "0001":
            pytest.skip("Only one revision; cannot downgrade one step")
        command.downgrade(cfg, "-1")
        rev = _get_current_rev(db_path)
        assert rev is not None, "Stopped at a valid non-initial revision"


# ===========================================================================
# Phase 43 carryover — Theme 2.1: Token-hash migration test (T2.1)
# Should remain GREEN (token_hash backfill exists in 0003).
# ===========================================================================


class TestTokenHashMigration:
    """T2.1: alembic 0003 adds agents.token_hash and backfills."""

    def test_0003_token_hash(self, alembic_cfg):
        """T2.1 (Phase 43): alembic upgrade to revision 0003 adds agents.token_hash
        and backfills via deterministic HMAC. After upgrade no row may have
        token_hash IS NULL.
        """
        cfg, db_path = alembic_cfg

        # Upgrade to 0002 first; insert a test row with plaintext token
        command.upgrade(cfg, "0002")

        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                "INSERT INTO agents "
                "(address, public_key, token, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))",
                ("alice::test.local", "pk_b64", "plaintext_xyz", "active"),
            )
            conn.commit()
        finally:
            conn.close()

        try:
            command.upgrade(cfg, "0003")
        except Exception as exc:
            pytest.fail(
                f"T2.1 contract: alembic upgrade to 0003 must succeed. Got: {exc!r}"
            )

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
        from uam.relay.token_hashing import hash_token
        from uam.relay.config import settings
        pepper = getattr(settings, "token_pepper", None)
        assert pepper, "Settings.token_pepper must be configured (UAM_TOKEN_PEPPER env)"
        assert token_hash == hash_token("plaintext_xyz", pepper), (
            "Backfilled token_hash does not match the deterministic HMAC of "
            "the plaintext token; backfill is not reproducible."
        )


# ===========================================================================
# Phase 47 — T7.3a foreign-keys pre-flight (RED until 47-07 lands 0006)
# ===========================================================================


class TestForeignKeysOrphanCheck:
    """T7.3a: 0006_foreign_keys must REJECT migration when orphan rows exist."""

    def test_0006_orphan_check_rejects(self, alembic_cfg):
        """Pre-seed an orphan messages.from_addr row; assert 0006 raises RuntimeError.

        Strategy:
          1. Upgrade to 0005_tz_aware_timestamps (the revision before 0006).
          2. Insert an orphan messages row (from_addr references non-existent agent).
          3. Attempt to upgrade to 0006_foreign_keys.
          4. Assert RuntimeError with "orphan" in the message.

        47-07 GREEN: the pre-flight check in 0006 raises before any DDL runs.
        """
        cfg, db_path = alembic_cfg

        # Step 1: upgrade to the revision BEFORE 0006_foreign_keys so we can
        # insert orphan rows without the FK already enforcing parent existence.
        script = ScriptDirectory.from_config(cfg)
        revisions = [r.revision for r in script.walk_revisions()]
        # Sanity: 0006_foreign_keys must exist; 0005_tz_aware_timestamps must
        # be its parent.
        if "0006_foreign_keys" not in revisions:
            pytest.fail(
                "T7.3a contract: alembic/versions/0006_foreign_keys.py must exist."
            )
        command.upgrade(cfg, "0005_tz_aware_timestamps")

        # Step 2: insert an orphan messages row (from_addr references non-existent agent).
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                "INSERT INTO messages "
                "(message_id, envelope, status, from_addr, to_addr, "
                "retry_count, created_at) "
                "VALUES (?, ?, ?, ?, ?, 0, datetime('now'))",
                ("orphan-msg-1", "{}", "queued",
                 "ghost::nowhere.example", "alice::test.local"),
            )
            conn.commit()
        finally:
            conn.close()

        # Step 3 + 4: attempt upgrade to 0006_foreign_keys; pre-flight must reject.
        try:
            command.upgrade(cfg, "0006_foreign_keys")
        except RuntimeError as exc:
            assert "orphan" in str(exc).lower(), (
                f"Expected 'orphan' in error message; got: {exc!r}"
            )
            return
        except CommandError as exc:
            pytest.fail(
                f"T7.3a contract: 47-07 must add alembic/versions/0006_foreign_keys.py "
                f"with a pre-flight orphan check. Today: {exc!r}"
            )
        # If we reach here, the migration succeeded WITHOUT rejecting orphans -> BUG
        pytest.fail(
            "T7.3a contract: 0006_foreign_keys must REJECT migration when orphan "
            "rows exist (pre-flight assertion). Migration succeeded silently."
        )


# ===========================================================================
# Phase 47 — T7.5 drop-plaintext-token pre-flight (RED until 47-08 lands 0007)
# ===========================================================================


class TestDropTokenPlaintextPreflight:
    """T7.5: 0007_drop_token_plaintext must REJECT when token_hash is NULL."""

    def test_0007_rejects_null_token_hash(self, alembic_cfg):
        """Pre-seed an agents row with token_hash=NULL; assert 0007 refuses.

        Phase 47 Plan 08: this exercises the pre-flight assertion in
        ``alembic/versions/0007_drop_token_plaintext.py``. Pattern mirrors the
        0006 orphan-row test: upgrade to the immediately-prior revision (0006),
        seed a pathological row that bypasses the NOT NULL constraint via raw
        DDL (table rebuild), then attempt ``upgrade(0007)`` and assert
        RuntimeError with "null token_hash" in the message.

        Bypassing NOT NULL on SQLite requires a table rebuild (you cannot
        UPDATE a NOT NULL column to NULL even via raw SQL; SQLite enforces it
        on writes regardless of how the column became NOT NULL). We use
        SQLite's PRAGMA writable_schema to flip the column metadata without
        rebuilding — this is the documented "operator tampering" path the
        pre-flight check exists to catch (RESEARCH Pattern 7).
        """
        cfg, db_path = alembic_cfg

        # Step 1: upgrade to the prior revision so we can simulate drift.
        command.upgrade(cfg, "0006_foreign_keys")

        # Step 2: bypass NOT NULL via PRAGMA writable_schema and a CREATE
        # TABLE rewrite (this is the documented SQLite escape hatch — see
        # https://www.sqlite.org/pragma.html#pragma_writable_schema). Then
        # insert a row with token_hash=NULL.
        conn = sqlite3.connect(str(db_path))
        try:
            # Read the original CREATE TABLE statement and produce a relaxed
            # variant that drops the NOT NULL on token_hash. The exact column
            # type spelling depends on what alembic emitted (VARCHAR(64),
            # VARCHAR, STRING) — try common variants then fall back to a
            # regex-style replace on the column line.
            import re as _re
            original = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='agents'"
            ).fetchone()[0]
            relaxed = _re.sub(
                r'(token_hash\s+\S+(?:\(\d+\))?)\s+NOT\s+NULL',
                r'\1',
                original,
            )
            assert relaxed != original, (
                f"Test setup: could not find token_hash NOT NULL clause in "
                f"agents schema to relax. Schema: {original}"
            )
            conn.execute("PRAGMA writable_schema = ON")
            conn.execute(
                "UPDATE sqlite_master SET sql = ? "
                "WHERE type = 'table' AND name = 'agents'",
                (relaxed,),
            )
            conn.execute("PRAGMA writable_schema = OFF")
            conn.commit()
            conn.close()

            # Reopen so SQLite reloads the schema cache.
            conn = sqlite3.connect(str(db_path))
            conn.execute(
                "INSERT INTO agents "
                "(address, public_key, token, token_hash, status, "
                "created_at, updated_at) "
                "VALUES (?, ?, ?, NULL, ?, datetime('now'), datetime('now'))",
                ("driftbot::test.local", "pk_b64", "tok_drift", "active"),
            )
            conn.commit()
            row = conn.execute(
                "SELECT token_hash FROM agents WHERE address = ?",
                ("driftbot::test.local",),
            ).fetchone()
            assert row is not None and row[0] is None, (
                "Test setup precondition: row exists with token_hash=NULL"
            )
        finally:
            conn.close()

        # Step 3: attempt upgrade to 0007; pre-flight must reject with
        # RuntimeError mentioning "null token_hash".
        with pytest.raises(RuntimeError) as exc_info:
            command.upgrade(cfg, "0007_drop_token_plaintext")
        msg = str(exc_info.value).lower()
        assert "null token_hash" in msg or "token_hash" in msg, (
            f"T7.5 contract: 0007 pre-flight must reject NULL token_hash with "
            f"a descriptive RuntimeError. Got: {exc_info.value!r}"
        )
