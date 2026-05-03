"""Postgres-only migration tests (T7.6 + cross-validation for T7.2/T7.3/T7.4).

All tests here require a Postgres testcontainer (or UAM_TEST_POSTGRES_URL env
var). Skipped cleanly when Docker is unavailable. Run with:

    pytest tests/db/test_migrations_postgres.py -m postgres
"""

from __future__ import annotations

import io

import pytest
import sqlalchemy as sa
from alembic import command


pytestmark = pytest.mark.postgres


def _sync_url(postgres_url: str) -> str:
    """testcontainers gives us +asyncpg; many tests need a sync engine."""
    return postgres_url.replace("+asyncpg", "")


def test_postgres_fixture_smoke(postgres_url):
    """Sanity: container is up, sync URL works for trivial query."""
    eng = sa.create_engine(_sync_url(postgres_url))
    with eng.connect() as conn:
        result = conn.execute(sa.text("SELECT 1")).scalar()
        assert result == 1
    eng.dispose()


def test_postgres_upgrade_creates_all_tables(postgres_alembic_cfg, postgres_url):
    """All migrations apply against Postgres + table set matches SQLite test."""
    command.upgrade(postgres_alembic_cfg, "head")
    eng = sa.create_engine(_sync_url(postgres_url))
    with eng.connect() as conn:
        rows = conn.execute(sa.text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name != 'alembic_version' "
            "ORDER BY table_name"
        )).fetchall()
    eng.dispose()
    tables = sorted(r[0] for r in rows)
    # Reuse the canonical list — keep in sync with tests/db/test_migrations.py
    from tests.db.test_migrations import EXPECTED_TABLES
    assert tables == EXPECTED_TABLES


def test_postgres_timestamp_columns_are_tz_aware(postgres_alembic_cfg, postgres_url):
    """T7.4: every datetime column on Postgres MUST be TIMESTAMP WITH TIME ZONE."""
    command.upgrade(postgres_alembic_cfg, "head")
    eng = sa.create_engine(_sync_url(postgres_url))
    with eng.connect() as conn:
        rows = conn.execute(sa.text(
            "SELECT table_name, column_name, data_type FROM information_schema.columns "
            "WHERE table_schema = 'public' AND data_type LIKE 'timestamp%'"
        )).fetchall()
    eng.dispose()
    bad = [(t, c) for t, c, dt in rows if dt != "timestamp with time zone"]
    assert not bad, (
        f"T7.4 contract: every Postgres timestamp column must be 'timestamp with time zone'. "
        f"Tz-naive: {bad}"
    )


def test_postgres_fk_restrict_blocks_agent_delete(postgres_alembic_cfg, postgres_url):
    """T7.3a RESTRICT: insert agent + message; DELETE agent -> IntegrityError.

    47-09 patch: use per-test address + token_hash prefixes ('restrict-*')
    so this test does not collide with sibling tests sharing the same
    session-scoped Postgres container (agents.token_hash has a UNIQUE
    index from migration 0003).
    """
    command.upgrade(postgres_alembic_cfg, "head")
    eng = sa.create_engine(_sync_url(postgres_url))
    with eng.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO agents (address, public_key, token_hash, status) "
            "VALUES ('restrict-alice::test.local', 'pk', 'restrict-hash-a', 'active')"
        ))
        conn.execute(sa.text(
            "INSERT INTO agents (address, public_key, token_hash, status) "
            "VALUES ('restrict-bob::test.local', 'pk', 'restrict-hash-b', 'active')"
        ))
        conn.execute(sa.text(
            "INSERT INTO messages (message_id, envelope, status, from_addr, to_addr, retry_count) "
            "VALUES ('restrict-m1', '{}', 'queued', 'restrict-alice::test.local', "
            "'restrict-bob::test.local', 0)"
        ))
    from sqlalchemy.exc import IntegrityError
    with pytest.raises(IntegrityError):
        with eng.begin() as conn:
            conn.execute(sa.text(
                "DELETE FROM agents WHERE address = 'restrict-alice::test.local'"
            ))
    eng.dispose()


def test_postgres_fk_cascade_deletes_seen_messages(postgres_alembic_cfg, postgres_url):
    """T7.3a CASCADE: delete agent -> seen_message_ids rows gone.

    47-09 patch: use per-test 'cascade-*' prefixes for address + token_hash to
    avoid UNIQUE collisions with sibling tests on the session-scoped container.
    Verifies the SPECIFIC seen_message_ids row tied to this test (not a global
    COUNT(*) which would mix in sibling test data).
    """
    command.upgrade(postgres_alembic_cfg, "head")
    eng = sa.create_engine(_sync_url(postgres_url))
    with eng.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO agents (address, public_key, token_hash, status) "
            "VALUES ('cascade-alice::test.local', 'pk', 'cascade-hash', 'active')"
        ))
        conn.execute(sa.text(
            "INSERT INTO seen_message_ids (message_id, from_addr) "
            "VALUES ('cascade-seen-1', 'cascade-alice::test.local')"
        ))
    with eng.begin() as conn:
        conn.execute(sa.text(
            "DELETE FROM agents WHERE address = 'cascade-alice::test.local'"
        ))
    with eng.connect() as conn:
        n = conn.execute(sa.text(
            "SELECT COUNT(*) FROM seen_message_ids "
            "WHERE from_addr = 'cascade-alice::test.local'"
        )).scalar()
    eng.dispose()
    assert n == 0


def test_postgres_fk_set_null_on_audit_log(postgres_alembic_cfg, postgres_url):
    """T7.3a SET NULL: delete actor agent -> audit_log.actor_address NULL.

    47-09 patch: per-test 'setnull-*' prefixes for the same UNIQUE-collision
    reason as the sibling FK tests above.
    """
    command.upgrade(postgres_alembic_cfg, "head")
    eng = sa.create_engine(_sync_url(postgres_url))
    with eng.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO agents (address, public_key, token_hash, status) "
            "VALUES ('setnull-alice::test.local', 'pk', 'setnull-hash', 'active')"
        ))
        conn.execute(sa.text(
            "INSERT INTO audit_log (entity_type, entity_id, action, actor_address) "
            "VALUES ('agent', 'setnull-alice::test.local', 'register', "
            "'setnull-alice::test.local')"
        ))
    with eng.begin() as conn:
        conn.execute(sa.text(
            "DELETE FROM agents WHERE address = 'setnull-alice::test.local'"
        ))
    with eng.connect() as conn:
        row = conn.execute(sa.text(
            "SELECT actor_address FROM audit_log "
            "WHERE entity_id = 'setnull-alice::test.local'"
        )).fetchone()
    eng.dispose()
    assert row is not None, "Audit log entry MUST survive actor deletion"
    assert row[0] is None, "actor_address must be NULL after referenced agent deleted"


def test_postgres_server_default_created_at(postgres_alembic_cfg, postgres_url):
    """T7.4a: INSERT INTO agents WITHOUT created_at -> row has populated created_at.

    47-09 patch: per-test 'srv-*' prefixes for the same UNIQUE-collision
    reason as the sibling tests. The server_default DDL is set by alembic
    migration 0008_server_default_timestamps (added in 47-09 to close the
    gap left by 47-06 — model edits declared server_default but the type-only
    migration 0005 never emitted ``ALTER COLUMN ... SET DEFAULT now()`` DDL).
    """
    command.upgrade(postgres_alembic_cfg, "head")
    eng = sa.create_engine(_sync_url(postgres_url))
    with eng.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO agents (address, public_key, token_hash, status) "
            "VALUES ('srv-default::test.local', 'pk', 'srv-default-hash', 'active')"
        ))
    with eng.connect() as conn:
        row = conn.execute(sa.text(
            "SELECT created_at, updated_at FROM agents "
            "WHERE address = 'srv-default::test.local'"
        )).fetchone()
    eng.dispose()
    assert row[0] is not None, "created_at must be populated by server_default=func.now()"
    assert row[1] is not None, "updated_at must be populated by server_default=func.now()"


def test_no_table_recreates_on_postgres(postgres_alembic_cfg, postgres_url):
    """T7.2: alembic upgrade on Postgres must NOT leave _alembic_tmp_* / _bk / _old tables.

    These statements are the destructive batch-mode rewrite signature; render_as_batch=False
    on Postgres prevents them.
    """
    command.upgrade(postgres_alembic_cfg, "head")
    eng = sa.create_engine(_sync_url(postgres_url))
    with eng.connect() as conn:
        backup_tables = conn.execute(sa.text(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = 'public' AND ("
            "table_name LIKE '%_bk' OR table_name LIKE '%_old' "
            "OR table_name LIKE '_alembic_tmp_%')"
        )).fetchall()
    eng.dispose()
    assert not backup_tables, (
        f"T7.2 contract: render_as_batch=True on Postgres leaves _bk/_old/_alembic_tmp_* "
        f"backup tables. Found: {backup_tables}. Confirm dialect-gating in env.py."
    )
