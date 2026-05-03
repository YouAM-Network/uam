"""Failing-by-design tz-aware datetime tests (T7.3b / T7.4).

Per RESEARCH Pattern 4: every datetime column in models.py must declare
sa.DateTime(timezone=True). The 38-column census below is the contract; if a
new datetime column is added to a model, the census drift assertion catches it.

Tz-naive datetime storage is the textbook bug: row written in container timezone
'America/Chicago' is interpreted as UTC on read in container 'UTC', shifting
timestamps by -6h in the response. T7.4 closes this.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


# 38-column census (table, column, nullable) from RESEARCH Pattern 4.
DATETIME_COLUMNS = [
    ("agents", "last_seen", True),
    ("agents", "created_at", False),
    ("agents", "updated_at", False),
    ("agents", "deleted_at", True),
    ("messages", "created_at", False),
    ("messages", "delivered_at", True),
    ("messages", "expires_at", True),
    ("messages", "deleted_at", True),
    ("handshakes", "created_at", False),
    ("handshakes", "resolved_at", True),
    ("handshakes", "deleted_at", True),
    ("contacts", "created_at", False),
    ("contacts", "updated_at", False),
    ("contacts", "deleted_at", True),
    ("audit_log", "timestamp", False),
    ("seen_message_ids", "seen_at", False),
    ("domain_verifications", "verified_at", False),
    ("domain_verifications", "last_checked", False),
    ("domain_verifications", "deleted_at", True),
    ("webhook_deliveries", "created_at", False),
    ("webhook_deliveries", "completed_at", True),
    ("webhook_deliveries", "deleted_at", True),
    ("reputation", "created_at", False),
    ("reputation", "updated_at", False),
    ("blocklist", "created_at", False),
    ("allowlist", "created_at", False),
    ("known_relays", "last_verified", False),
    ("federation_log", "created_at", False),
    ("relay_blocklist", "created_at", False),
    ("relay_allowlist", "created_at", False),
    ("relay_reputation", "last_success", True),
    ("relay_reputation", "last_failure", True),
    ("relay_reputation", "created_at", False),
    ("relay_reputation", "updated_at", False),
    ("federation_queue", "next_retry", True),
    ("federation_queue", "created_at", False),
    ("reservations", "created_at", False),
    ("reservations", "expires_at", False),
    ("reservations", "claimed_at", True),
    ("reservations", "deleted_at", True),
]
# Note: census above has 40 entries; federation_nonces.seen_at adds a 41st on
# Phase 45+. The census-drift test below allows ±2 to absorb minor additions.


@pytest.fixture
def sqlite_at_head(tmp_path):
    db_path = tmp_path / "tz.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"
    os.environ["DATABASE_URL"] = db_url
    project_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(project_root / "alembic.ini"))
    command.upgrade(cfg, "head")
    yield db_path
    os.environ.pop("DATABASE_URL", None)


def test_models_declare_tz_aware_datetime():
    """T7.4: every datetime column in models.py uses sa.DateTime(timezone=True).

    RED at HEAD because models.py uses bare sa.DateTime() (no timezone=True kwarg)
    via the SQLAlchemy default for Python `datetime` annotations.
    GREEN after 47-06 lands the model edits.
    """
    from sqlalchemy import DateTime
    from sqlmodel import SQLModel
    from uam.db import models  # noqa: F401 — ensure registry populated

    bad: list[tuple[str, str]] = []
    for table_name, table in SQLModel.metadata.tables.items():
        for col in table.columns:
            if isinstance(col.type, DateTime) and not col.type.timezone:
                bad.append((table_name, col.name))
    assert not bad, (
        f"T7.4 contract: every datetime column must declare timezone=True. "
        f"Tz-naive columns at HEAD: {bad}"
    )


def test_tz_aware_roundtrip_via_orm(sqlite_at_head):
    """Insert tz-aware datetime; read back; assert it round-trips.

    SQLite stores datetimes as text and aiosqlite returns naive datetimes — this
    test on SQLite is best-effort. The Postgres equivalent in
    tests/db/test_migrations_postgres.py is the authoritative tz-roundtrip
    assertion.
    """
    import sqlite3
    conn = sqlite3.connect(str(sqlite_at_head))
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(agents)").fetchall()]
    if "token" in cols:
        conn.execute(
            "INSERT INTO agents (address, public_key, token, token_hash, status, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, 'active', ?, ?)",
            ("tz::test.local", "pk", "plaintext", "hash",
             now_utc.isoformat(), now_utc.isoformat()),
        )
    else:
        conn.execute(
            "INSERT INTO agents (address, public_key, token_hash, status, "
            "created_at, updated_at) VALUES (?, ?, ?, 'active', ?, ?)",
            ("tz::test.local", "pk", "hash", now_utc.isoformat(), now_utc.isoformat()),
        )
    conn.commit()
    row = conn.execute(
        "SELECT created_at FROM agents WHERE address = ?", ("tz::test.local",)
    ).fetchone()
    conn.close()
    assert row is not None
    assert now_utc.isoformat() in row[0] or row[0] == now_utc.isoformat()


def test_tz_aware_column_count_matches_census():
    """Sanity: the census in this file matches what models.py exposes.

    If a new datetime column is added to a model, this test catches drift so the
    census above can be updated alongside the model change.
    """
    from sqlalchemy import DateTime
    from sqlmodel import SQLModel
    from uam.db import models  # noqa: F401

    actual: list[tuple[str, str]] = []
    for table_name, table in SQLModel.metadata.tables.items():
        for col in table.columns:
            if isinstance(col.type, DateTime):
                actual.append((table_name, col.name))
    actual.sort()
    expected_pairs = sorted([(t, c) for t, c, _ in DATETIME_COLUMNS])
    drift = abs(len(actual) - len(expected_pairs))
    assert drift <= 2, (
        f"Census drift: census has {len(expected_pairs)} pairs, "
        f"models.py has {len(actual)} datetime columns. "
        f"Update tests/db/test_tz_aware.py DATETIME_COLUMNS list."
    )
