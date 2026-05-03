"""Failing-by-design tests for scripts/cleanup_orphan_rows.py helper.

Per RESEARCH A3 + OQ5: production likely has orphan rows from the pre-FK era
that would block alembic 0006_foreign_keys mid-flight. Operators MUST run
this script BEFORE applying 0006 in production.

These tests GREEN at HEAD (the script ships in this same plan / Task 3) — the
RED-by-design pieces are the FK migration tests; the script's tests are
positive contracts that lock in its dry-run / commit / re-run-clean behavior.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "cleanup_orphan_rows.py"


@pytest.fixture
def db_with_orphans(tmp_path):
    """Spin up SQLite at alembic head; insert 2 orphan rows."""
    db_path = tmp_path / "orphan.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"
    os.environ["DATABASE_URL"] = db_url
    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    command.upgrade(cfg, "head")

    conn = sqlite3.connect(str(db_path))
    # Insert orphan messages (from_addr references non-existent agent).
    # Pre-T7.5, agents.token is NOT NULL; we don't insert agents here on purpose
    # so the orphan rows reference non-existent agents.
    conn.execute(
        "INSERT INTO messages (message_id, envelope, status, from_addr, to_addr, "
        "retry_count, created_at) VALUES (?, ?, ?, ?, ?, 0, datetime('now'))",
        ("orphan-1", "{}", "queued", "ghost::nowhere.example",
         "ghost2::nowhere.example"),
    )
    conn.execute(
        "INSERT INTO messages (message_id, envelope, status, from_addr, to_addr, "
        "retry_count, created_at) VALUES (?, ?, ?, ?, ?, 0, datetime('now'))",
        ("orphan-2", "{}", "queued", "another-ghost::nowhere.example",
         "ghost3::nowhere.example"),
    )
    conn.commit()
    conn.close()

    yield db_path, db_url
    os.environ.pop("DATABASE_URL", None)


def test_dry_run_reports_orphans(db_with_orphans):
    """--dry-run (default) MUST report orphan counts and MUST NOT delete."""
    db_path, db_url = db_with_orphans
    if not SCRIPT.exists():
        pytest.fail("T7.3a contract: scripts/cleanup_orphan_rows.py must exist; missing.")

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--database-url", db_url],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"Dry-run exit nonzero: {result.stderr}"
    combined = (result.stdout + result.stderr).lower()
    assert "orphan" in combined, (
        f"Dry-run output should mention 'orphan'. stdout={result.stdout!r}, "
        f"stderr={result.stderr!r}"
    )
    # Verify NO deletion happened
    conn = sqlite3.connect(str(db_path))
    n = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    conn.close()
    assert n == 2, f"Dry-run must not delete; expected 2 messages, got {n}"


def test_commit_deletes_orphans(db_with_orphans):
    """--commit MUST delete orphan rows."""
    db_path, db_url = db_with_orphans
    if not SCRIPT.exists():
        pytest.fail("T7.3a contract: scripts/cleanup_orphan_rows.py must exist; missing.")

    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--database-url", db_url, "--commit"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"Commit exit nonzero: {result.stderr}"
    conn = sqlite3.connect(str(db_path))
    n = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
    conn.close()
    assert n == 0, f"Commit must delete; expected 0 messages, got {n}"


def test_second_run_reports_zero(db_with_orphans):
    """After --commit, a second --dry-run reports 0 orphans."""
    db_path, db_url = db_with_orphans
    if not SCRIPT.exists():
        pytest.fail("T7.3a contract: scripts/cleanup_orphan_rows.py must exist; missing.")
    subprocess.run(
        [sys.executable, str(SCRIPT), "--database-url", db_url, "--commit"],
        capture_output=True, text=True, timeout=30,
    )
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--database-url", db_url],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0
    out = (result.stdout + result.stderr).lower()
    assert "0 orphan" in out or "no orphan" in out or "clean" in out, (
        f"Second dry-run should indicate clean state; got stdout={result.stdout!r}, "
        f"stderr={result.stderr!r}"
    )
