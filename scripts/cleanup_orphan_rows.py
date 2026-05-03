#!/usr/bin/env python3
"""Detect and (optionally) clean orphan rows referencing non-existent agents.address.

Phase 47 — RESEARCH OQ5 + Assumption A3: production likely has orphan rows from
the pre-FK era that would block alembic 0006_foreign_keys mid-flight. Operators
MUST run this script BEFORE applying 0006 in production.

Usage:
    # Dry-run (default — reports counts, no changes):
    python scripts/cleanup_orphan_rows.py --database-url $DATABASE_URL

    # Commit deletions:
    python scripts/cleanup_orphan_rows.py --database-url $DATABASE_URL --commit

Exit codes:
    0 — no orphans found OR cleanup succeeded
    1 — error (DB unreachable, schema mismatch, etc.)
"""

from __future__ import annotations

import argparse
import sys


# (child_table, child_column, parent_table, parent_pk_column)
# Mirrors the FK list from RESEARCH Pattern 3 / Code Examples Example 1.
ORPHAN_CHECKS: list[tuple[str, str, str, str]] = [
    ("messages", "from_addr", "agents", "address"),
    ("messages", "to_addr", "agents", "address"),
    ("contacts", "owner_address", "agents", "address"),
    ("contacts", "contact_address", "agents", "address"),
    ("handshakes", "from_addr", "agents", "address"),
    ("handshakes", "to_addr", "agents", "address"),
    ("webhook_deliveries", "agent_address", "agents", "address"),
    ("domain_verifications", "agent_address", "agents", "address"),
    ("seen_message_ids", "from_addr", "agents", "address"),
    ("reputation", "address", "agents", "address"),
    ("audit_log", "actor_address", "agents", "address"),
    # NOTE: reservations.address has NO FK (RESEARCH OQ3); not checked here.
]


def _open_sync(url: str):
    """Return a sync SQLAlchemy engine + connection from any URL.

    Strips the async driver prefixes so we get a sync engine; install the
    matching sync driver yourself (psycopg2 for postgres, sqlite3 stdlib for
    sqlite). Async URLs are routed to their sync equivalents transparently.
    """
    import sqlalchemy as sa
    sync_url = url.replace("+aiosqlite", "").replace("+asyncpg", "")
    engine = sa.create_engine(sync_url)
    return engine, engine.connect()


def find_orphans(conn, child_table, child_col, parent_table, parent_col) -> int:
    """Count orphan rows in child_table.child_col not in parent_table.parent_col.

    NULL values are NOT orphans (FK is nullable for SET NULL columns).
    """
    import sqlalchemy as sa
    sql = sa.text(
        f"SELECT COUNT(*) FROM {child_table} "
        f"WHERE {child_col} IS NOT NULL "
        f"AND {child_col} NOT IN (SELECT {parent_col} FROM {parent_table})"
    )
    return int(conn.execute(sql).scalar() or 0)


def delete_orphans(conn, child_table, child_col, parent_table, parent_col) -> int:
    """DELETE orphan rows; return rowcount."""
    import sqlalchemy as sa
    sql = sa.text(
        f"DELETE FROM {child_table} "
        f"WHERE {child_col} IS NOT NULL "
        f"AND {child_col} NOT IN (SELECT {parent_col} FROM {parent_table})"
    )
    result = conn.execute(sql)
    return int(result.rowcount or 0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--database-url", required=True, help="SQLAlchemy URL")
    parser.add_argument(
        "--commit", action="store_true",
        help="Actually delete orphans (default: dry-run)",
    )
    args = parser.parse_args(argv)

    try:
        engine, conn = _open_sync(args.database_url)
    except Exception as exc:
        print(f"ERROR: cannot connect to {args.database_url!r}: {exc}", file=sys.stderr)
        return 1

    total_orphans = 0
    total_deleted = 0
    print(f"Phase 47 orphan-row report (mode: {'COMMIT' if args.commit else 'DRY-RUN'})")
    print("=" * 70)
    try:
        for child_table, child_col, parent_table, parent_col in ORPHAN_CHECKS:
            try:
                count = find_orphans(conn, child_table, child_col, parent_table, parent_col)
            except Exception as exc:
                # Table might not exist yet (running before alembic upgrade); skip
                print(f"  SKIP {child_table}.{child_col}: {exc}", file=sys.stderr)
                continue
            total_orphans += count
            if count > 0:
                print(f"  {child_table:25s}.{child_col:18s} -> {count} orphan rows")
                if args.commit:
                    deleted = delete_orphans(conn, child_table, child_col, parent_table, parent_col)
                    total_deleted += deleted
                    conn.commit()
                    print(f"    DELETED {deleted}")
        print("=" * 70)
        if total_orphans == 0:
            print("Result: 0 orphan rows — database is clean. Safe to run 0006_foreign_keys.")
        elif args.commit:
            print(f"Result: deleted {total_deleted} orphan rows. Re-run --dry-run to verify.")
        else:
            print(f"Result: {total_orphans} orphan rows found. Re-run with --commit to delete.")
        return 0
    finally:
        conn.close()
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
