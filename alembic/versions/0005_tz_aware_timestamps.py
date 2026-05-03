"""tz_aware_timestamps

Revision ID: 0005_tz_aware_timestamps
Revises: 0004_add_federation_nonces
Create Date: 2026-05-04

Phase 47 T7.4 + T7.3b: convert all 41 datetime columns from
``TIMESTAMP WITHOUT TIME ZONE`` to ``TIMESTAMP WITH TIME ZONE`` on Postgres.

The ``USING (col AT TIME ZONE 'UTC')`` clause is REQUIRED — Postgres won't
auto-cast naive → tz-aware (the conversion semantics are ambiguous: which
timezone?). We treat existing naive values as UTC (the codebase uses
``datetime.utcnow()`` consistently — verified by grep across src/).

SQLite is a no-op: aiosqlite stores datetimes as ISO-8601 text regardless
of the column type, and SQLite has no native ``TIMESTAMP WITH TIME ZONE``
type. The model edit (``sa_column=Column(DateTime(timezone=True), ...)``)
informs SQLAlchemy to attach UTC tz to read values, but no DDL is needed.

Migration ordering: revises ``0004_add_federation_nonces`` (Phase 45 head).
Subsequent migrations (``0006_foreign_keys`` in 47-07, ``0007_drop_token_plaintext``
in 47-08) revise ``0005_tz_aware_timestamps``.

Source: .planning/phases/47-.../47-RESEARCH.md § Pattern 4 + Code Example 2.
Pitfall reference: § Pitfall 3 (USING clause required for naive→tz-aware).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "0005_tz_aware_timestamps"
down_revision = "0004_add_federation_nonces"
branch_labels = None
depends_on = None


# (table, column, nullable) — 41 columns across 19 tables.
# Census verified by grepping src/uam/db/models.py for `datetime` field
# annotations. Includes federation_nonces.seen_at (added in Phase 45's
# 0004 migration).
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
    ("federation_nonces", "seen_at", False),
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


def upgrade() -> None:
    """Convert every datetime column to TIMESTAMP WITH TIME ZONE on Postgres.

    On SQLite, this is a no-op — aiosqlite stores timestamps as ISO-8601
    text regardless of the column type declaration.
    """
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for table, column, _nullable in DATETIME_COLUMNS:
        op.execute(sa.text(
            f"ALTER TABLE {table} "
            f"ALTER COLUMN {column} TYPE TIMESTAMP WITH TIME ZONE "
            f"USING ({column} AT TIME ZONE 'UTC')"
        ))


def downgrade() -> None:
    """Reverse the type change on Postgres; no-op on SQLite.

    The ``AT TIME ZONE 'UTC'`` clause is symmetric — it converts a
    ``TIMESTAMP WITH TIME ZONE`` value to a ``TIMESTAMP WITHOUT TIME ZONE``
    by stripping the offset and storing the UTC instant as naive.
    """
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for table, column, _nullable in DATETIME_COLUMNS:
        op.execute(sa.text(
            f"ALTER TABLE {table} "
            f"ALTER COLUMN {column} TYPE TIMESTAMP WITHOUT TIME ZONE "
            f"USING ({column} AT TIME ZONE 'UTC')"
        ))
