"""server_default_timestamps

Revision ID: 0008_server_default_timestamps
Revises: 0007_drop_token_plaintext
Create Date: 2026-05-04

Phase 47 T7.6 (gap-fix from 47-06): align Postgres DDL with the model
declarations of ``server_default=func.now()``. Migration 0005 only
changed datetime column TYPES (naive → tz-aware); the model edits in
``src/uam/db/models.py`` (47-06) declared ``server_default`` and
``default_factory`` on every auto-managed timestamp, but Alembic never
emitted ``ALTER COLUMN ... SET DEFAULT now()`` DDL. Result: bare-SQL
INSERTs that omitted ``created_at`` failed with NotNullViolation on
Postgres (e.g. the Wave 0 Postgres testcontainer suite).

This migration emits ``ALTER COLUMN ... SET DEFAULT now()`` for every
column that the model layer declares with ``server_default=func.now()``.
``onupdate=func.now()`` is INTENTIONALLY NOT emitted as DDL — the
on-update behaviour in the codebase is handled at the SQLAlchemy/CRUD
layer (Python-side ``datetime.now(timezone.utc)`` in update statements),
not via a DB-side trigger. Postgres has no built-in onupdate equivalent
short of a PL/pgSQL trigger, which would be a stronger change than the
codebase intends.

Coverage: 24 columns across 18 tables. Census derived by walking
``SQLModel.metadata.tables`` and filtering ``column.server_default is
not None``.

SQLite is a no-op: aiosqlite does not honour ``ALTER COLUMN ... SET
DEFAULT`` and the codebase has no SQLite-side ``DEFAULT`` story for
auto-managed timestamps. Bare-SQL inserts on SQLite either provide
explicit timestamps or use the model's ``default_factory`` via the ORM.

Migration ordering: revises ``0007_drop_token_plaintext`` (Phase 47 head
post-47-08).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "0008_server_default_timestamps"
down_revision = "0007_drop_token_plaintext"
branch_labels = None
depends_on = None


# (table, column) — 24 columns across 18 tables.
# Census derived by introspecting SQLModel.metadata for columns where
# ``column.server_default`` is set in src/uam/db/models.py.
SERVER_DEFAULT_NOW_COLUMNS = [
    ("agents", "created_at"),
    ("agents", "updated_at"),
    ("messages", "created_at"),
    ("handshakes", "created_at"),
    ("contacts", "created_at"),
    ("contacts", "updated_at"),
    ("audit_log", "timestamp"),
    ("seen_message_ids", "seen_at"),
    ("federation_nonces", "seen_at"),
    ("domain_verifications", "verified_at"),
    ("domain_verifications", "last_checked"),
    ("webhook_deliveries", "created_at"),
    ("reputation", "created_at"),
    ("reputation", "updated_at"),
    ("blocklist", "created_at"),
    ("allowlist", "created_at"),
    ("known_relays", "last_verified"),
    ("federation_log", "created_at"),
    ("relay_blocklist", "created_at"),
    ("relay_allowlist", "created_at"),
    ("relay_reputation", "created_at"),
    ("relay_reputation", "updated_at"),
    ("federation_queue", "created_at"),
    ("reservations", "created_at"),
]


def upgrade() -> None:
    """Set DEFAULT now() on every model-declared server_default column.

    On SQLite, this is a no-op — aiosqlite ignores ALTER COLUMN ... SET
    DEFAULT, and the codebase relies on Python-side defaults via the ORM
    or explicit values in raw SQL.
    """
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for table, column in SERVER_DEFAULT_NOW_COLUMNS:
        op.execute(sa.text(
            f"ALTER TABLE {table} ALTER COLUMN {column} SET DEFAULT now()"
        ))


def downgrade() -> None:
    """Drop the DEFAULT now() on every column on Postgres; no-op on SQLite."""
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    for table, column in SERVER_DEFAULT_NOW_COLUMNS:
        op.execute(sa.text(
            f"ALTER TABLE {table} ALTER COLUMN {column} DROP DEFAULT"
        ))
