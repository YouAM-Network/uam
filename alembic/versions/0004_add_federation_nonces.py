"""add_federation_nonces

Revision ID: 0004_add_federation_nonces
Revises: 0003
Create Date: 2026-05-02

Phase 45 T3.2: ``federation_nonces`` table for relay-to-relay nonce dedup.

The ``(from_relay, nonce)`` COMPOSITE PRIMARY KEY guarantees atomic
INSERT-or-conflict — a second insert of the same pair raises
``IntegrityError`` and the route layer turns that into HTTP 409.

Per-relay scope is intentional: relay-A and relay-B may legitimately both
emit the same random 22-char nonce string and neither is replaying the
other.

Cross-DB: this migration uses ``sa.String`` and ``sa.DateTime`` only — no
JSONB, no PG-specific types — so it applies cleanly on both PostgreSQL
and SQLite. ``server_default=sa.func.now()`` is portable.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "0004_add_federation_nonces"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "federation_nonces",
        sa.Column("from_relay", sa.String(length=255), nullable=False),
        sa.Column("nonce", sa.String(length=64), nullable=False),
        sa.Column(
            "seen_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint(
            "from_relay", "nonce", name="pk_federation_nonces"
        ),
    )
    op.create_index(
        "ix_federation_nonces_seen_at",
        "federation_nonces",
        ["seen_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_federation_nonces_seen_at", table_name="federation_nonces"
    )
    op.drop_table("federation_nonces")
