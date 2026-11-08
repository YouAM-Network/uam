"""add_routed_messages

Revision ID: 0010_add_routed_messages
Revises: 0009_drop_sender_foreign_keys
Create Date: 2026-11-04

``routed_messages`` records each message the relay accepted for delivery
(id, from, to) so a receipt can be matched to the message it answers:
a receipt from B to A is bound when its signed ``reply_to`` names a row
routed A -> B, up to 3 receipts per row (``receipt_count``). Bound
receipts skip the message rate limits; others share a small per-sender
bucket. Rows are swept after 7 days, like ``seen_message_ids``.

New table only (no change to existing tables), so relays that build
their schema with ``create_tables`` get it too. No FKs: either side may
be on another relay. Portable types only.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010_add_routed_messages"
down_revision = "0009_drop_sender_foreign_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "routed_messages",
        sa.Column("message_id", sa.String(), nullable=False),
        sa.Column("from_addr", sa.String(), nullable=False),
        sa.Column("to_addr", sa.String(), nullable=False),
        sa.Column("receipt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "routed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("message_id", name="pk_routed_messages"),
    )
    op.create_index(
        "ix_routed_messages_routed_at",
        "routed_messages",
        ["routed_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_routed_messages_routed_at", table_name="routed_messages")
    op.drop_table("routed_messages")
