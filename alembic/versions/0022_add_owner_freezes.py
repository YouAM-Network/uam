"""add_owner_freezes

Revision ID: 0022_add_owner_freezes
Revises: 0021_add_owner_mail
Create Date: 2026-11-12

An owner who lost every passkey starts again (DEC-010): the relay admin
freezes the account, the email gets a link that keeps it for 72 hours
(only the link's hash is kept), and after that the account closes and its
email is free for a new one. ``owners.status`` gains ``closed``; it is a
plain string, so no change to that column.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022_add_owner_freezes"
down_revision = "0021_add_owner_mail"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "owner_freezes",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "owner_pk", sa.Integer(),
            sa.ForeignKey("owners.id", ondelete="CASCADE", name="fk_owner_freezes_owner"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("frozen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closes_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kept_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("token_hash", name="uq_owner_freezes_token_hash"),
    )
    op.create_index("ix_owner_freezes_owner_pk", "owner_freezes", ["owner_pk"])
    op.create_index("ix_owner_freezes_closes_at", "owner_freezes", ["closes_at"])


def downgrade() -> None:
    op.drop_index("ix_owner_freezes_closes_at", table_name="owner_freezes")
    op.drop_index("ix_owner_freezes_owner_pk", table_name="owner_freezes")
    op.drop_table("owner_freezes")
