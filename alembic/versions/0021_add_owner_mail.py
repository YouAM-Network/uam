"""add_owner_mail

Revision ID: 0021_add_owner_mail
Revises: 0020_add_fleets
Create Date: 2026-11-11

Owner email (P2g-1): an outbox of emails to owners and people being
invited (``owner_mail``). The recipient and the contents are encrypted with
the email key (they hold sign-in codes and secret links). A row is due when
``next_try_at`` has passed and it is neither sent nor given up; it is
deleted 7 days after either. ``owner_pk`` (null for someone without an
account) cascades, so deleting an owner deletes their mail.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0021_add_owner_mail"
down_revision = "0020_add_fleets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "owner_mail",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column(
            "owner_pk", sa.Integer(),
            sa.ForeignKey("owners.id", ondelete="CASCADE", name="fk_owner_mail_owner"),
            nullable=True,
        ),
        sa.Column("to_enc", sa.Text(), nullable=False),
        sa.Column("data_enc", sa.Text(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_try_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("provider_id", sa.String(), nullable=True),
        sa.Column("last_error", sa.String(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_owner_mail_next_try_at", "owner_mail", ["next_try_at"])
    op.create_index("ix_owner_mail_owner_pk", "owner_mail", ["owner_pk"])


def downgrade() -> None:
    op.drop_index("ix_owner_mail_owner_pk", table_name="owner_mail")
    op.drop_index("ix_owner_mail_next_try_at", table_name="owner_mail")
    op.drop_table("owner_mail")
