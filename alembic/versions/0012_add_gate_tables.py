"""add_gate_tables

Revision ID: 0012_add_gate_tables
Revises: 0011_add_webhook_secret
Create Date: 2026-11-09

The delivery gate (P1). ``inbound_policies`` says whether an agent takes
mail from anyone (no row, or ``open``) or only from approved senders
(``contacts``/``closed``); ``inbound_contacts`` lists those senders, each
bound to the key it must sign with. Columns later phases fill
(``grant_ref``, ``expires_at``) are created now, so they add rows, never
columns.

New tables only (no change to existing tables), so relays that build
their schema with ``create_tables`` get them too. Portable types only.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0012_add_gate_tables"
down_revision = "0011_add_webhook_secret"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "inbound_policies",
        sa.Column("agent_address", sa.String(), nullable=False),
        sa.Column("policy", sa.String(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("set_by", sa.String(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("agent_address", name="pk_inbound_policies"),
        sa.ForeignKeyConstraint(
            ["agent_address"],
            ["agents.address"],
            ondelete="CASCADE",
            name="fk_inbound_policies_agent",
        ),
    )
    op.create_table(
        "inbound_contacts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("agent_address", sa.String(), nullable=False),
        sa.Column("contact_address", sa.String(), nullable=False),
        sa.Column("contact_key", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("source", sa.String(), nullable=False),
        sa.Column("grant_ref", sa.String(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id", name="pk_inbound_contacts"),
        sa.ForeignKeyConstraint(
            ["agent_address"],
            ["agents.address"],
            ondelete="CASCADE",
            name="fk_inbound_contacts_agent",
        ),
        sa.UniqueConstraint(
            "agent_address", "contact_address", name="uq_inbound_contacts_pair"
        ),
    )


def downgrade() -> None:
    op.drop_table("inbound_contacts")
    op.drop_table("inbound_policies")
