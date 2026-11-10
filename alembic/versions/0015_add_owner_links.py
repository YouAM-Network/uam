"""add_owner_links

Revision ID: 0015_add_owner_links
Revises: 0014_add_owner_passkeys
Create Date: 2026-11-10

Linking agents to owners (P2d). ``owner_codes`` (setup and link codes,
stored as HMACs, 10 minutes, single use), ``owner_code_tries`` (each
redeem attempt, so an agent gets 5 per 10 minutes), ``owner_links`` (the
signed UamOwnerLink and both signatures; ``live_for`` holds the agent's
address while the link is pending or active, and is unique, so an agent
has at most one live link) and ``owner_unlinks`` (the signed
UamOwnerUnlink, by the owner's passkey or the relay).

New tables only, so relays that build their schema with ``create_tables``
get them too. Portable types only.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0015_add_owner_links"
down_revision = "0014_add_owner_passkeys"
branch_labels = None
depends_on = None


def _created_at() -> sa.Column:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )


def _when(name: str) -> sa.Column:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=True)


def upgrade() -> None:
    op.create_table(
        "owner_codes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("owner_pk", sa.Integer(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("code_hash", sa.String(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        _when("used_at"),
        sa.Column("used_by", sa.String(), nullable=True),
        _created_at(),
        sa.PrimaryKeyConstraint("id", name="pk_owner_codes"),
        sa.ForeignKeyConstraint(
            ["owner_pk"], ["owners.id"], ondelete="CASCADE", name="fk_owner_codes_owner"
        ),
        sa.UniqueConstraint("code_hash", name="uq_owner_codes_code_hash"),
    )
    op.create_index("ix_owner_codes_owner_pk", "owner_codes", ["owner_pk"])
    op.create_table(
        "owner_code_tries",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("agent_address", sa.String(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_owner_code_tries"),
        sa.ForeignKeyConstraint(
            ["agent_address"], ["agents.address"], ondelete="CASCADE",
            name="fk_owner_code_tries_agent",
        ),
    )
    op.create_index("ix_owner_code_tries_agent_address", "owner_code_tries", ["agent_address"])
    op.create_table(
        "owner_links",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("owner_pk", sa.Integer(), nullable=False),
        sa.Column("agent_address", sa.String(), nullable=False),
        sa.Column("agent_key", sa.String(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("hash", sa.String(), nullable=False),
        sa.Column("via", sa.String(), nullable=False),
        sa.Column("effective_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.String(), nullable=False, server_default="started"),
        sa.Column("live_for", sa.String(), nullable=True),
        sa.Column("agent_signature", sa.Text(), nullable=True),
        sa.Column("owner_signer", sa.String(), nullable=True),
        sa.Column("authenticator_data", sa.Text(), nullable=True),
        sa.Column("client_data_json", sa.Text(), nullable=True),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("screen", sa.Text(), nullable=True),
        sa.Column("private", sa.Boolean(), nullable=False, server_default=sa.false()),
        _created_at(),
        _when("approved_at"),
        _when("ended_at"),
        sa.PrimaryKeyConstraint("id", name="pk_owner_links"),
        sa.ForeignKeyConstraint(
            ["owner_pk"], ["owners.id"], ondelete="CASCADE", name="fk_owner_links_owner"
        ),
        sa.ForeignKeyConstraint(
            ["agent_address"], ["agents.address"], ondelete="CASCADE",
            name="fk_owner_links_agent",
        ),
        sa.UniqueConstraint("hash", name="uq_owner_links_hash"),
        sa.UniqueConstraint("live_for", name="uq_owner_links_live_for"),
    )
    op.create_index("ix_owner_links_owner_pk", "owner_links", ["owner_pk"])
    op.create_index("ix_owner_links_agent_address", "owner_links", ["agent_address"])
    op.create_table(
        "owner_unlinks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("link_pk", sa.Integer(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("hash", sa.String(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("signer", sa.String(), nullable=False),
        sa.Column("authenticator_data", sa.Text(), nullable=True),
        sa.Column("client_data_json", sa.Text(), nullable=True),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("screen", sa.Text(), nullable=True),
        _created_at(),
        sa.PrimaryKeyConstraint("id", name="pk_owner_unlinks"),
        sa.ForeignKeyConstraint(
            ["link_pk"], ["owner_links.id"], ondelete="CASCADE", name="fk_owner_unlinks_link"
        ),
        sa.UniqueConstraint("link_pk", name="uq_owner_unlinks_link_pk"),
        sa.UniqueConstraint("hash", name="uq_owner_unlinks_hash"),
    )


def downgrade() -> None:
    op.drop_table("owner_unlinks")
    op.drop_index("ix_owner_links_agent_address", table_name="owner_links")
    op.drop_index("ix_owner_links_owner_pk", table_name="owner_links")
    op.drop_table("owner_links")
    op.drop_index("ix_owner_code_tries_agent_address", table_name="owner_code_tries")
    op.drop_table("owner_code_tries")
    op.drop_index("ix_owner_codes_owner_pk", table_name="owner_codes")
    op.drop_table("owner_codes")
