"""add_owner_passkeys

Revision ID: 0014_add_owner_passkeys
Revises: 0013_add_owner_accounts
Create Date: 2026-11-09

Owner passkeys and key log (P2c-2). ``owner_passkeys`` (a passkey is
``held`` from registration until the key log entry that adds it is signed,
then ``active``; ``removed`` later), ``owner_key_log`` (the signed
UamOwnerKeys chain, one row per entry, keyed by owner and seq so the chain
can't fork) and ``webauthn_challenges`` (single-use, 5 minutes; an
``approve`` challenge carries the entry it signs and the text shown).

New tables only, so relays that build their schema with ``create_tables``
get them too. Portable types only.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014_add_owner_passkeys"
down_revision = "0013_add_owner_accounts"
branch_labels = None
depends_on = None


def _created_at() -> sa.Column:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )


def _owner_fk(table: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["owner_pk"], ["owners.id"], ondelete="CASCADE", name=f"fk_{table}_owner"
    )


def upgrade() -> None:
    op.create_table(
        "owner_passkeys",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("owner_pk", sa.Integer(), nullable=False),
        sa.Column("credential_id", sa.String(), nullable=False),
        sa.Column("public_key", sa.String(), nullable=False),
        sa.Column("did", sa.String(), nullable=False),
        sa.Column("backup_eligible", sa.Boolean(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("label", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False, server_default="held"),
        _created_at(),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("removed_reason", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_owner_passkeys"),
        _owner_fk("owner_passkeys"),
        sa.UniqueConstraint("credential_id", name="uq_owner_passkeys_credential_id"),
    )
    op.create_index("ix_owner_passkeys_owner_pk", "owner_passkeys", ["owner_pk"])
    op.create_table(
        "owner_key_log",
        sa.Column("owner_pk", sa.Integer(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("hash", sa.String(), nullable=False),
        sa.Column("signer", sa.String(), nullable=False),
        sa.Column("authenticator_data", sa.Text(), nullable=False),
        sa.Column("client_data_json", sa.Text(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("screen", sa.Text(), nullable=False),
        _created_at(),
        sa.PrimaryKeyConstraint("owner_pk", "seq", name="pk_owner_key_log"),
        _owner_fk("owner_key_log"),
        sa.UniqueConstraint("hash", name="uq_owner_key_log_hash"),
    )
    op.create_table(
        "webauthn_challenges",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("owner_pk", sa.Integer(), nullable=False),
        sa.Column("purpose", sa.String(), nullable=False),
        sa.Column("challenge", sa.String(), nullable=False),
        sa.Column("passkey_pk", sa.Integer(), nullable=True),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("screen", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        sa.PrimaryKeyConstraint("id", name="pk_webauthn_challenges"),
        _owner_fk("webauthn_challenges"),
        sa.ForeignKeyConstraint(
            ["passkey_pk"], ["owner_passkeys.id"], ondelete="CASCADE",
            name="fk_webauthn_challenges_passkey",
        ),
        sa.UniqueConstraint("challenge", name="uq_webauthn_challenges_challenge"),
    )
    op.create_index("ix_webauthn_challenges_owner_pk", "webauthn_challenges", ["owner_pk"])


def downgrade() -> None:
    op.drop_index("ix_webauthn_challenges_owner_pk", table_name="webauthn_challenges")
    op.drop_table("webauthn_challenges")
    op.drop_table("owner_key_log")
    op.drop_index("ix_owner_passkeys_owner_pk", table_name="owner_passkeys")
    op.drop_table("owner_passkeys")
