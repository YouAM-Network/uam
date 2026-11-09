"""add_owner_accounts

Revision ID: 0013_add_owner_accounts
Revises: 0012_add_gate_tables
Create Date: 2026-11-09

Owner accounts (P2c-1): the people who will approve contacts for their
agents. ``owners`` (``owner_id`` is filled once the owner's key log has an
entry 0, P2c-2), ``owner_emails`` (an HMAC to look up, and the address
encrypted), ``owner_login_codes`` (emailed sign-in codes, stored hashed),
``owner_sessions`` (cookie sessions on the owner origin, stored hashed) and
``owner_audit`` (what happened to an account; never an email or an IP).

New tables only, so relays that build their schema with ``create_tables``
get them too. Portable types only.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0013_add_owner_accounts"
down_revision = "0012_add_gate_tables"
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
        "owners",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("owner_id", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="active"),
        sa.Column("created_via", sa.String(), nullable=False),
        _created_at(),
        sa.PrimaryKeyConstraint("id", name="pk_owners"),
        sa.UniqueConstraint("owner_id", name="uq_owners_owner_id"),
    )
    op.create_table(
        "owner_emails",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("owner_pk", sa.Integer(), nullable=False),
        sa.Column("email_hmac", sa.String(), nullable=False),
        sa.Column("email_enc", sa.String(), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        sa.PrimaryKeyConstraint("id", name="pk_owner_emails"),
        _owner_fk("owner_emails"),
        sa.UniqueConstraint("email_hmac", name="uq_owner_emails_hmac"),
    )
    op.create_table(
        "owner_login_codes",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email_hmac", sa.String(), nullable=False),
        sa.Column("code_hash", sa.String(), nullable=False),
        sa.Column("tries", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        sa.PrimaryKeyConstraint("id", name="pk_owner_login_codes"),
    )
    op.create_index(
        "ix_owner_login_codes_email_hmac", "owner_login_codes", ["email_hmac"]
    )
    op.create_table(
        "owner_sessions",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("owner_pk", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        _created_at(),
        sa.PrimaryKeyConstraint("id", name="pk_owner_sessions"),
        _owner_fk("owner_sessions"),
        sa.UniqueConstraint("token_hash", name="uq_owner_sessions_token_hash"),
    )
    op.create_table(
        "owner_audit",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("owner_pk", sa.Integer(), nullable=False),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("details", sa.Text(), nullable=False, server_default="{}"),
        sa.Column(
            "at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id", name="pk_owner_audit"),
        _owner_fk("owner_audit"),
    )
    op.create_index("ix_owner_audit_owner_pk", "owner_audit", ["owner_pk"])


def downgrade() -> None:
    op.drop_index("ix_owner_audit_owner_pk", table_name="owner_audit")
    op.drop_table("owner_audit")
    op.drop_table("owner_sessions")
    op.drop_index("ix_owner_login_codes_email_hmac", table_name="owner_login_codes")
    op.drop_table("owner_login_codes")
    op.drop_table("owner_emails")
    op.drop_table("owners")
