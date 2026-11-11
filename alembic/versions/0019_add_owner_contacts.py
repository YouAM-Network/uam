"""add_owner_contacts

Revision ID: 0019_add_owner_contacts
Revises: 0018_add_held_names
Create Date: 2026-11-10

Owners connect and decide who reaches their agents (P2e). An owner's
invite (``owner_invites``) is redeemed once (``invite_redemptions``, keyed
by the invite's hash); each side's approval is a signed grant
(``owner_grants``). Widening who may message an agent is a signed
``UamAgentPolicy`` (``agent_policy_approvals``); ``inbound_policies``
gains ``same_owner``, the switch that lets an owner's own agents through.
Revoked grants and cancelled invites go on the relay's revocation list
(``owner_revocations``). ``owner_invite_tries`` counts wrong invite codes.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019_add_owner_contacts"
down_revision = "0018_add_held_names"
branch_labels = None
depends_on = None


def _now() -> sa.Column:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
    )


def _owner(table: str) -> sa.Column:
    return sa.Column(
        "owner_pk", sa.Integer(),
        sa.ForeignKey("owners.id", ondelete="CASCADE", name=f"fk_{table}_owner"),
        nullable=False,
    )


def _approval() -> list[sa.Column]:
    return [
        sa.Column("signer", sa.String(), nullable=False),
        sa.Column("authenticator_data", sa.Text(), nullable=False),
        sa.Column("client_data_json", sa.Text(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("screen", sa.Text(), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "owner_invites",
        sa.Column("id", sa.Integer(), primary_key=True),
        _owner("owner_invites"),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("hash", sa.String(), nullable=False),
        sa.Column("link_id", sa.String(), nullable=False),
        sa.Column("mode", sa.String(), nullable=False),
        sa.Column("how", sa.String(), nullable=False),
        sa.Column("secret", sa.String(), nullable=True),
        sa.Column("code_hash", sa.String(), nullable=True),
        sa.Column("email_hmac", sa.String(), nullable=True),
        sa.Column("email_enc", sa.String(), nullable=True),
        sa.Column("state", sa.String(), nullable=False, server_default="open"),
        sa.Column("redeem_by", sa.DateTime(timezone=True), nullable=False),
        sa.Column("send_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        _now(),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("hash", name="uq_owner_invites_hash"),
        sa.UniqueConstraint("link_id", name="uq_owner_invites_link_id"),
        sa.UniqueConstraint("code_hash", name="uq_owner_invites_code_hash"),
    )
    op.create_index("ix_owner_invites_owner_pk", "owner_invites", ["owner_pk"])
    op.create_table(
        "invite_redemptions",
        sa.Column("invite_hash", sa.String(), primary_key=True),
        sa.Column(
            "invite_pk", sa.Integer(),
            sa.ForeignKey("owner_invites.id", ondelete="CASCADE",
                          name="fk_invite_redemptions_invite"),
            nullable=False,
        ),
        _owner("invite_redemptions"),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("hash", sa.String(), nullable=False),
        *_approval(),
        _now(),
        sa.UniqueConstraint("hash", name="uq_invite_redemptions_hash"),
    )
    op.create_table(
        "owner_grants",
        sa.Column("id", sa.Integer(), primary_key=True),
        _owner("owner_grants"),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("hash", sa.String(), nullable=False),
        sa.Column("subject_kind", sa.String(), nullable=False),
        sa.Column(
            "subject_owner_pk", sa.Integer(),
            sa.ForeignKey("owners.id", ondelete="CASCADE",
                          name="fk_owner_grants_subject_owner"),
            nullable=True,
        ),
        sa.Column("subject_address", sa.String(), nullable=True),
        sa.Column("subject_key", sa.String(), nullable=True),
        sa.Column(
            "invite_pk", sa.Integer(),
            sa.ForeignKey("owner_invites.id", ondelete="SET NULL",
                          name="fk_owner_grants_invite"),
            nullable=True,
        ),
        sa.Column("location_keys", sa.Text(), nullable=True),
        sa.Column("via", sa.String(), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        *_approval(),
        _now(),
        sa.UniqueConstraint("hash", name="uq_owner_grants_hash"),
    )
    op.create_index("ix_owner_grants_owner_pk", "owner_grants", ["owner_pk"])
    op.create_index("ix_owner_grants_subject_owner_pk", "owner_grants", ["subject_owner_pk"])
    op.create_index("ix_owner_grants_subject_address", "owner_grants", ["subject_address"])
    op.create_table(
        "agent_policy_approvals",
        sa.Column("id", sa.Integer(), primary_key=True),
        _owner("agent_policy_approvals"),
        sa.Column("agent_address", sa.String(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("hash", sa.String(), nullable=False),
        *_approval(),
        _now(),
        sa.UniqueConstraint("hash", name="uq_agent_policy_approvals_hash"),
    )
    op.create_table(
        "owner_revocations",
        sa.Column("seq", sa.Integer(), primary_key=True),
        sa.Column("t", sa.String(), nullable=False),
        sa.Column("h", sa.String(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("t", "h", name="uq_owner_revocations_t_h"),
    )
    op.create_table(
        "owner_invite_tries",
        sa.Column("id", sa.Integer(), primary_key=True),
        _owner("owner_invite_tries"),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
    )
    with op.batch_alter_table("inbound_policies") as batch_op:
        batch_op.add_column(
            sa.Column("same_owner", sa.Boolean(), nullable=False, server_default=sa.true())
        )


def downgrade() -> None:
    with op.batch_alter_table("inbound_policies") as batch_op:
        batch_op.drop_column("same_owner")
    op.drop_table("owner_invite_tries")
    op.drop_table("owner_revocations")
    op.drop_table("agent_policy_approvals")
    op.drop_index("ix_owner_grants_subject_address", table_name="owner_grants")
    op.drop_index("ix_owner_grants_subject_owner_pk", table_name="owner_grants")
    op.drop_index("ix_owner_grants_owner_pk", table_name="owner_grants")
    op.drop_table("owner_grants")
    op.drop_table("invite_redemptions")
    op.drop_index("ix_owner_invites_owner_pk", table_name="owner_invites")
    op.drop_table("owner_invites")
