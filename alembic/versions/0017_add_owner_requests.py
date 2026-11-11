"""add_owner_requests

Revision ID: 0017_add_owner_requests
Revises: 0016_add_link_sets
Create Date: 2026-11-10

Agents ask for an owner by email (P2s-3, DEC-009). ``owner_requests``
holds each ask: the agent, the email (HMAC to look it up, encrypted to
send to it), the hash of the token the email carries, ``via``, its state,
whether an email went out, and the account and link it led to.
``live_for`` holds the agent's address while the request is open or
accepted, and is unique, so an agent has one at a time.
``owner_request_optouts`` keeps the emails that said "never email me about
agents" (``agent_address`` NULL) or "stop this agent asking".
``owner_sessions.request_id`` marks a session opened from a request email:
it may only finish that request.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017_add_owner_requests"
down_revision = "0016_add_link_sets"
branch_labels = None
depends_on = None


def _created_at() -> sa.Column:
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )


def upgrade() -> None:
    op.create_table(
        "owner_requests",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("agent_address", sa.String(), nullable=False),
        sa.Column("email_hmac", sa.String(), nullable=False),
        sa.Column("email_enc", sa.String(), nullable=False),
        sa.Column("token_hash", sa.String(), nullable=False),
        sa.Column("via", sa.String(), nullable=False),
        sa.Column("state", sa.String(), nullable=False, server_default="open"),
        sa.Column("live_for", sa.String(), nullable=True),
        sa.Column("emailed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("owner_pk", sa.Integer(), nullable=True),
        sa.Column("link_id", sa.Integer(), nullable=True),
        _created_at(),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_owner_requests"),
        sa.ForeignKeyConstraint(
            ["agent_address"], ["agents.address"], ondelete="CASCADE",
            name="fk_owner_requests_agent",
        ),
        sa.ForeignKeyConstraint(
            ["owner_pk"], ["owners.id"], ondelete="SET NULL", name="fk_owner_requests_owner"
        ),
        sa.ForeignKeyConstraint(
            ["link_id"], ["owner_links.id"], ondelete="SET NULL", name="fk_owner_requests_link"
        ),
        sa.UniqueConstraint("token_hash", name="uq_owner_requests_token_hash"),
        sa.UniqueConstraint("live_for", name="uq_owner_requests_live_for"),
    )
    op.create_index("ix_owner_requests_agent_address", "owner_requests", ["agent_address"])
    op.create_index("ix_owner_requests_email_hmac", "owner_requests", ["email_hmac"])
    op.create_table(
        "owner_request_optouts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("email_hmac", sa.String(), nullable=False),
        sa.Column("agent_address", sa.String(), nullable=True),
        _created_at(),
        sa.PrimaryKeyConstraint("id", name="pk_owner_request_optouts"),
    )
    op.create_index(
        "ix_owner_request_optouts_email_hmac", "owner_request_optouts", ["email_hmac"]
    )
    with op.batch_alter_table("owner_sessions") as batch_op:
        batch_op.add_column(sa.Column("request_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_owner_sessions_request", "owner_requests", ["request_id"], ["id"],
            ondelete="CASCADE",
        )


def downgrade() -> None:
    with op.batch_alter_table("owner_sessions") as batch_op:
        batch_op.drop_constraint("fk_owner_sessions_request", type_="foreignkey")
        batch_op.drop_column("request_id")
    op.drop_index("ix_owner_request_optouts_email_hmac", table_name="owner_request_optouts")
    op.drop_table("owner_request_optouts")
    op.drop_index("ix_owner_requests_email_hmac", table_name="owner_requests")
    op.drop_index("ix_owner_requests_agent_address", table_name="owner_requests")
    op.drop_table("owner_requests")
