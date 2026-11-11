"""add_fleets

Revision ID: 0020_add_fleets
Revises: 0019_add_owner_contacts
Create Date: 2026-11-11

Fleets (P2e-1b, UAM-17): a named group of one owner's agents
(``owner_fleets``, unique per owner by ``name_key``) and the setting its
agents share (``policy``/``same_owner``, null until set). A link is in one
fleet at most (``owner_links.fleet_id``); a code for several agents can name
one (``owner_codes.fleet_id``). Ungrouping deletes the fleet and leaves its
links where they are, so both keys are ``ON DELETE SET NULL``. Several
agents widened with one passkey keep the hashes signed together
(``agent_policy_approvals.approval_set``), as linked sets do.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020_add_fleets"
down_revision = "0019_add_owner_contacts"
branch_labels = None
depends_on = None


def _fleet(batch_op, table: str) -> None:
    batch_op.add_column(sa.Column("fleet_id", sa.Integer(), nullable=True))
    batch_op.create_foreign_key(
        f"fk_{table}_fleet", "owner_fleets", ["fleet_id"], ["id"], ondelete="SET NULL",
    )


def upgrade() -> None:
    op.create_table(
        "owner_fleets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "owner_pk", sa.Integer(),
            sa.ForeignKey("owners.id", ondelete="CASCADE", name="fk_owner_fleets_owner"),
            nullable=False,
        ),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("name_key", sa.String(), nullable=False),
        sa.Column("policy", sa.String(), nullable=True),
        sa.Column("same_owner", sa.Boolean(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint("owner_pk", "name_key", name="uq_owner_fleets_name"),
    )
    with op.batch_alter_table("owner_links") as batch_op:
        _fleet(batch_op, "owner_links")
        batch_op.create_index("ix_owner_links_fleet_id", ["fleet_id"])
    with op.batch_alter_table("owner_codes") as batch_op:
        _fleet(batch_op, "owner_codes")
    with op.batch_alter_table("agent_policy_approvals") as batch_op:
        batch_op.add_column(sa.Column("approval_set", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("agent_policy_approvals") as batch_op:
        batch_op.drop_column("approval_set")
    with op.batch_alter_table("owner_codes") as batch_op:
        batch_op.drop_constraint("fk_owner_codes_fleet", type_="foreignkey")
        batch_op.drop_column("fleet_id")
    with op.batch_alter_table("owner_links") as batch_op:
        batch_op.drop_index("ix_owner_links_fleet_id")
        batch_op.drop_constraint("fk_owner_links_fleet", type_="foreignkey")
        batch_op.drop_column("fleet_id")
    op.drop_table("owner_fleets")
