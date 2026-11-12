"""add_owner_agent_policy

Revision ID: 0023_add_owner_agent_policy
Revises: 0022_add_owner_freezes
Create Date: 2026-11-12

Who may message an owner's agents by default (Amir, chat 2026-11-12):
only their contacts and their own agents, unless the owner chooses Anyone.

``owners.agent_policy`` holds the choice (null until made; it counts as
``contacts``). ``owner_links.settled_at`` records when a linked agent took
its owner's setting. A link in effect without one takes it on the relay's
next sweep, so agents linked before this migration are narrowed too,
except those whose owner already chose a setting for them, which keep it.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0023_add_owner_agent_policy"
down_revision = "0022_add_owner_freezes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("owners") as batch_op:
        batch_op.add_column(sa.Column("agent_policy", sa.String(), nullable=True))
    with op.batch_alter_table("owner_links") as batch_op:
        batch_op.add_column(sa.Column("settled_at", sa.DateTime(timezone=True), nullable=True))
    # An agent its owner already set keeps that setting.
    op.execute(
        "UPDATE owner_links SET settled_at = CURRENT_TIMESTAMP "
        "WHERE state = 'active' AND agent_address IN "
        "(SELECT agent_address FROM inbound_policies WHERE set_by = 'owner')"
    )


def downgrade() -> None:
    with op.batch_alter_table("owner_links") as batch_op:
        batch_op.drop_column("settled_at")
    with op.batch_alter_table("owners") as batch_op:
        batch_op.drop_column("agent_policy")
