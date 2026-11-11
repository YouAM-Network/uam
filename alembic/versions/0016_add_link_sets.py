"""add_link_sets

Revision ID: 0016_add_link_sets
Revises: 0015_add_owner_links
Create Date: 2026-11-10

Linking a fleet (P2d-4, DEC-006). A code can be redeemed by up to
``max_uses`` agents (1 for a plain code); ``uses`` counts redemptions and
``used_at`` is set when the last one is taken. A link approved with others
in one Face ID keeps the set's hashes, in screen order, in
``approval_set`` (JSON), so its proof can be checked later; it is null for
a link approved on its own.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0016_add_link_sets"
down_revision = "0015_add_owner_links"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("owner_codes") as batch_op:
        batch_op.add_column(
            sa.Column("max_uses", sa.Integer(), nullable=False, server_default="1")
        )
        batch_op.add_column(sa.Column("uses", sa.Integer(), nullable=False, server_default="0"))
    with op.batch_alter_table("owner_links") as batch_op:
        batch_op.add_column(sa.Column("approval_set", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("owner_links") as batch_op:
        batch_op.drop_column("approval_set")
    with op.batch_alter_table("owner_codes") as batch_op:
        batch_op.drop_column("uses")
        batch_op.drop_column("max_uses")
