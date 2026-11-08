"""add_webhook_secret

Revision ID: 0011_add_webhook_secret
Revises: 0010_add_routed_messages
Create Date: 2026-11-06

``agents.webhook_secret`` is the key the relay signs an agent's webhooks with.
Every agent that already has a webhook gets one here, so "has a webhook" and
"has a secret" stay the same set of agents; the agent reads it by setting its
webhook again.
"""

from __future__ import annotations

import secrets

import sqlalchemy as sa
from alembic import op

revision = "0011_add_webhook_secret"
down_revision = "0010_add_routed_messages"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("agents") as batch_op:
        batch_op.add_column(sa.Column("webhook_secret", sa.String(), nullable=True))

    agents = sa.table(
        "agents",
        sa.column("address", sa.String()),
        sa.column("webhook_url", sa.String()),
        sa.column("webhook_secret", sa.String()),
    )
    conn = op.get_bind()
    addresses = conn.execute(
        sa.select(agents.c.address).where(agents.c.webhook_url.is_not(None))
    ).scalars().all()
    for address in addresses:
        conn.execute(
            agents.update()
            .where(agents.c.address == address)
            .values(webhook_secret=secrets.token_urlsafe(32))
        )


def downgrade() -> None:
    with op.batch_alter_table("agents") as batch_op:
        batch_op.drop_column("webhook_secret")
