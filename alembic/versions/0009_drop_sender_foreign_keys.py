"""drop_sender_foreign_keys

Revision ID: 0009_drop_sender_foreign_keys
Revises: 0008_server_default_timestamps
Create Date: 2026-11-04

0006 made ``messages.from_addr`` and ``seen_message_ids.from_addr``
reference ``agents.address``. A federated message's sender lives on
another relay and is never in the local agents table, so the dedup
insert in ``federation_deliver`` failed its FK check, was read as a
duplicate, and the message was dropped. Senders are not local entities;
these two columns stay plain strings. ``messages.to_addr`` keeps its FK:
recipients are always local.

Downgrade re-adds both FKs and refuses (before any DDL) if rows with a
non-local sender exist, as 0006's pre-flight check does.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009_drop_sender_foreign_keys"
down_revision = "0008_server_default_timestamps"
branch_labels = None
depends_on = None

# (table, column, fk_name, ondelete) as created by 0006.
SENDER_FKS = [
    ("messages", "from_addr", "fk_messages_from_addr", "RESTRICT"),
    ("seen_message_ids", "from_addr", "fk_seen_messages_from", "CASCADE"),
]


def upgrade() -> None:
    for table, _column, fk_name, _ondelete in SENDER_FKS:
        with op.batch_alter_table(table) as batch_op:
            batch_op.drop_constraint(fk_name, type_="foreignkey")


def downgrade() -> None:
    conn = op.get_bind()
    for table, column, _fk_name, _ondelete in SENDER_FKS:
        orphans = conn.execute(
            sa.text(
                f"SELECT COUNT(*) FROM {table} t "
                f"LEFT JOIN agents a ON t.{column} = a.address "
                "WHERE a.address IS NULL"
            )
        ).scalar_one()
        if orphans:
            raise RuntimeError(
                f"Cannot downgrade 0009: {orphans} row(s) in {table}.{column} "
                "have a sender that is not a local agent (federated mail). "
                "Delete or archive them first."
            )
    for table, column, fk_name, ondelete in SENDER_FKS:
        with op.batch_alter_table(table) as batch_op:
            batch_op.create_foreign_key(
                fk_name,
                referent_table="agents",
                local_cols=[column],
                remote_cols=["address"],
                ondelete=ondelete,
            )
