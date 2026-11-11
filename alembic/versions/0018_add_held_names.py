"""add_held_names

Revision ID: 0018_add_held_names
Revises: 0017_add_owner_requests
Create Date: 2026-11-10

Reservations become setup codes (P2s-2, DEC-005). Once owners are on, a
name is reserved with an email, and only that email's account can set it
up. ``reservations`` gains the email (HMAC to look it up, encrypted to
send to it), the hash of the token its confirmation email carries,
whether an email went out, and the account that opened it or was given
it. ``owner_codes.reservation_id`` names the reserved name a setup code
is for. ``owner_sessions.reservation_id`` marks a session opened from a
reservation email: it may only set up that name.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0018_add_held_names"
down_revision = "0017_add_owner_requests"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("reservations") as batch_op:
        batch_op.add_column(sa.Column("email_hmac", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("email_enc", sa.String(), nullable=True))
        batch_op.add_column(sa.Column("token_hash", sa.String(), nullable=True))
        batch_op.add_column(
            sa.Column("emailed", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch_op.add_column(sa.Column("owner_pk", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_reservations_owner", "owners", ["owner_pk"], ["id"], ondelete="SET NULL"
        )
        batch_op.create_unique_constraint("uq_reservations_token_hash", ["token_hash"])
        batch_op.create_index("ix_reservations_email_hmac", ["email_hmac"])
    with op.batch_alter_table("owner_codes") as batch_op:
        batch_op.add_column(sa.Column("reservation_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_owner_codes_reservation", "reservations", ["reservation_id"], ["id"],
            ondelete="CASCADE",
        )
    with op.batch_alter_table("owner_sessions") as batch_op:
        batch_op.add_column(sa.Column("reservation_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_owner_sessions_reservation", "reservations", ["reservation_id"], ["id"],
            ondelete="CASCADE",
        )


def downgrade() -> None:
    with op.batch_alter_table("owner_sessions") as batch_op:
        batch_op.drop_constraint("fk_owner_sessions_reservation", type_="foreignkey")
        batch_op.drop_column("reservation_id")
    with op.batch_alter_table("owner_codes") as batch_op:
        batch_op.drop_constraint("fk_owner_codes_reservation", type_="foreignkey")
        batch_op.drop_column("reservation_id")
    with op.batch_alter_table("reservations") as batch_op:
        batch_op.drop_index("ix_reservations_email_hmac")
        batch_op.drop_constraint("uq_reservations_token_hash", type_="unique")
        batch_op.drop_constraint("fk_reservations_owner", type_="foreignkey")
        batch_op.drop_column("owner_pk")
        batch_op.drop_column("emailed")
        batch_op.drop_column("token_hash")
        batch_op.drop_column("email_enc")
        batch_op.drop_column("email_hmac")
