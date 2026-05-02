"""Add agents.token_hash and backfill from existing token column.

Revision ID: 0003
Revises: 0002
Create Date: 2026-05-02

T2.1 (Phase 43 Plan 04) -- HMAC-SHA-256 token hashing at rest.

Order of operations (additive, single upgrade):
    1. ADD COLUMN token_hash TEXT NULL  +  unique index ix_agents_token_hash
    2. Backfill via Python loop using ``hash_token(token, pepper)`` -- the same
       primitive the runtime ``auth.py`` uses, so backfilled hashes match
       any token the relay later receives.
    3. Pre-fill rows whose token is NULL (already-deleted / corrupted) with
       a non-matching placeholder so the NOT NULL ALTER below doesn't fail.
       Operators must re-issue tokens for affected agents (or hard-delete
       the rows) -- the placeholder cannot match any real HMAC output.
    4. Sanity check: assert no NULL token_hash rows remain.
    5. ALTER COLUMN token_hash NOT NULL via batch_alter_table (works for
       SQLite via copy-and-rebuild; works for Postgres natively).

The plaintext ``token`` column is intentionally NOT dropped here.  It
stays for one full deploy cycle as an emergency-rollback safety net.
A follow-up migration (Phase 47) drops it after the new auth path is
proven stable in production.

Pre-deploy operational requirement:
    UAM_TOKEN_PEPPER must be set in the migration environment to the
    SAME value the relay runtime will use.  A different pepper at
    backfill time vs runtime would mean every existing token mismatches.
"""

from __future__ import annotations

import hashlib
import hmac
import os

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


# Placeholder used for rows whose ``token`` column is NULL at migration time
# (already-deleted / soft-deleted / corrupted).  This is NOT a valid HMAC-SHA-256
# digest (those are 64 hex chars), so it cannot collide with any real token's
# hash.  Operators must re-issue tokens for these agents post-migration.
_PLACEHOLDER_HASH = "PLACEHOLDER-REQUIRES-REREGISTRATION"


def _hash_token(token: str, pepper: str) -> str:
    """Inline copy of ``uam.relay.token_hashing.hash_token`` to avoid
    importing the runtime package during a migration (alembic envs
    sometimes run before the package is fully importable).
    """
    return hmac.new(
        pepper.encode("utf-8"),
        token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def upgrade() -> None:
    # Step 1: add column nullable + unique index
    op.add_column(
        "agents",
        sa.Column("token_hash", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_agents_token_hash",
        "agents",
        ["token_hash"],
        unique=True,
    )

    # Step 2: backfill via Python loop using the same HMAC the runtime uses.
    pepper = os.environ.get("UAM_TOKEN_PEPPER")
    if not pepper:
        raise RuntimeError(
            "UAM_TOKEN_PEPPER must be set for migration 0003 to backfill "
            "token hashes. Set the env var BEFORE running 'alembic upgrade "
            "head'. Generate with: "
            "python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )

    conn = op.get_bind()
    rows = conn.execute(
        sa.text("SELECT address, token FROM agents WHERE token IS NOT NULL")
    ).fetchall()
    for row in rows:
        token_hash = _hash_token(row.token, pepper)
        conn.execute(
            sa.text(
                "UPDATE agents SET token_hash = :h WHERE address = :a"
            ),
            {"h": token_hash, "a": row.address},
        )

    # Step 3: handle rows with no plaintext token (already-deleted / corrupted).
    # Such rows would otherwise fail the NOT NULL ALTER below.  Mark them with
    # a non-matching placeholder so they CANNOT authenticate but the column
    # tightens cleanly.  Operators must re-issue tokens for affected agents
    # (or hard-delete the rows).
    conn.execute(
        sa.text(
            "UPDATE agents SET token_hash = :p "
            "WHERE token IS NULL AND token_hash IS NULL"
        ),
        {"p": _PLACEHOLDER_HASH},
    )

    # Step 4: sanity check -- NO row may have NULL token_hash before the ALTER.
    null_count = conn.execute(
        sa.text("SELECT COUNT(*) FROM agents WHERE token_hash IS NULL")
    ).scalar()
    if null_count and null_count > 0:
        raise RuntimeError(
            f"Migration 0003 left {null_count} rows with NULL token_hash; "
            f"aborting. Inspect the agents table and either backfill or "
            f"delete these rows manually."
        )

    # Step 5: tighten -- token_hash NOT NULL.
    # batch_alter_table works for both SQLite (copy-and-rebuild) and Postgres
    # (native ALTER); env.py sets render_as_batch=True so we get this for free.
    with op.batch_alter_table("agents") as batch_op:
        batch_op.alter_column(
            "token_hash",
            existing_type=sa.String(length=64),
            nullable=False,
        )


def downgrade() -> None:
    """Reverse the migration.

    Note: dropping the column drops the hashes.  The plaintext ``token``
    column is still in place (we did not drop it in upgrade), so the
    pre-0003 auth path (looking up by ``token``) continues to work after
    a downgrade -- which is the entire point of keeping ``token`` for
    one release.
    """
    with op.batch_alter_table("agents") as batch_op:
        batch_op.alter_column(
            "token_hash",
            existing_type=sa.String(length=64),
            nullable=True,
        )
        batch_op.drop_index("ix_agents_token_hash")
        batch_op.drop_column("token_hash")
