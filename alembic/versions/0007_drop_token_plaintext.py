"""drop_token_plaintext

Revision ID: 0007_drop_token_plaintext
Revises: 0006_foreign_keys
Create Date: 2026-05-04

Phase 47 T7.5: drop the plaintext ``agents.token`` column. Phase 43
``0003`` added ``token_hash`` (HMAC-SHA-256 of token + server pepper) and
made it the authoritative auth column; the plaintext column has been
redundant for one release and is a DB-read attack surface (a snapshot
leak compromises every agent's bearer token in the clear).

Pre-flight assertion: every row MUST have ``token_hash IS NOT NULL``.
Phase 43 ``0003`` enforced this at the DB level (``NOT NULL`` constraint
added after backfill), but the defensive check catches pathological
state (e.g. a row inserted via raw SQL that bypassed the constraint, or
schema drift between dev and prod). On NULL detection the migration
raises ``RuntimeError`` BEFORE any DDL runs, leaving the DB in the
pre-migration state for clean operator intervention.

IRREVERSIBLE: ``downgrade()`` raises ``NotImplementedError``. Adding the
column back yields a NULL-filled column with no plaintext recovery
possible. Operators must reissue tokens for every agent if a rollback is
ever required (RESEARCH Pattern 7 — "Don't bundle irreversible work
with reversible work"; this migration is intentionally a one-way trip).

Coordinated cross-cutting changes (all landed in Phase 47 Plan 08
ahead of this migration):
  * ``src/uam/db/models.py`` — ``Agent.token`` field removed;
    ``Agent.token_hash`` tightened to non-Optional ``str``.
  * ``src/uam/db/crud/agents.py`` — ``create_agent`` signature drops
    the ``token`` parameter; ``get_agent_by_token`` deleted.
  * ``src/uam/relay/routes/register.py`` + ``reserve.py`` — pass
    ``token_hash`` only to ``create_agent``; plaintext token is returned
    in the HTTP response and never persisted.
  * ``src/uam/relay/webhook.py`` — HMAC signing key switches from
    ``agent.token`` (plaintext, dropped) to ``agent.token_hash``
    (RESEARCH OQ1 option (a)). External webhook receivers MUST be
    re-keyed against the agent's ``token_hash`` before signature
    verification works again — see operator runbook below for the
    T-47-08-02 caveat.

Operator runbook (CRITICAL — pre-migration):
  1. Snapshot the database (Railway: ``railway db backup``).
  2. Inventory external webhook receivers — any integration that
     verifies ``X-UAM-Signature`` HMAC using the plaintext token they
     were given at registration WILL FAIL after this migration deploys.
     Coordinate a re-key window: receivers must verify against the
     agent's ``token_hash`` (the relay surfaces it via the existing
     ``GET /api/v1/agents/{address}`` admin endpoint).
  3. Drain in-flight requests OR take the relay offline (Pitfall 8 —
     concurrent INSERTs during migration could create NULL token_hash
     rows that the pre-flight already passed).
  4. Run ``alembic upgrade head``.
  5. Restart the relay process.
  Total downtime: ~10 seconds (excluding the optional webhook re-key
  coordination, which can happen out-of-band before/after the deploy).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "0007_drop_token_plaintext"
down_revision = "0006_foreign_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Drop ``ix_agents_token`` + ``agents.token`` after a NULL-hash pre-flight.

    Step 1: ``SELECT COUNT(*) FROM agents WHERE token_hash IS NULL``.
    If any rows exist, raise ``RuntimeError`` BEFORE any DDL — the
    operator must re-run alembic ``0003`` backfill OR hard-delete the
    affected rows, because dropping the plaintext column for an agent
    with NULL ``token_hash`` would permanently lock that agent out of
    authentication.

    Step 2: drop ``ix_agents_token`` index AND the ``token`` column in a
    single ``batch_alter_table`` block. SQLite needs ``batch_alter_table``
    for column drops (copy-and-move strategy); Postgres uses native
    ``ALTER`` which the dialect-gated ``render_as_batch`` in env.py
    handles transparently.
    """
    conn = op.get_bind()

    null_hash = conn.execute(sa.text(
        "SELECT COUNT(*) FROM agents WHERE token_hash IS NULL"
    )).scalar()
    if null_hash and int(null_hash) > 0:
        raise RuntimeError(
            f"Pre-flight aborted: {null_hash} agents rows have NULL token_hash. "
            f"This is a Phase 43 backfill regression -- the plaintext token "
            f"column cannot be safely dropped while the authoritative hash is "
            f"missing (auth would silently fail for affected agents). "
            f"Re-run alembic 0003 backfill OR hard-delete the affected rows. "
            f"DO NOT proceed."
        )

    with op.batch_alter_table("agents") as batch_op:
        batch_op.drop_index("ix_agents_token")
        batch_op.drop_column("token")


def downgrade() -> None:
    """IRREVERSIBLE: dropping the plaintext token column drops the plaintext.

    Adding the column back yields a NULL-filled column with no plaintext
    recovery possible. Operators must reissue tokens for every agent.
    """
    raise NotImplementedError(
        "Dropping agents.token is irreversible -- plaintext tokens cannot "
        "be recovered. If you need to roll back to a state with a plaintext "
        "token column, restore from a pre-0007 database snapshot AND reissue "
        "tokens via the register endpoint for every active agent."
    )
