"""foreign_keys

Revision ID: 0006_foreign_keys
Revises: 0005_tz_aware_timestamps
Create Date: 2026-05-04

Phase 47 T7.3a: add 11 ``ForeignKey`` constraints across 9 tables with
explicit ``ON DELETE`` policy.

Per-column policy (RESEARCH Pattern 3 + Code Examples Example 1):

| Table.column                       | Policy   | Rationale                                        |
|-----------------------------------|----------|--------------------------------------------------|
| messages.from_addr                 | RESTRICT | Audit data; sender identity is part of record    |
| messages.to_addr                   | RESTRICT | Audit data; recipient identity is part of record |
| contacts.owner_address             | CASCADE  | Owner gone -> contact book meaningless           |
| contacts.contact_address           | SET NULL | Preserve as tombstone; sever link                |
| handshakes.from_addr               | RESTRICT | Audit data                                       |
| handshakes.to_addr                 | RESTRICT | Audit data                                       |
| webhook_deliveries.agent_address   | CASCADE  | Per-agent operational state                      |
| domain_verifications.agent_address | CASCADE  | Per-agent verification state                     |
| seen_message_ids.from_addr         | CASCADE  | Per-recipient dedup state                        |
| reputation.address                 | CASCADE  | Per-agent reputation                             |
| audit_log.actor_address            | SET NULL | Audit MUST survive actor deletion                |

NEGATIVE: ``reservations.address`` has NO FK (RESEARCH OQ3 -- reservations
exist BEFORE agents do). Documented in the model docstring.

Pre-flight check (Pitfall 1): adding an FK to a table with orphan rows fails
mid-flight on Postgres. Operators MUST run ``scripts/cleanup_orphan_rows.py``
BEFORE this migration. The pre-flight aborts cleanly with a descriptive
RuntimeError if orphans are detected, leaving the DB in the pre-migration
state.

For ``contacts.contact_address`` SET NULL: the column must be nullable. The
upgrade alters the column to nullable BEFORE adding the FK. Downgrade leaves
the column nullable -- reverting to NOT NULL would risk breaking SET-NULL'd
rows that survived a prior agent delete.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = "0006_foreign_keys"
down_revision = "0005_tz_aware_timestamps"
branch_labels = None
depends_on = None


# (child_table, child_col, parent_table, parent_col, ondelete, fk_name)
FOREIGN_KEYS: list[tuple[str, str, str, str, str, str]] = [
    ("messages", "from_addr", "agents", "address", "RESTRICT", "fk_messages_from_addr"),
    ("messages", "to_addr", "agents", "address", "RESTRICT", "fk_messages_to_addr"),
    ("contacts", "owner_address", "agents", "address", "CASCADE", "fk_contacts_owner"),
    ("contacts", "contact_address", "agents", "address", "SET NULL", "fk_contacts_contact"),
    ("handshakes", "from_addr", "agents", "address", "RESTRICT", "fk_handshakes_from"),
    ("handshakes", "to_addr", "agents", "address", "RESTRICT", "fk_handshakes_to"),
    ("webhook_deliveries", "agent_address", "agents", "address", "CASCADE", "fk_webhook_deliveries_agent"),
    ("domain_verifications", "agent_address", "agents", "address", "CASCADE", "fk_domain_verifications_agent"),
    ("seen_message_ids", "from_addr", "agents", "address", "CASCADE", "fk_seen_messages_from"),
    ("reputation", "address", "agents", "address", "CASCADE", "fk_reputation_address"),
    ("audit_log", "actor_address", "agents", "address", "SET NULL", "fk_audit_log_actor"),
]


def _check_no_orphans(
    conn,
    child_table: str,
    child_col: str,
    parent_table: str,
    parent_col: str,
) -> None:
    """Pre-flight: assert no orphan rows before adding FK.

    Pitfall 1: adding an FK to a table with orphan rows fails mid-flight on
    Postgres. This check aborts cleanly BEFORE any DDL runs, so the DB is
    left in the pre-migration state and the operator can run cleanup.
    """
    sql = sa.text(
        f"SELECT COUNT(*) FROM {child_table} "
        f"WHERE {child_col} IS NOT NULL "
        f"AND {child_col} NOT IN (SELECT {parent_col} FROM {parent_table})"
    )
    orphans = int(conn.execute(sql).scalar() or 0)
    if orphans:
        raise RuntimeError(
            f"Pre-flight aborted: {orphans} orphan rows in "
            f"{child_table}.{child_col} (NOT IN {parent_table}.{parent_col}). "
            f"Run scripts/cleanup_orphan_rows.py --commit before retrying. "
            f"See .planning/phases/47-.../47-RESEARCH.md Pitfall 1."
        )


def _fks_by_table(fks: list[tuple[str, str, str, str, str, str]]) -> dict[str, list[tuple[str, str, str, str, str, str]]]:
    """Group FOREIGN_KEYS by child table for batch operations."""
    out: dict[str, list[tuple[str, str, str, str, str, str]]] = {}
    for entry in fks:
        out.setdefault(entry[0], []).append(entry)
    return out


def upgrade() -> None:
    """Add 11 FKs after a pre-flight orphan-row check.

    Step 1: scan every (child_table, child_col) pair for orphan rows. If any
    table has orphans, raise RuntimeError BEFORE any DDL is issued, so the
    operator can run scripts/cleanup_orphan_rows.py and retry cleanly.

    Step 2: alter contacts.contact_address to nullable (required for SET
    NULL policy per Pitfall 7) AND add the contacts FKs in the same batch
    (SQLite cannot ALTER constraints without table rebuild via batch mode).

    Step 3: add the remaining FKs in a per-table batch_alter_table block so
    SQLite's copy-and-move strategy is used (Pitfall 2 / Pitfall 7).
    """
    conn = op.get_bind()

    # Step 1: pre-flight orphan check on EVERY FK before adding any DDL.
    for child_t, child_c, parent_t, parent_c, _ondelete, _name in FOREIGN_KEYS:
        _check_no_orphans(conn, child_t, child_c, parent_t, parent_c)

    # Step 2 + 3: per-table batch ALTER. For ``contacts`` we both make
    # contact_address nullable AND add both FKs in a single batch so SQLite
    # rebuilds the table once.
    grouped = _fks_by_table(FOREIGN_KEYS)
    for child_table, entries in grouped.items():
        with op.batch_alter_table(child_table) as batch_op:
            if child_table == "contacts":
                batch_op.alter_column(
                    "contact_address",
                    existing_type=sa.String(),
                    nullable=True,
                )
            for _ct, child_col, parent_table, parent_col, ondelete, fk_name in entries:
                batch_op.create_foreign_key(
                    fk_name,
                    referent_table=parent_table,
                    local_cols=[child_col],
                    remote_cols=[parent_col],
                    ondelete=ondelete,
                )


def downgrade() -> None:
    """Drop the 11 FKs in reverse-add order via per-table batch ALTER.

    contacts.contact_address is left nullable -- reverting to NOT NULL would
    risk breaking SET-NULL'd rows that survived a prior agent delete in the
    upgraded state.
    """
    grouped = _fks_by_table(FOREIGN_KEYS)
    # Reverse table order for symmetry with upgrade ordering.
    for child_table in reversed(list(grouped.keys())):
        with op.batch_alter_table(child_table) as batch_op:
            for _ct, _cc, _pt, _pc, _ondelete, fk_name in reversed(
                grouped[child_table]
            ):
                batch_op.drop_constraint(fk_name, type_="foreignkey")
