"""Failing-by-design FK enforcement tests (T7.3a) — 12 FKs across 9 tables.

Per RESEARCH Pattern 3 + Code Examples Example 1.
PRAGMA foreign_keys=ON is installed via tests/db/conftest.py (Pitfall 2).

These tests RED at HEAD because alembic/versions/0006_foreign_keys.py does not
exist. They GREEN after 47-07 lands the FK migration.

ondelete policy reference (per RESEARCH Pattern 3):
    messages.from_addr           -> ondelete=RESTRICT (block agent delete)
    messages.to_addr             -> ondelete=RESTRICT
    handshakes.from_addr         -> ondelete=RESTRICT
    handshakes.to_addr           -> ondelete=RESTRICT
    contacts.owner_address       -> ondelete=CASCADE  (delete owner -> contact gone)
    contacts.contact_address     -> ondelete=SET NULL (delete contact -> NULL ref)
    webhook_deliveries.agent     -> ondelete=CASCADE
    domain_verifications.agent   -> ondelete=CASCADE
    seen_message_ids.from_addr   -> ondelete=CASCADE
    reputation.address           -> ondelete=CASCADE
    audit_log.actor_address      -> ondelete=SET NULL (audit row survives)
    reservations.address         -> NO FK (RESEARCH OQ3 — denormalized)
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


@pytest.fixture
def db_with_head(tmp_path):
    """Spin up a SQLite DB at alembic head, return path."""
    db_path = tmp_path / "test_fk.db"
    db_url = f"sqlite+aiosqlite:///{db_path}"
    os.environ["DATABASE_URL"] = db_url
    project_root = Path(__file__).resolve().parents[2]
    cfg = Config(str(project_root / "alembic.ini"))
    command.upgrade(cfg, "head")
    yield db_path
    os.environ.pop("DATABASE_URL", None)


def _conn(db_path):
    c = sqlite3.connect(str(db_path))
    c.execute("PRAGMA foreign_keys=ON")
    return c


def _seed_agent(conn, address="alice::test.local"):
    """Insert an agent row, populating both `token` (legacy NOT NULL pre-T7.5)
    and `token_hash` (Phase 43 column). 47-08 will DROP the `token` column;
    after that, this defensive INSERT will fail and we'll need to drop the
    `token` value here. Until then, both must be populated.
    """
    cols = [r[1] for r in conn.execute("PRAGMA table_info(agents)").fetchall()]
    if "token" in cols:
        conn.execute(
            "INSERT INTO agents (address, public_key, token, token_hash, status, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, 'active', "
            "datetime('now'), datetime('now'))",
            (address, "pk", f"plaintext-{address}", f"hash-{address}"),
        )
    else:
        conn.execute(
            "INSERT INTO agents (address, public_key, token_hash, status, "
            "created_at, updated_at) VALUES (?, ?, ?, 'active', "
            "datetime('now'), datetime('now'))",
            (address, "pk", f"hash-{address}"),
        )
    conn.commit()


# ---- RESTRICT: messages.from_addr / to_addr ---------------------------------

def test_messages_from_addr_restrict_blocks_orphan_insert(db_with_head):
    """T7.3a: insert message with non-existent from_addr -> IntegrityError."""
    conn = _conn(db_with_head)
    _seed_agent(conn, "alice::test.local")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO messages (message_id, envelope, status, from_addr, "
            "to_addr, retry_count, created_at) VALUES "
            "(?, ?, ?, ?, ?, 0, datetime('now'))",
            ("m1", "{}", "queued", "ghost::nowhere.example",
             "alice::test.local"),
        )
        conn.commit()


def test_messages_delete_agent_with_messages_blocked(db_with_head):
    """T7.3a RESTRICT: DELETE agent with messages -> IntegrityError."""
    conn = _conn(db_with_head)
    _seed_agent(conn, "alice::test.local")
    _seed_agent(conn, "bob::test.local")
    conn.execute(
        "INSERT INTO messages (message_id, envelope, status, from_addr, "
        "to_addr, retry_count, created_at) VALUES "
        "(?, ?, ?, ?, ?, 0, datetime('now'))",
        ("m1", "{}", "queued", "alice::test.local", "bob::test.local"),
    )
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM agents WHERE address = ?", ("alice::test.local",))
        conn.commit()


# ---- RESTRICT: handshakes ---------------------------------------------------

def test_handshakes_from_addr_restrict(db_with_head):
    """T7.3a RESTRICT: insert handshake with non-existent from_addr -> IntegrityError."""
    conn = _conn(db_with_head)
    _seed_agent(conn, "alice::test.local")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO handshakes (from_addr, to_addr, status, created_at) "
            "VALUES (?, ?, 'pending', datetime('now'))",
            ("ghost::nowhere.example", "alice::test.local"),
        )
        conn.commit()


# ---- CASCADE: contacts.owner_address ----------------------------------------

def test_contacts_owner_cascade_on_agent_delete(db_with_head):
    """T7.3a CASCADE: delete owner agent -> contact rows deleted."""
    conn = _conn(db_with_head)
    _seed_agent(conn, "alice::test.local")
    _seed_agent(conn, "bob::test.local")
    conn.execute(
        "INSERT INTO contacts (owner_address, contact_address, "
        "trust_state, created_at, updated_at) "
        "VALUES (?, ?, 'unknown', datetime('now'), datetime('now'))",
        ("alice::test.local", "bob::test.local"),
    )
    conn.commit()
    # alice has zero messages here, so RESTRICT on messages is fine.
    conn.execute("DELETE FROM agents WHERE address = ?", ("alice::test.local",))
    conn.commit()
    rows = conn.execute(
        "SELECT COUNT(*) FROM contacts WHERE owner_address = ?",
        ("alice::test.local",),
    ).fetchone()
    assert rows[0] == 0, "Contacts owned by alice should have CASCADE-deleted"


# ---- SET NULL: contacts.contact_address -------------------------------------

def test_contacts_contact_set_null_on_agent_delete(db_with_head):
    """T7.3a SET NULL: delete contact agent -> contacts.contact_address becomes NULL."""
    conn = _conn(db_with_head)
    _seed_agent(conn, "alice::test.local")
    _seed_agent(conn, "bob::test.local")
    conn.execute(
        "INSERT INTO contacts (owner_address, contact_address, "
        "trust_state, created_at, updated_at) "
        "VALUES (?, ?, 'unknown', datetime('now'), datetime('now'))",
        ("alice::test.local", "bob::test.local"),
    )
    conn.commit()
    conn.execute("DELETE FROM agents WHERE address = ?", ("bob::test.local",))
    conn.commit()
    row = conn.execute(
        "SELECT contact_address FROM contacts WHERE owner_address = ?",
        ("alice::test.local",),
    ).fetchone()
    assert row[0] is None, "contact_address should be NULL after referenced agent deleted"


# ---- CASCADE: webhook_deliveries.agent_address ------------------------------

def test_webhook_deliveries_cascade_on_agent_delete(db_with_head):
    """T7.3a CASCADE: delete agent -> webhook_deliveries rows deleted."""
    conn = _conn(db_with_head)
    _seed_agent(conn, "alice::test.local")
    conn.execute(
        "INSERT INTO webhook_deliveries (agent_address, message_id, "
        "envelope, status, attempt_count, created_at) "
        "VALUES (?, ?, ?, 'pending', 0, datetime('now'))",
        ("alice::test.local", "m1", "{}"),
    )
    conn.commit()
    conn.execute("DELETE FROM agents WHERE address = ?", ("alice::test.local",))
    conn.commit()
    n = conn.execute(
        "SELECT COUNT(*) FROM webhook_deliveries WHERE agent_address = ?",
        ("alice::test.local",),
    ).fetchone()[0]
    assert n == 0


# ---- CASCADE: domain_verifications.agent_address ---------------------------

def test_domain_verifications_cascade_on_agent_delete(db_with_head):
    """T7.3a CASCADE: delete agent -> domain_verifications rows deleted."""
    conn = _conn(db_with_head)
    _seed_agent(conn, "alice::test.local")
    conn.execute(
        "INSERT INTO domain_verifications (agent_address, domain, public_key, "
        "method, status, verified_at, last_checked, ttl_hours) "
        "VALUES (?, ?, 'pk', 'dns', 'verified', datetime('now'), datetime('now'), 24)",
        ("alice::test.local", "alice.example.com"),
    )
    conn.commit()
    conn.execute("DELETE FROM agents WHERE address = ?", ("alice::test.local",))
    conn.commit()
    n = conn.execute(
        "SELECT COUNT(*) FROM domain_verifications WHERE agent_address = ?",
        ("alice::test.local",),
    ).fetchone()[0]
    assert n == 0


# ---- CASCADE: seen_message_ids.from_addr ------------------------------------

def test_seen_message_ids_cascade_on_agent_delete(db_with_head):
    """T7.3a CASCADE: delete agent -> seen_message_ids rows deleted."""
    conn = _conn(db_with_head)
    _seed_agent(conn, "alice::test.local")
    conn.execute(
        "INSERT INTO seen_message_ids (message_id, from_addr, seen_at) "
        "VALUES (?, ?, datetime('now'))",
        ("seen-1", "alice::test.local"),
    )
    conn.commit()
    conn.execute("DELETE FROM agents WHERE address = ?", ("alice::test.local",))
    conn.commit()
    n = conn.execute("SELECT COUNT(*) FROM seen_message_ids").fetchone()[0]
    assert n == 0


# ---- CASCADE: reputation.address --------------------------------------------

def test_reputation_cascade_on_agent_delete(db_with_head):
    """T7.3a CASCADE: delete agent -> reputation row deleted."""
    conn = _conn(db_with_head)
    _seed_agent(conn, "alice::test.local")
    conn.execute(
        "INSERT INTO reputation (address, score, messages_sent, messages_rejected, "
        "created_at, updated_at) VALUES (?, 50, 0, 0, datetime('now'), datetime('now'))",
        ("alice::test.local",),
    )
    conn.commit()
    conn.execute("DELETE FROM agents WHERE address = ?", ("alice::test.local",))
    conn.commit()
    n = conn.execute("SELECT COUNT(*) FROM reputation").fetchone()[0]
    assert n == 0


# ---- SET NULL: audit_log.actor_address --------------------------------------

def test_audit_log_actor_set_null_on_agent_delete(db_with_head):
    """T7.3a SET NULL: delete actor agent -> audit_log.actor_address becomes NULL.

    Audit data MUST survive actor deletion (compliance / forensics).
    """
    conn = _conn(db_with_head)
    _seed_agent(conn, "alice::test.local")
    conn.execute(
        "INSERT INTO audit_log (entity_type, entity_id, action, "
        "actor_address, timestamp) "
        "VALUES ('agent', 'alice::test.local', 'register', ?, datetime('now'))",
        ("alice::test.local",),
    )
    conn.commit()
    conn.execute("DELETE FROM agents WHERE address = ?", ("alice::test.local",))
    conn.commit()
    row = conn.execute(
        "SELECT actor_address FROM audit_log WHERE entity_id = ?",
        ("alice::test.local",),
    ).fetchone()
    assert row is not None, "Audit log entry MUST survive actor deletion"
    assert row[0] is None, "actor_address must be NULL after referenced agent deleted"


# ---- NEGATIVE: reservations.address has NO FK (RESEARCH OQ3) ----------------

def test_reservations_address_has_no_fk(db_with_head):
    """RESEARCH OQ3: reservations.address is intentionally a denormalized string.

    Reservations exist BEFORE agents do — adding FK would prevent the workflow.
    """
    conn = _conn(db_with_head)
    # Insert a reservation for an address that has NO agent yet — must succeed.
    conn.execute(
        "INSERT INTO reservations (address, claim_token, status, ip_address, "
        "created_at, expires_at) VALUES (?, ?, 'reserved', '127.0.0.1', "
        "datetime('now'), datetime('now', '+48 hours'))",
        ("future-agent::test.local", "tok-1"),
    )
    conn.commit()  # Must NOT raise — confirms no FK constraint
    n = conn.execute(
        "SELECT COUNT(*) FROM reservations WHERE address = ?",
        ("future-agent::test.local",),
    ).fetchone()[0]
    assert n == 1
