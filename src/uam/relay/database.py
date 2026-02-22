"""SQLite database schema, initialization, and query helpers for the relay."""

from __future__ import annotations

import json
import logging
from typing import Any

import aiosqlite

logger = logging.getLogger(__name__)

SCHEMA = """\
CREATE TABLE IF NOT EXISTS agents (
    address     TEXT PRIMARY KEY,
    public_key  TEXT NOT NULL,
    token       TEXT NOT NULL UNIQUE,
    webhook_url TEXT,
    last_seen   TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    from_addr   TEXT NOT NULL,
    to_addr     TEXT NOT NULL,
    envelope    TEXT NOT NULL,
    delivered   INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_agents_token ON agents(token);
CREATE INDEX IF NOT EXISTS idx_messages_to_addr ON messages(to_addr, delivered);
CREATE INDEX IF NOT EXISTS idx_messages_delivered ON messages(delivered, created_at);

CREATE TABLE IF NOT EXISTS domain_verifications (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_address   TEXT NOT NULL,
    domain          TEXT NOT NULL,
    public_key      TEXT NOT NULL,
    method          TEXT NOT NULL DEFAULT 'dns',
    verified_at     TEXT NOT NULL DEFAULT (datetime('now')),
    last_checked    TEXT NOT NULL DEFAULT (datetime('now')),
    ttl_hours       INTEGER NOT NULL DEFAULT 24,
    status          TEXT NOT NULL DEFAULT 'verified',
    UNIQUE(agent_address, domain),
    FOREIGN KEY (agent_address) REFERENCES agents(address)
);

CREATE INDEX IF NOT EXISTS idx_domain_verifications_domain
    ON domain_verifications(domain);
CREATE INDEX IF NOT EXISTS idx_domain_verifications_status
    ON domain_verifications(status, last_checked);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_address   TEXT NOT NULL,
    message_id      TEXT NOT NULL,
    envelope        TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    last_status_code INTEGER,
    last_error      TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at    TEXT,
    FOREIGN KEY (agent_address) REFERENCES agents(address)
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_agent
    ON webhook_deliveries(agent_address, status);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status
    ON webhook_deliveries(status, created_at);

CREATE TABLE IF NOT EXISTS reputation (
    address          TEXT PRIMARY KEY,
    score            INTEGER NOT NULL DEFAULT 30,
    messages_sent    INTEGER NOT NULL DEFAULT 0,
    messages_rejected INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at       TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (address) REFERENCES agents(address)
);

CREATE INDEX IF NOT EXISTS idx_reputation_score ON reputation(score);

CREATE TABLE IF NOT EXISTS blocklist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern     TEXT NOT NULL UNIQUE,
    reason      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS allowlist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern     TEXT NOT NULL UNIQUE,
    reason      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


async def _migrate(db: aiosqlite.Connection) -> None:
    """Run additive schema migrations using PRAGMA user_version.

    Each migration block checks the current version and applies changes
    incrementally.  Existing tables (from SCHEMA) are never modified here.
    """
    cursor = await db.execute("PRAGMA user_version")
    row = await cursor.fetchone()
    version = row[0]

    if version < 1:
        logger.info("Relay DB migration: applying version 1 (seen_message_ids)")
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS seen_message_ids (
                message_id TEXT PRIMARY KEY,
                from_addr  TEXT NOT NULL,
                seen_at    TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        await db.execute("PRAGMA user_version = 1")
        await db.commit()

    if version < 2:
        logger.info("Relay DB migration: applying version 2 (expires column)")
        await db.execute(
            "ALTER TABLE messages ADD COLUMN expires TEXT"
        )
        await db.execute("PRAGMA user_version = 2")
        await db.commit()

    if version < 3:
        logger.info("Relay DB migration: applying version 3 (last_seen column)")
        try:
            await db.execute(
                "ALTER TABLE agents ADD COLUMN last_seen TEXT"
            )
        except Exception:
            pass  # Column already exists (fresh DB has it in SCHEMA)
        await db.execute("PRAGMA user_version = 3")
        await db.commit()


async def init_db(path: str) -> aiosqlite.Connection:
    """Open the database, apply pragmas and schema, return the connection."""
    db = await aiosqlite.connect(path)
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA busy_timeout=5000")
    await db.execute("PRAGMA synchronous=NORMAL")
    await db.execute("PRAGMA foreign_keys=ON")
    db.row_factory = aiosqlite.Row
    await db.executescript(SCHEMA)
    await db.commit()
    await _migrate(db)
    return db


async def close_db(db: aiosqlite.Connection) -> None:
    """Close the database connection."""
    await db.close()


# ---------------------------------------------------------------------------
# Message dedup helpers (MSG-03)
# ---------------------------------------------------------------------------


async def record_message_id(
    db: aiosqlite.Connection, message_id: str, from_addr: str
) -> bool:
    """Record a message_id as seen.  Returns ``True`` if new, ``False`` if duplicate.

    Uses INSERT OR IGNORE so the primary-key constraint is the single
    source of truth -- safe under concurrent access.
    """
    cursor = await db.execute(
        "INSERT OR IGNORE INTO seen_message_ids (message_id, from_addr) VALUES (?, ?)",
        (message_id, from_addr),
    )
    await db.commit()
    return cursor.rowcount == 1


async def cleanup_expired_dedup(db: aiosqlite.Connection, max_age_days: int = 7) -> int:
    """Delete dedup entries older than *max_age_days*.  Returns count deleted."""
    cursor = await db.execute(
        "DELETE FROM seen_message_ids WHERE datetime(seen_at, '+' || ? || ' days') < datetime('now')",
        (str(max_age_days),),
    )
    await db.commit()
    return cursor.rowcount


# ---------------------------------------------------------------------------
# Message expiry helpers (MSG-04)
# ---------------------------------------------------------------------------


async def cleanup_expired_messages(db: aiosqlite.Connection) -> int:
    """Delete stored messages whose ``expires`` timestamp is in the past.

    Only deletes undelivered messages (``delivered = 0``).  Returns count
    deleted.
    """
    cursor = await db.execute(
        "DELETE FROM messages WHERE delivered = 0 "
        "AND expires IS NOT NULL AND datetime(replace(expires, 'Z', '+00:00')) <= datetime('now')"
    )
    await db.commit()
    return cursor.rowcount


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


async def get_agent_by_token(db: aiosqlite.Connection, token: str) -> dict[str, Any] | None:
    """Look up an agent by token. Returns {address, public_key} or None."""
    cursor = await db.execute(
        "SELECT address, public_key FROM agents WHERE token = ?", (token,)
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return {"address": row["address"], "public_key": row["public_key"]}


async def get_agent_by_address(db: aiosqlite.Connection, address: str) -> dict[str, Any] | None:
    """Look up an agent by address. Returns {address, public_key, token, webhook_url, last_seen} or None."""
    cursor = await db.execute(
        "SELECT address, public_key, token, webhook_url, last_seen FROM agents WHERE address = ?", (address,)
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return {
        "address": row["address"],
        "public_key": row["public_key"],
        "token": row["token"],
        "webhook_url": row["webhook_url"],
        "last_seen": row["last_seen"],
    }


async def update_agent_last_seen(db: aiosqlite.Connection, address: str) -> None:
    """Persist the last_seen timestamp for an agent (UTC ISO-8601)."""
    await db.execute(
        "UPDATE agents SET last_seen = datetime('now') WHERE address = ?",
        (address,),
    )
    await db.commit()


async def register_agent(
    db: aiosqlite.Connection, address: str, public_key: str, token: str
) -> None:
    """Insert a new agent record."""
    await db.execute(
        "INSERT INTO agents (address, public_key, token) VALUES (?, ?, ?)",
        (address, public_key, token),
    )
    await db.commit()


async def store_message(
    db: aiosqlite.Connection,
    from_addr: str,
    to_addr: str,
    envelope_json: str,
    expires: str | None = None,
) -> int:
    """Store an envelope for offline delivery. Returns the row ID."""
    cursor = await db.execute(
        "INSERT INTO messages (from_addr, to_addr, envelope, expires) VALUES (?, ?, ?, ?)",
        (from_addr, to_addr, envelope_json, expires),
    )
    await db.commit()
    return cursor.lastrowid  # type: ignore[return-value]


async def get_stored_messages(
    db: aiosqlite.Connection, to_addr: str, limit: int = 50
) -> list[dict[str, Any]]:
    """Fetch undelivered messages for an address, ordered by ID ascending.

    Each returned dict has ``"id"`` (int) and ``"envelope"`` (parsed dict).
    """
    cursor = await db.execute(
        "SELECT id, envelope FROM messages WHERE to_addr = ? AND delivered = 0 "
        "AND (expires IS NULL OR datetime(replace(expires, 'Z', '+00:00')) > datetime('now')) "
        "ORDER BY id ASC LIMIT ?",
        (to_addr, limit),
    )
    rows = await cursor.fetchall()
    return [{"id": row["id"], "envelope": json.loads(row["envelope"])} for row in rows]


async def mark_messages_delivered(db: aiosqlite.Connection, message_ids: list[int]) -> None:
    """Mark messages as delivered by their IDs."""
    if not message_ids:
        return
    placeholders = ",".join("?" for _ in message_ids)
    await db.execute(
        f"UPDATE messages SET delivered = 1 WHERE id IN ({placeholders})",
        message_ids,
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Domain verification helpers (DNS-04)
# ---------------------------------------------------------------------------


async def upsert_domain_verification(
    db: aiosqlite.Connection,
    agent_address: str,
    domain: str,
    public_key: str,
    method: str,
    ttl_hours: int,
) -> None:
    """Insert or update a domain verification record."""
    await db.execute(
        """INSERT INTO domain_verifications (agent_address, domain, public_key, method, ttl_hours)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(agent_address, domain) DO UPDATE SET
             public_key = excluded.public_key,
             method = excluded.method,
             verified_at = datetime('now'),
             last_checked = datetime('now'),
             ttl_hours = excluded.ttl_hours,
             status = 'verified'""",
        (agent_address, domain, public_key, method, ttl_hours),
    )
    await db.commit()


async def get_domain_verification(
    db: aiosqlite.Connection, agent_address: str
) -> dict[str, Any] | None:
    """Get the verified domain for an agent, or None."""
    cursor = await db.execute(
        "SELECT domain, method, status, verified_at FROM domain_verifications "
        "WHERE agent_address = ? AND status = 'verified'",
        (agent_address,),
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return {
        "domain": row["domain"],
        "method": row["method"],
        "status": row["status"],
        "verified_at": row["verified_at"],
    }


async def get_expired_verifications(db: aiosqlite.Connection) -> list[dict[str, Any]]:
    """Get verifications where last_checked + ttl_hours < now()."""
    cursor = await db.execute(
        """SELECT id, agent_address, domain, public_key, method
           FROM domain_verifications
           WHERE status = 'verified'
             AND datetime(last_checked, '+' || ttl_hours || ' hours') < datetime('now')""",
    )
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def update_verification_timestamp(
    db: aiosqlite.Connection, verification_id: int
) -> None:
    """Update last_checked to now for a successful re-verification."""
    await db.execute(
        "UPDATE domain_verifications SET last_checked = datetime('now') WHERE id = ?",
        (verification_id,),
    )
    await db.commit()


async def downgrade_verification(
    db: aiosqlite.Connection, verification_id: int
) -> None:
    """Downgrade a verification to expired status."""
    await db.execute(
        "UPDATE domain_verifications SET status = 'expired' WHERE id = ?",
        (verification_id,),
    )
    await db.commit()


# ---------------------------------------------------------------------------
# Webhook delivery helpers (HOOK-06)
# ---------------------------------------------------------------------------


async def get_agent_with_webhook(
    db: aiosqlite.Connection, address: str
) -> dict[str, Any] | None:
    """Look up an agent with a configured webhook URL.

    Returns ``{address, public_key, token, webhook_url}`` or ``None``
    if the agent does not exist or has no webhook URL set.
    """
    cursor = await db.execute(
        "SELECT address, public_key, token, webhook_url FROM agents "
        "WHERE address = ? AND webhook_url IS NOT NULL AND webhook_url != ''",
        (address,),
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return {
        "address": row["address"],
        "public_key": row["public_key"],
        "token": row["token"],
        "webhook_url": row["webhook_url"],
    }


async def create_webhook_delivery(
    db: aiosqlite.Connection,
    agent_address: str,
    message_id: str,
    envelope_json: str,
) -> int:
    """Create a pending webhook delivery record.  Returns the row ID."""
    cursor = await db.execute(
        "INSERT INTO webhook_deliveries (agent_address, message_id, envelope, status) "
        "VALUES (?, ?, ?, 'pending')",
        (agent_address, message_id, envelope_json),
    )
    await db.commit()
    return cursor.lastrowid  # type: ignore[return-value]


async def update_webhook_delivery_attempt(
    db: aiosqlite.Connection,
    delivery_id: int,
    attempt_count: int,
    status_code: int | None,
    error: str | None,
) -> None:
    """Record an individual delivery attempt (in-progress update)."""
    await db.execute(
        "UPDATE webhook_deliveries "
        "SET attempt_count = ?, last_status_code = ?, last_error = ?, status = 'in_progress' "
        "WHERE id = ?",
        (attempt_count, status_code, error, delivery_id),
    )
    await db.commit()


async def complete_webhook_delivery(
    db: aiosqlite.Connection,
    delivery_id: int,
    status: str,
    error: str | None = None,
) -> None:
    """Mark a delivery as completed (``succeeded`` or ``failed``)."""
    await db.execute(
        "UPDATE webhook_deliveries "
        "SET status = ?, last_error = ?, completed_at = datetime('now') "
        "WHERE id = ?",
        (status, error, delivery_id),
    )
    await db.commit()


async def get_webhook_deliveries(
    db: aiosqlite.Connection, agent_address: str, limit: int = 50
) -> list[dict[str, Any]]:
    """Fetch recent webhook deliveries for an agent, newest first."""
    cursor = await db.execute(
        "SELECT id, message_id, status, attempt_count, last_status_code, "
        "last_error, created_at, completed_at "
        "FROM webhook_deliveries WHERE agent_address = ? ORDER BY id DESC LIMIT ?",
        (agent_address, limit),
    )
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def update_agent_webhook_url(
    db: aiosqlite.Connection, address: str, webhook_url: str | None
) -> None:
    """Set or clear the webhook URL for an agent."""
    await db.execute(
        "UPDATE agents SET webhook_url = ? WHERE address = ?",
        (webhook_url, address),
    )
    await db.commit()
