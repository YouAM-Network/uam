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
    expires     TEXT,
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

-- Tables previously only in migrations (now in SCHEMA as single source of truth):

CREATE TABLE IF NOT EXISTS seen_message_ids (
    message_id TEXT PRIMARY KEY,
    from_addr  TEXT NOT NULL,
    seen_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS known_relays (
    domain          TEXT PRIMARY KEY,
    federation_url  TEXT NOT NULL,
    public_key      TEXT NOT NULL,
    discovered_via  TEXT NOT NULL DEFAULT 'well-known',
    last_verified   TEXT NOT NULL DEFAULT (datetime('now')),
    ttl_hours       INTEGER NOT NULL DEFAULT 1,
    status          TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE IF NOT EXISTS federation_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id      TEXT NOT NULL,
    from_relay      TEXT NOT NULL,
    to_relay        TEXT NOT NULL,
    direction       TEXT NOT NULL,
    hop_count       INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL,
    error           TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_federation_log_message
    ON federation_log(message_id);
CREATE INDEX IF NOT EXISTS idx_federation_log_relay
    ON federation_log(from_relay, created_at);

CREATE TABLE IF NOT EXISTS relay_blocklist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL UNIQUE,
    reason      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS relay_allowlist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain      TEXT NOT NULL UNIQUE,
    reason      TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS relay_reputation (
    domain              TEXT PRIMARY KEY,
    score               INTEGER NOT NULL DEFAULT 50,
    messages_forwarded  INTEGER NOT NULL DEFAULT 0,
    messages_rejected   INTEGER NOT NULL DEFAULT 0,
    last_success        TEXT,
    last_failure        TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS federation_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_domain   TEXT NOT NULL,
    envelope        TEXT NOT NULL,
    via             TEXT NOT NULL DEFAULT '[]',
    hop_count       INTEGER NOT NULL DEFAULT 0,
    attempt_count   INTEGER NOT NULL DEFAULT 0,
    next_retry      TEXT NOT NULL DEFAULT (datetime('now')),
    status          TEXT NOT NULL DEFAULT 'pending',
    error           TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_federation_queue_status
    ON federation_queue(status, next_retry);
CREATE INDEX IF NOT EXISTS idx_federation_queue_domain
    ON federation_queue(target_domain, status);
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
        try:
            await db.execute(
                "ALTER TABLE messages ADD COLUMN expires TEXT"
            )
        except Exception:
            pass  # Column already exists (fresh DB has it in SCHEMA)
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

    if version < 4:
        logger.info("Relay DB migration: applying version 4 (known_relays)")
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS known_relays (
                domain          TEXT PRIMARY KEY,
                federation_url  TEXT NOT NULL,
                public_key      TEXT NOT NULL,
                discovered_via  TEXT NOT NULL DEFAULT 'well-known',
                last_verified   TEXT NOT NULL DEFAULT (datetime('now')),
                ttl_hours       INTEGER NOT NULL DEFAULT 1,
                status          TEXT NOT NULL DEFAULT 'active'
            )
            """
        )
        await db.execute("PRAGMA user_version = 4")
        await db.commit()

    if version < 5:
        logger.info("Relay DB migration: applying version 5 (federation_log)")
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS federation_log (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id      TEXT NOT NULL,
                from_relay      TEXT NOT NULL,
                to_relay        TEXT NOT NULL,
                direction       TEXT NOT NULL,
                hop_count       INTEGER NOT NULL DEFAULT 0,
                status          TEXT NOT NULL,
                error           TEXT,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_federation_log_message "
            "ON federation_log(message_id)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_federation_log_relay "
            "ON federation_log(from_relay, created_at)"
        )
        await db.execute("PRAGMA user_version = 5")
        await db.commit()

    if version < 6:
        logger.info("Relay DB migration: applying version 6 (relay_blocklist, relay_allowlist)")
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS relay_blocklist (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                domain      TEXT NOT NULL UNIQUE,
                reason      TEXT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS relay_allowlist (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                domain      TEXT NOT NULL UNIQUE,
                reason      TEXT,
                created_at  TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        await db.execute("PRAGMA user_version = 6")
        await db.commit()

    if version < 7:
        logger.info("Relay DB migration: applying version 7 (relay_reputation)")
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS relay_reputation (
                domain              TEXT PRIMARY KEY,
                score               INTEGER NOT NULL DEFAULT 50,
                messages_forwarded  INTEGER NOT NULL DEFAULT 0,
                messages_rejected   INTEGER NOT NULL DEFAULT 0,
                last_success        TEXT,
                last_failure        TEXT,
                created_at          TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at          TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        await db.execute("PRAGMA user_version = 7")
        await db.commit()

    if version < 8:
        logger.info("Relay DB migration: applying version 8 (federation_queue)")
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS federation_queue (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                target_domain   TEXT NOT NULL,
                envelope        TEXT NOT NULL,
                via             TEXT NOT NULL DEFAULT '[]',
                hop_count       INTEGER NOT NULL DEFAULT 0,
                attempt_count   INTEGER NOT NULL DEFAULT 0,
                next_retry      TEXT NOT NULL DEFAULT (datetime('now')),
                status          TEXT NOT NULL DEFAULT 'pending',
                error           TEXT,
                created_at      TEXT NOT NULL DEFAULT (datetime('now'))
            )
            """
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_federation_queue_status "
            "ON federation_queue(status, next_retry)"
        )
        await db.execute(
            "CREATE INDEX IF NOT EXISTS idx_federation_queue_domain "
            "ON federation_queue(target_domain, status)"
        )
        await db.execute("PRAGMA user_version = 8")
        await db.commit()

    if version < 9:
        logger.info("Relay DB migration: applying version 9 (agents token + webhook_url columns)")
        # Old DBs may have api_key instead of token. Detect and migrate.
        cursor = await db.execute("PRAGMA table_info(agents)")
        columns = {row[1] for row in await cursor.fetchall()}
        has_api_key = "api_key" in columns
        has_token = "token" in columns

        if has_api_key and not has_token:
            # Rename api_key -> token via table rebuild (SQLite can't rename columns pre-3.25)
            logger.info("Renaming agents.api_key -> token")
            await db.executescript("""
                CREATE TABLE agents_new (
                    address     TEXT PRIMARY KEY,
                    public_key  TEXT NOT NULL,
                    token       TEXT UNIQUE,
                    webhook_url TEXT,
                    last_seen   TEXT,
                    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
                );
                INSERT INTO agents_new (address, public_key, token, webhook_url, last_seen, created_at)
                    SELECT address, public_key, api_key, webhook_url, last_seen, created_at
                    FROM agents;
                DROP TABLE agents;
                ALTER TABLE agents_new RENAME TO agents;
            """)
        else:
            # Add missing columns
            for col, col_def in [
                ("token", "TEXT"),
                ("webhook_url", "TEXT"),
            ]:
                try:
                    await db.execute(f"ALTER TABLE agents ADD COLUMN {col} {col_def}")
                except Exception:
                    pass  # Column already exists

        # Backfill: agents without a token get a random one
        import secrets as _secrets
        cursor = await db.execute("SELECT address FROM agents WHERE token IS NULL")
        rows = await cursor.fetchall()
        for row in rows:
            await db.execute(
                "UPDATE agents SET token = ? WHERE address = ?",
                (_secrets.token_urlsafe(32), row[0]),
            )
        # Create unique index if not exists
        try:
            await db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_agents_token ON agents(token)")
        except Exception:
            pass
        await db.execute("PRAGMA user_version = 9")
        await db.commit()

    if version < 10:
        logger.info("Relay DB migration: applying version 10 (api_key -> token rename)")
        # v9 shipped without the api_key detection. Re-run for DBs stuck at v9
        # with the old api_key column still present.
        cursor = await db.execute("PRAGMA table_info(agents)")
        columns = {row[1] for row in await cursor.fetchall()}
        if "api_key" in columns:
            logger.info("Renaming agents.api_key -> token (v10)")
            await db.executescript("""
                CREATE TABLE agents_new (
                    address     TEXT PRIMARY KEY,
                    public_key  TEXT NOT NULL,
                    token       TEXT UNIQUE,
                    webhook_url TEXT,
                    last_seen   TEXT,
                    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
                );
                INSERT INTO agents_new (address, public_key, token, webhook_url, last_seen, created_at)
                    SELECT address, public_key, api_key, webhook_url, last_seen, created_at
                    FROM agents;
                DROP TABLE agents;
                ALTER TABLE agents_new RENAME TO agents;
            """)
        await db.execute("PRAGMA user_version = 10")
        await db.commit()


async def init_db(path: str) -> aiosqlite.Connection:
    """Open the database, apply pragmas and schema, return the connection."""
    db = await aiosqlite.connect(path)
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA busy_timeout=5000")
    await db.execute("PRAGMA synchronous=NORMAL")
    await db.execute("PRAGMA foreign_keys=ON")
    db.row_factory = aiosqlite.Row

    # Detect fresh DB: if core tables don't exist, apply SCHEMA first so
    # migrations can safely ALTER TABLE on existing tables.
    cursor = await db.execute(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='messages'"
    )
    is_fresh = (await cursor.fetchone())[0] == 0
    if is_fresh:
        await db.executescript(SCHEMA)
        await db.commit()

    # Run migrations (safe: tables exist either from SCHEMA or previous runs).
    # On existing DBs this upgrades incrementally; on fresh DBs migrations
    # become no-ops (columns/tables already in SCHEMA) but still set user_version.
    await _migrate(db)

    # Re-apply SCHEMA idempotently (catches any new CREATE TABLE IF NOT EXISTS
    # added to SCHEMA that older DBs don't have yet).
    await db.executescript(SCHEMA)
    await db.commit()
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


# ---------------------------------------------------------------------------
# Federation helpers (FED-01)
# ---------------------------------------------------------------------------


async def upsert_known_relay(
    db: aiosqlite.Connection,
    domain: str,
    federation_url: str,
    public_key: str,
    discovered_via: str,
    ttl_hours: int = 1,
) -> None:
    """Insert or update a known relay record."""
    await db.execute(
        """INSERT INTO known_relays (domain, federation_url, public_key, discovered_via, ttl_hours)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(domain) DO UPDATE SET
             federation_url = excluded.federation_url,
             public_key = excluded.public_key,
             discovered_via = excluded.discovered_via,
             last_verified = datetime('now'),
             ttl_hours = excluded.ttl_hours,
             status = 'active'""",
        (domain, federation_url, public_key, discovered_via, ttl_hours),
    )
    await db.commit()


async def get_known_relay(
    db: aiosqlite.Connection, domain: str
) -> dict[str, Any] | None:
    """Look up a known relay by domain.  Returns its fields or ``None``."""
    cursor = await db.execute(
        "SELECT domain, federation_url, public_key, discovered_via, "
        "last_verified, ttl_hours, status "
        "FROM known_relays WHERE domain = ?",
        (domain,),
    )
    row = await cursor.fetchone()
    if row is None:
        return None
    return dict(row)


async def log_federation(
    db: aiosqlite.Connection,
    message_id: str,
    from_relay: str,
    to_relay: str,
    direction: str,
    hop_count: int,
    status: str,
    error: str | None = None,
) -> None:
    """Write an entry to the federation log."""
    await db.execute(
        "INSERT INTO federation_log "
        "(message_id, from_relay, to_relay, direction, hop_count, status, error) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (message_id, from_relay, to_relay, direction, hop_count, status, error),
    )
    await db.commit()


async def is_relay_blocked(db: aiosqlite.Connection, domain: str) -> bool:
    """Return ``True`` if *domain* is on the relay blocklist."""
    cursor = await db.execute(
        "SELECT 1 FROM relay_blocklist WHERE domain = ?", (domain,)
    )
    return await cursor.fetchone() is not None


async def is_relay_allowed(db: aiosqlite.Connection, domain: str) -> bool:
    """Return ``True`` if *domain* is on the relay allowlist."""
    cursor = await db.execute(
        "SELECT 1 FROM relay_allowlist WHERE domain = ?", (domain,)
    )
    return await cursor.fetchone() is not None
