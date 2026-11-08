/**
 * Replay protection for inbound envelopes.
 *
 * Used by Agent._processInbound to drop envelopes whose
 * (from address, message id) pair was already seen.
 *
 * PersistentReplayCache is what the Agent uses: a SQLite file under the
 * agent's data dir, shared by every process using that dir, that keeps each
 * pair for RETENTION_SECONDS. Stored mail can arrive days after it was
 * signed, so the window an envelope can be accepted in is longer than one
 * process lives.
 *
 * - Never evicts inside the window. Rows go only when they are older than
 *   RETENTION_SECONDS. When the file holds `capacity` rows it fails closed:
 *   an envelope signed within MAX_ENVELOPE_AGE is still accepted (and
 *   deduplicated in memory); anything older is refused.
 * - Knows its age. created_at is written once, so a caller can refuse old
 *   stored mail signed before the cache existed.
 *
 * EnvelopeReplayCache is the bounded in-memory cache it falls back on when
 * full: least-recently-used entries are evicted at capacity, and entries
 * older than the TTL are treated as new.
 *
 * Matches the Python SDK's sdk/replay_cache.py, and shares its file format:
 * times in the file are seconds since the epoch.
 */

import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

import Database from "better-sqlite3";

import { MAX_ENVELOPE_AGE } from "../protocol/types.js";
import { STORED_MAIL_MAX_AGE } from "./freshness.js";
import { log } from "./log.js";

/**
 * Seven days of stored mail, plus the freshness window on either side of the
 * signed timestamp (clock skew between sender, relay and recipient).
 */
export const RETENTION_SECONDS = STORED_MAIL_MAX_AGE + 2 * MAX_ENVELOPE_AGE;

/** How often expired rows are purged, at most. */
const PURGE_INTERVAL_MS = 60_000;

const WAL_ATTEMPTS = 100;
const WAL_RETRY_MS = 100;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS seen_envelopes (
    from_address TEXT NOT NULL,
    message_id   TEXT NOT NULL,
    seen_at      REAL NOT NULL,
    PRIMARY KEY (from_address, message_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS seen_envelopes_seen_at ON seen_envelopes (seen_at);
CREATE TABLE IF NOT EXISTS replay_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
`;

function isLocked(err: unknown): boolean {
  const code = (err as { code?: unknown }).code;
  return (
    typeof code === "string" &&
    (code.startsWith("SQLITE_BUSY") || code.startsWith("SQLITE_LOCKED"))
  );
}

/**
 * Switch `db` to WAL, waiting out another process doing the same.
 *
 * SQLite doesn't apply the busy timeout to this switch: two processes opening
 * a new file together get "database is locked" at once.
 */
async function enableWal(db: Database.Database): Promise<void> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      db.pragma("journal_mode = WAL");
      return;
    } catch (err) {
      if (attempt >= WAL_ATTEMPTS || !isLocked(err)) throw err;
      await sleep(WAL_RETRY_MS);
    }
  }
}

export const DEFAULT_REPLAY_CACHE_CAPACITY = 1_000_000;

export class EnvelopeReplayCache {
  readonly capacity: number;
  readonly ttlMs: number;
  private readonly _now: () => number;
  // Map iteration order is insertion order: first key = least recently used.
  private readonly _seen = new Map<string, number>();

  constructor(options?: {
    capacity?: number;
    ttlMs?: number;
    now?: () => number;
  }) {
    const capacity = options?.capacity ?? 100_000;
    if (!Number.isInteger(capacity) || capacity < 1) {
      throw new RangeError(
        `Replay cache capacity must be a positive integer, got ${capacity}`
      );
    }
    this.capacity = capacity;
    this.ttlMs = options?.ttlMs ?? 300_000;
    this._now = options?.now ?? (() => Date.now());
  }

  get size(): number {
    return this._seen.size;
  }

  /** True if this pair was seen within the TTL. Records nothing. */
  has(fromAddress: string, messageId: string): boolean {
    const seenAt = this._seen.get(this._key(fromAddress, messageId));
    return seenAt !== undefined && this._now() - seenAt < this.ttlMs;
  }

  /**
   * Return true if this (fromAddress, messageId) pair was already seen
   * within the TTL (a replay). Otherwise record it and return false.
   */
  seenOrRecord(fromAddress: string, messageId: string): boolean {
    const key = this._key(fromAddress, messageId);
    const now = this._now();
    const seenAt = this._seen.get(key);
    if (seenAt !== undefined && now - seenAt < this.ttlMs) {
      // LRU touch: move to the most-recently-used end.
      this._seen.delete(key);
      this._seen.set(key, seenAt);
      return true;
    }
    this._seen.delete(key);
    this._seen.set(key, now);
    while (this._seen.size > this.capacity) {
      const oldest = this._seen.keys().next().value as string;
      this._seen.delete(oldest);
    }
    return false;
  }

  private _key(fromAddress: string, messageId: string): string {
    // JSON encoding keeps the two parts unambiguous whatever they contain.
    return JSON.stringify([fromAddress, messageId]);
  }
}

/**
 * Inbound (from address, message id) pairs kept in a SQLite file.
 *
 * Opens itself on first use, so an Agent driven without connect() still has
 * replay protection. Safe to share between processes: the insert is the
 * check (INSERT OR IGNORE), in WAL mode.
 */
export class PersistentReplayCache {
  readonly capacity: number;
  private readonly _path: string;
  private readonly _now: () => number;
  private _db: Database.Database | null = null;
  private _opening: Promise<Database.Database> | null = null;
  private _count = 0;
  private _lastPurge = 0;
  private _createdAt = 0;
  // Used only while the file is full, for envelopes inside MAX_ENVELOPE_AGE.
  // One can be signed that far ahead of us and stay acceptable until that far
  // behind, so its id must last both.
  private readonly _overflow: EnvelopeReplayCache;

  /**
   * @param path - The SQLite file
   * @param options.now - The clock, in ms since the epoch
   */
  constructor(
    path: string,
    options?: { capacity?: number; now?: () => number }
  ) {
    const capacity = options?.capacity ?? DEFAULT_REPLAY_CACHE_CAPACITY;
    if (!Number.isInteger(capacity) || capacity < 1) {
      throw new RangeError(
        `Replay cache capacity must be a positive integer, got ${capacity}`
      );
    }
    this.capacity = capacity;
    this._path = path;
    this._now = options?.now ?? (() => Date.now());
    this._overflow = new EnvelopeReplayCache({
      capacity: 10_000,
      ttlMs: 2 * MAX_ENVELOPE_AGE * 1000,
      now: this._now,
    });
  }

  /** Open the file now, rather than on first use. */
  async open(): Promise<void> {
    await this._open();
  }

  /**
   * Return true if the envelope must be dropped as a replay. Otherwise record
   * the pair and return false.
   *
   * @param signedAt - The envelope's signed time, in ms since the epoch. It
   *   matters only when the cache is full.
   */
  async seenOrRecord(
    fromAddress: string,
    messageId: string,
    signedAt: number
  ): Promise<boolean> {
    const db = await this._open();
    const now = this._now();
    if (now - this._lastPurge >= PURGE_INTERVAL_MS) this._purge(db);

    // Accepted while the file was full, so it's only in memory.
    if (this._overflow.has(fromAddress, messageId)) return true;

    if (this._count < this.capacity) {
      const { changes } = db
        .prepare(
          "INSERT OR IGNORE INTO seen_envelopes " +
            "(from_address, message_id, seen_at) VALUES (?, ?, ?)"
        )
        .run(fromAddress, messageId, now / 1000);
      if (changes === 0) return true;
      this._count += 1;
      return false;
    }

    // Full: never evict inside the window. Known pairs are replays, fresh
    // envelopes are deduplicated in memory, older ones refused.
    const known = db
      .prepare(
        "SELECT 1 FROM seen_envelopes WHERE from_address = ? AND message_id = ?"
      )
      .get(fromAddress, messageId);
    if (known !== undefined) return true;

    if (Math.abs(now - signedAt) <= MAX_ENVELOPE_AGE * 1000) {
      return this._overflow.seenOrRecord(fromAddress, messageId);
    }
    log.warn(
      `Replay cache full (${this._count} ids); refused envelope ${messageId} ` +
        `from ${fromAddress} signed ${Math.round((now - signedAt) / 1000)}s ago`
    );
    return true;
  }

  /** When this cache file was first created, in ms since the epoch. */
  async createdAt(): Promise<number> {
    await this._open();
    return this._createdAt;
  }

  /** True if an envelope signed at `signedAt` (ms) predates this cache. */
  async signedBeforeCache(signedAt: number): Promise<boolean> {
    return signedAt < (await this.createdAt());
  }

  /** Number of ids currently held on disk. */
  async count(): Promise<number> {
    const db = await this._open();
    return this._countRows(db);
  }

  /** Close the file; the next call opens it again. */
  async close(): Promise<void> {
    await this._opening?.catch(() => undefined);
    this._db?.close();
    this._db = null;
  }

  private _open(): Promise<Database.Database> {
    if (this._db !== null) return Promise.resolve(this._db);
    this._opening ??= this._connect().finally(() => {
      this._opening = null;
    });
    return this._opening;
  }

  private async _connect(): Promise<Database.Database> {
    mkdirSync(dirname(this._path), { recursive: true });
    const db = new Database(this._path, { timeout: 30_000 });
    try {
      await enableWal(db);
      db.exec(SCHEMA);
      db.prepare(
        "INSERT OR IGNORE INTO replay_meta (key, value) VALUES ('created_at', ?)"
      ).run(String(this._now() / 1000));
      const row = db
        .prepare("SELECT value FROM replay_meta WHERE key = 'created_at'")
        .get() as { value: string };
      this._createdAt = Number(row.value) * 1000;
      this._purge(db);
    } catch (err) {
      db.close();
      throw err;
    }
    this._db = db;
    return db;
  }

  private _purge(db: Database.Database): void {
    const now = this._now();
    db.prepare("DELETE FROM seen_envelopes WHERE seen_at < ?").run(
      now / 1000 - RETENTION_SECONDS
    );
    this._count = this._countRows(db);
    this._lastPurge = now;
  }

  private _countRows(db: Database.Database): number {
    const row = db.prepare("SELECT COUNT(*) AS n FROM seen_envelopes").get() as {
      n: number;
    };
    return row.n;
  }
}
