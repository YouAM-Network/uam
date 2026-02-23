/**
 * SQLite-backed local contact storage (HAND-03).
 *
 * Stores known contacts with their public keys and trust state.
 * Provides fast in-memory caches for isKnown() and isBlocked() checks.
 *
 * Uses better-sqlite3 for synchronous SQLite (simpler than Python's aiosqlite).
 */

import { mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import Database from "better-sqlite3";

/**
 * A row returned from listContacts().
 */
export interface ContactRow {
  address: string;
  displayName: string | null;
  trustState: string;
  firstSeen: string;
  lastSeen: string;
}

/**
 * A pending handshake entry.
 */
export interface PendingEntry {
  address: string;
  contactCard: string;
  receivedAt: string;
}

/**
 * A blocked pattern entry.
 */
export interface BlockedEntry {
  pattern: string;
  blockedAt: string;
}

export class ContactBook {
  private _dbPath: string;
  private _db: Database.Database | null = null;
  private _knownAddresses: Set<string> = new Set();
  private _blockedExact: Set<string> = new Set();
  private _blockedDomains: Set<string> = new Set();

  constructor(dataDir: string) {
    this._dbPath = join(dataDir, "contacts", "contacts.db");
  }

  /**
   * Open the database, create tables, run migrations, load caches.
   */
  open(): void {
    mkdirSync(dirname(this._dbPath), { recursive: true });
    this._db = new Database(this._dbPath);
    this._db.pragma("journal_mode = WAL");

    // Create tables with all columns upfront (no migrations needed for new DB)
    this._db.exec(`
      CREATE TABLE IF NOT EXISTS contacts (
        address      TEXT PRIMARY KEY,
        public_key   TEXT NOT NULL,
        display_name TEXT,
        trust_state  TEXT NOT NULL DEFAULT 'unknown',
        trust_source TEXT DEFAULT 'legacy-unknown',
        relay        TEXT,
        relays_json  TEXT,
        pinned_at    TEXT,
        first_seen   TEXT NOT NULL DEFAULT (datetime('now')),
        last_seen    TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS pending_handshakes (
        address      TEXT PRIMARY KEY,
        contact_card TEXT NOT NULL,
        received_at  TEXT NOT NULL DEFAULT (datetime('now'))
      );

      CREATE TABLE IF NOT EXISTS blocked_patterns (
        pattern     TEXT PRIMARY KEY,
        blocked_at  TEXT NOT NULL DEFAULT (datetime('now'))
      );
    `);

    // Run migrations
    this._migrate();

    // Load all known addresses into memory for fast sync lookups
    const rows = this._db
      .prepare("SELECT address FROM contacts")
      .all() as Array<{ address: string }>;
    this._knownAddresses = new Set(rows.map((r) => r.address));

    // Load blocked patterns into memory
    this._blockedExact.clear();
    this._blockedDomains.clear();
    const blocked = this._db
      .prepare("SELECT pattern FROM blocked_patterns")
      .all() as Array<{ pattern: string }>;
    for (const row of blocked) {
      this._cacheBlockPattern(row.pattern);
    }
  }

  /**
   * Run schema migrations using PRAGMA user_version.
   */
  private _migrate(): void {
    if (!this._db) return;

    const versionRow = this._db
      .prepare("PRAGMA user_version")
      .get() as { user_version: number };
    const version = versionRow.user_version;

    if (version < 2) {
      // For new DBs, tables are created with all columns upfront
      // (including pinned_at). Skip straight to version 3.
      this._db.exec("PRAGMA user_version = 3");
    } else if (version < 3) {
      // Existing v2 database: add pinned_at column for key pinning lifecycle
      this._db.exec(
        "ALTER TABLE contacts ADD COLUMN pinned_at TEXT"
      );
      this._db.exec("PRAGMA user_version = 3");
    }
  }

  /**
   * Close the database connection.
   */
  close(): void {
    if (this._db !== null) {
      this._db.close();
      this._db = null;
    }
  }

  /**
   * Check if an address is in the contact book (in-memory, no I/O).
   */
  isKnown(address: string): boolean {
    return this._knownAddresses.has(address);
  }

  /**
   * Check if an address matches any blocked pattern (O(1) set lookup).
   */
  isBlocked(address: string): boolean {
    if (this._blockedExact.has(address)) {
      return true;
    }
    // Extract domain from 'name::domain' format
    if (address.includes("::")) {
      const domain = address.split("::")[1];
      return this._blockedDomains.has(domain);
    }
    return false;
  }

  /**
   * Look up the public key for a known contact.
   */
  getPublicKey(address: string): string | null {
    if (this._db === null) return null;
    const row = this._db
      .prepare("SELECT public_key FROM contacts WHERE address = ?")
      .get(address) as { public_key: string } | undefined;
    return row?.public_key ?? null;
  }

  /**
   * Return the relay URLs for a known contact (CARD-04).
   */
  getRelayUrls(address: string): string[] | null {
    if (this._db === null) return null;
    const row = this._db
      .prepare("SELECT relay, relays_json FROM contacts WHERE address = ?")
      .get(address) as { relay: string | null; relays_json: string | null } | undefined;
    if (!row) return null;
    if (row.relays_json !== null) {
      return JSON.parse(row.relays_json) as string[];
    }
    if (row.relay !== null) {
      return [row.relay];
    }
    return null;
  }

  /**
   * Add or update a contact (upsert).
   */
  addContact(
    address: string,
    publicKey: string,
    options?: {
      displayName?: string | null;
      trustState?: string;
      trustSource?: string | null;
      relay?: string | null;
      relays?: string[] | null;
    }
  ): void {
    if (this._db === null) {
      throw new Error("ContactBook not open. Call open() first.");
    }
    const displayName = options?.displayName ?? null;
    const trustState = options?.trustState ?? "trusted";
    const trustSource = options?.trustSource ?? null;
    const relay = options?.relay ?? null;
    const relaysJson =
      options?.relays !== undefined && options?.relays !== null
        ? JSON.stringify(options.relays)
        : null;

    this._db
      .prepare(
        `INSERT INTO contacts (address, public_key, display_name, trust_state, trust_source, relay, relays_json)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(address) DO UPDATE SET
           public_key = excluded.public_key,
           display_name = excluded.display_name,
           trust_state = excluded.trust_state,
           trust_source = COALESCE(excluded.trust_source, contacts.trust_source),
           relay = COALESCE(excluded.relay, contacts.relay),
           relays_json = COALESCE(excluded.relays_json, contacts.relays_json),
           last_seen = datetime('now')`
      )
      .run(address, publicKey, displayName, trustState, trustSource, relay, relaysJson);

    this._knownAddresses.add(address);
  }

  /**
   * Return all contacts sorted by last_seen DESC.
   */
  listContacts(): ContactRow[] {
    if (this._db === null) return [];
    const rows = this._db
      .prepare(
        "SELECT address, display_name, trust_state, first_seen, last_seen " +
          "FROM contacts ORDER BY last_seen DESC"
      )
      .all() as Array<{
      address: string;
      display_name: string | null;
      trust_state: string;
      first_seen: string;
      last_seen: string;
    }>;
    return rows.map((r) => ({
      address: r.address,
      displayName: r.display_name,
      trustState: r.trust_state,
      firstSeen: r.first_seen,
      lastSeen: r.last_seen,
    }));
  }

  /**
   * Store a pending handshake request.
   */
  addPending(address: string, contactCardJson: string): void {
    if (this._db === null) {
      throw new Error("ContactBook not open. Call open() first.");
    }
    this._db
      .prepare(
        `INSERT OR REPLACE INTO pending_handshakes (address, contact_card) VALUES (?, ?)`
      )
      .run(address, contactCardJson);
  }

  /**
   * Retrieve all pending handshake requests.
   */
  getPending(): PendingEntry[] {
    if (this._db === null) return [];
    const rows = this._db
      .prepare(
        "SELECT address, contact_card, received_at FROM pending_handshakes"
      )
      .all() as Array<{
      address: string;
      contact_card: string;
      received_at: string;
    }>;
    return rows.map((r) => ({
      address: r.address,
      contactCard: r.contact_card,
      receivedAt: r.received_at,
    }));
  }

  /**
   * Remove a pending handshake request.
   */
  removePending(address: string): void {
    if (this._db === null) return;
    this._db
      .prepare("DELETE FROM pending_handshakes WHERE address = ?")
      .run(address);
  }

  /**
   * Return pending handshakes older than N days.
   */
  getExpiredPending(days: number = 7): PendingEntry[] {
    if (this._db === null) return [];
    const rows = this._db
      .prepare(
        `SELECT address, contact_card, received_at FROM pending_handshakes
         WHERE datetime(received_at, '+' || ? || ' days') < datetime('now')`
      )
      .all(String(days)) as Array<{
      address: string;
      contact_card: string;
      received_at: string;
    }>;
    return rows.map((r) => ({
      address: r.address,
      contactCard: r.contact_card,
      receivedAt: r.received_at,
    }));
  }

  /**
   * Return the trust_state for an address, or null if unknown.
   */
  getTrustState(address: string): string | null {
    if (this._db === null) return null;
    const row = this._db
      .prepare("SELECT trust_state FROM contacts WHERE address = ?")
      .get(address) as { trust_state: string } | undefined;
    return row?.trust_state ?? null;
  }

  /**
   * Set the pinned_at timestamp and trust_state='pinned' for a contact (TOFU).
   */
  setPinnedAt(address: string): void {
    if (this._db === null) {
      throw new Error("ContactBook not open. Call open() first.");
    }
    this._db
      .prepare(
        "UPDATE contacts SET pinned_at = datetime('now'), trust_state = 'pinned' WHERE address = ?"
      )
      .run(address);
  }

  /**
   * Remove a contact by address. Returns true if a contact was deleted.
   */
  removeContact(address: string): boolean {
    if (this._db === null) {
      throw new Error("ContactBook not open. Call open() first.");
    }
    const result = this._db
      .prepare("DELETE FROM contacts WHERE address = ?")
      .run(address);
    this._knownAddresses.delete(address);
    return result.changes > 0;
  }

  /**
   * Return true if the address has trust_state 'trusted', 'verified', or 'pinned'.
   *
   * Convenience helper for inbound message filtering (CARD-05, TOFU-02).
   */
  isTrustedOrVerified(address: string): boolean {
    const state = this.getTrustState(address);
    return state === "trusted" || state === "verified" || state === "pinned";
  }

  /**
   * Block an address or domain pattern (e.g., '*::evil.com').
   */
  addBlock(pattern: string): void {
    if (this._db === null) {
      throw new Error("ContactBook not open. Call open() first.");
    }
    this._db
      .prepare("INSERT OR IGNORE INTO blocked_patterns (pattern) VALUES (?)")
      .run(pattern);
    this._cacheBlockPattern(pattern);
  }

  /**
   * Remove a block pattern.
   */
  removeBlock(pattern: string): void {
    if (this._db === null) {
      throw new Error("ContactBook not open. Call open() first.");
    }
    this._db
      .prepare("DELETE FROM blocked_patterns WHERE pattern = ?")
      .run(pattern);
    this._uncacheBlockPattern(pattern);
  }

  /**
   * Return all blocked patterns with their timestamps.
   */
  listBlocked(): BlockedEntry[] {
    if (this._db === null) return [];
    const rows = this._db
      .prepare(
        "SELECT pattern, blocked_at FROM blocked_patterns ORDER BY blocked_at DESC"
      )
      .all() as Array<{ pattern: string; blocked_at: string }>;
    return rows.map((r) => ({
      pattern: r.pattern,
      blockedAt: r.blocked_at,
    }));
  }

  // -- Internal block caching ---------------------------------------------------

  private _cacheBlockPattern(pattern: string): void {
    if (pattern.startsWith("*::")) {
      this._blockedDomains.add(pattern.slice(3));
    } else {
      this._blockedExact.add(pattern);
    }
  }

  private _uncacheBlockPattern(pattern: string): void {
    if (pattern.startsWith("*::")) {
      this._blockedDomains.delete(pattern.slice(3));
    } else {
      this._blockedExact.delete(pattern);
    }
  }
}
