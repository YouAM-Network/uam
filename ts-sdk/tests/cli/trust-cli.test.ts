/**
 * Trust management CLI tests.
 *
 * Tests pending, approve, deny, block, unblock commands.
 * Uses local ContactBook directly (no relay connection needed for block/unblock).
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { sodiumReady, generateKeypair, serializeSigningKey, serializeVerifyKey } from "../../src/protocol/index.js";
import { ContactBook } from "../../src/sdk/contact-book.js";

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

let testDir: string;

beforeAll(async () => {
  await sodiumReady;
});

beforeEach(() => {
  testDir = join(tmpdir(), `uam-trust-cli-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(testDir, { recursive: true });
});

afterEach(() => {
  if (existsSync(testDir)) {
    rmSync(testDir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Helper: set up a ContactBook with test data
// ---------------------------------------------------------------------------

function setupContactBook(): ContactBook {
  const book = new ContactBook(testDir);
  book.open();
  return book;
}

// ---------------------------------------------------------------------------
// pending command -- tests via ContactBook (offline)
// ---------------------------------------------------------------------------

describe("pending (via ContactBook)", () => {
  it("returns empty list when no pending handshakes", () => {
    const book = setupContactBook();
    const items = book.getPending();
    book.close();
    expect(items).toHaveLength(0);
  });

  it("shows pending handshakes after addPending", () => {
    const kp = generateKeypair();
    const pkStr = serializeVerifyKey(kp.verifyKey);
    const cardJson = JSON.stringify({
      address: "alice::relay.test",
      public_key: pkStr,
      display_name: "alice",
    });

    const book = setupContactBook();
    book.addPending("alice::relay.test", cardJson);
    const items = book.getPending();
    book.close();

    expect(items).toHaveLength(1);
    expect(items[0].address).toBe("alice::relay.test");
    expect(items[0].contactCard).toBe(cardJson);
  });
});

// ---------------------------------------------------------------------------
// block/unblock -- tests via ContactBook (offline)
// ---------------------------------------------------------------------------

describe("block/unblock (via ContactBook)", () => {
  it("blocks an exact address pattern", () => {
    const book = setupContactBook();
    book.addBlock("spammer::evil.com");
    expect(book.isBlocked("spammer::evil.com")).toBe(true);
    expect(book.isBlocked("other::evil.com")).toBe(false);
    book.close();
  });

  it("blocks a domain wildcard pattern", () => {
    const book = setupContactBook();
    book.addBlock("*::evil.com");
    expect(book.isBlocked("anyone::evil.com")).toBe(true);
    expect(book.isBlocked("someone::good.com")).toBe(false);
    book.close();
  });

  it("unblocks a pattern", () => {
    const book = setupContactBook();
    book.addBlock("spammer::evil.com");
    expect(book.isBlocked("spammer::evil.com")).toBe(true);
    book.removeBlock("spammer::evil.com");
    expect(book.isBlocked("spammer::evil.com")).toBe(false);
    book.close();
  });

  it("lists blocked patterns", () => {
    const book = setupContactBook();
    book.addBlock("spammer::evil.com");
    book.addBlock("*::spam.org");
    const blocked = book.listBlocked();
    book.close();

    expect(blocked).toHaveLength(2);
    const patterns = blocked.map((b) => b.pattern);
    expect(patterns).toContain("spammer::evil.com");
    expect(patterns).toContain("*::spam.org");
  });
});

// ---------------------------------------------------------------------------
// approve/deny -- tests via ContactBook lifecycle (offline)
// ---------------------------------------------------------------------------

describe("approve/deny lifecycle (via ContactBook)", () => {
  it("approve adds contact and removes from pending", () => {
    const kp = generateKeypair();
    const pkStr = serializeVerifyKey(kp.verifyKey);

    const book = setupContactBook();
    book.addPending(
      "alice::relay.test",
      JSON.stringify({
        address: "alice::relay.test",
        public_key: pkStr,
        display_name: "alice",
      })
    );

    // Simulate approve: add contact + remove pending
    book.addContact("alice::relay.test", pkStr, {
      trustState: "trusted",
      trustSource: "explicit-approval",
    });
    book.removePending("alice::relay.test");

    expect(book.isKnown("alice::relay.test")).toBe(true);
    expect(book.getTrustState("alice::relay.test")).toBe("trusted");
    expect(book.getPending()).toHaveLength(0);
    book.close();
  });

  it("deny removes from pending without adding to contacts", () => {
    const kp = generateKeypair();
    const pkStr = serializeVerifyKey(kp.verifyKey);

    const book = setupContactBook();
    book.addPending(
      "bob::relay.test",
      JSON.stringify({
        address: "bob::relay.test",
        public_key: pkStr,
        display_name: "bob",
      })
    );

    // Simulate deny: just remove from pending
    book.removePending("bob::relay.test");

    expect(book.isKnown("bob::relay.test")).toBe(false);
    expect(book.getPending()).toHaveLength(0);
    book.close();
  });
});
