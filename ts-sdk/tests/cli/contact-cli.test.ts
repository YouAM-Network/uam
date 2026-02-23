/**
 * Contact management CLI tests.
 *
 * Tests contact fingerprint, contact verify, contact remove commands.
 * Uses local ContactBook directly (offline operations).
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  sodiumReady,
  generateKeypair,
  serializeVerifyKey,
  deserializeVerifyKey,
  publicKeyFingerprint,
} from "../../src/protocol/index.js";
import { ContactBook } from "../../src/sdk/contact-book.js";
import { trustIndicator } from "../../src/cli/commands/contacts.js";

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

let testDir: string;

beforeAll(async () => {
  await sodiumReady;
});

beforeEach(() => {
  testDir = join(tmpdir(), `uam-contact-cli-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(testDir, { recursive: true });
});

afterEach(() => {
  if (existsSync(testDir)) {
    rmSync(testDir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function setupContactBook(): ContactBook {
  const book = new ContactBook(testDir);
  book.open();
  return book;
}

// ---------------------------------------------------------------------------
// contact fingerprint
// ---------------------------------------------------------------------------

describe("contact fingerprint", () => {
  it("shows hex hash for a known contact's public key", () => {
    const kp = generateKeypair();
    const pkStr = serializeVerifyKey(kp.verifyKey);

    const book = setupContactBook();
    book.addContact("alice::relay.test", pkStr, { trustState: "pinned" });

    // Look up and compute fingerprint (same as the CLI command logic)
    const storedPk = book.getPublicKey("alice::relay.test");
    expect(storedPk).toBe(pkStr);

    const vk = deserializeVerifyKey(storedPk!);
    const fp = publicKeyFingerprint(vk);

    // SHA-256 hex is 64 chars
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
    book.close();
  });

  it("returns null for unknown contact", () => {
    const book = setupContactBook();
    const pk = book.getPublicKey("nobody::relay.test");
    expect(pk).toBeNull();
    book.close();
  });
});

// ---------------------------------------------------------------------------
// contact verify
// ---------------------------------------------------------------------------

describe("contact verify", () => {
  it("upgrades trust state to verified", () => {
    const kp = generateKeypair();
    const pkStr = serializeVerifyKey(kp.verifyKey);

    const book = setupContactBook();
    book.addContact("alice::relay.test", pkStr, { trustState: "pinned" });

    // Simulate verify: upgrade trust state
    book.addContact("alice::relay.test", pkStr, {
      trustState: "verified",
      trustSource: "manual-verify",
    });

    expect(book.getTrustState("alice::relay.test")).toBe("verified");
    book.close();
  });

  it("preserves the same public key after verification", () => {
    const kp = generateKeypair();
    const pkStr = serializeVerifyKey(kp.verifyKey);

    const book = setupContactBook();
    book.addContact("alice::relay.test", pkStr, { trustState: "pinned" });
    book.addContact("alice::relay.test", pkStr, {
      trustState: "verified",
      trustSource: "manual-verify",
    });

    expect(book.getPublicKey("alice::relay.test")).toBe(pkStr);
    book.close();
  });
});

// ---------------------------------------------------------------------------
// contact remove
// ---------------------------------------------------------------------------

describe("contact remove", () => {
  it("deletes contact from the contact book", () => {
    const kp = generateKeypair();
    const pkStr = serializeVerifyKey(kp.verifyKey);

    const book = setupContactBook();
    book.addContact("alice::relay.test", pkStr, { trustState: "trusted" });
    expect(book.isKnown("alice::relay.test")).toBe(true);

    const removed = book.removeContact("alice::relay.test");
    expect(removed).toBe(true);
    expect(book.isKnown("alice::relay.test")).toBe(false);
    expect(book.getPublicKey("alice::relay.test")).toBeNull();
    book.close();
  });

  it("returns false when removing non-existent contact", () => {
    const book = setupContactBook();
    const removed = book.removeContact("nobody::relay.test");
    expect(removed).toBe(false);
    book.close();
  });
});

// ---------------------------------------------------------------------------
// Trust indicators
// ---------------------------------------------------------------------------

describe("trustIndicator", () => {
  it("maps provisional to (!)", () => {
    expect(trustIndicator("provisional")).toBe("provisional (!)");
  });

  it("maps trusted to [T]", () => {
    expect(trustIndicator("trusted")).toBe("trusted [T]");
  });

  it("maps pinned to [P]", () => {
    expect(trustIndicator("pinned")).toBe("pinned [P]");
  });

  it("maps verified to [V]", () => {
    expect(trustIndicator("verified")).toBe("verified [V]");
  });

  it("maps unknown to [?]", () => {
    expect(trustIndicator("unknown")).toBe("unknown [?]");
  });

  it("passes through unrecognized states", () => {
    expect(trustIndicator("bridge")).toBe("bridge");
  });
});
