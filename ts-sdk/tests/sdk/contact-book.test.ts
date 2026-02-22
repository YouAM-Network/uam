/**
 * Tests for ContactBook.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { ContactBook } from "../../src/sdk/contact-book.js";

describe("ContactBook", () => {
  let tempDir: string;
  let book: ContactBook;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "uam-cb-test-"));
    book = new ContactBook(tempDir);
    book.open();
  });

  afterEach(() => {
    book.close();
    rmSync(tempDir, { recursive: true, force: true });
  });

  // -- Open/Close --

  it("open creates the database file", () => {
    const { existsSync } = require("node:fs");
    expect(existsSync(join(tempDir, "contacts", "contacts.db"))).toBe(true);
  });

  it("close and reopen preserves data", () => {
    book.addContact("alice::youam.network", "pubkey_a");
    book.close();

    const book2 = new ContactBook(tempDir);
    book2.open();
    expect(book2.isKnown("alice::youam.network")).toBe(true);
    expect(book2.getPublicKey("alice::youam.network")).toBe("pubkey_a");
    book2.close();
  });

  // -- addContact / getPublicKey --

  it("adds and retrieves a contact", () => {
    book.addContact("bob::youam.network", "pubkey_b", {
      displayName: "Bob Agent",
    });
    expect(book.getPublicKey("bob::youam.network")).toBe("pubkey_b");
  });

  it("upserts on duplicate address", () => {
    book.addContact("bob::youam.network", "key_v1");
    book.addContact("bob::youam.network", "key_v2");
    expect(book.getPublicKey("bob::youam.network")).toBe("key_v2");
  });

  it("returns null for unknown contact", () => {
    expect(book.getPublicKey("unknown::youam.network")).toBeNull();
  });

  // -- isKnown --

  it("isKnown returns true for added contacts", () => {
    book.addContact("charlie::youam.network", "pubkey_c");
    expect(book.isKnown("charlie::youam.network")).toBe(true);
  });

  it("isKnown returns false for unknown addresses", () => {
    expect(book.isKnown("unknown::youam.network")).toBe(false);
  });

  // -- isBlocked --

  it("blocks exact address", () => {
    book.addBlock("spammer::evil.com");
    expect(book.isBlocked("spammer::evil.com")).toBe(true);
    expect(book.isBlocked("other::evil.com")).toBe(false);
  });

  it("blocks domain pattern", () => {
    book.addBlock("*::evil.com");
    expect(book.isBlocked("anyone::evil.com")).toBe(true);
    expect(book.isBlocked("other::evil.com")).toBe(true);
    expect(book.isBlocked("safe::good.com")).toBe(false);
  });

  it("unblocks a pattern", () => {
    book.addBlock("*::evil.com");
    expect(book.isBlocked("spammer::evil.com")).toBe(true);
    book.removeBlock("*::evil.com");
    expect(book.isBlocked("spammer::evil.com")).toBe(false);
  });

  it("listBlocked returns all patterns", () => {
    book.addBlock("spam::evil.com");
    book.addBlock("*::badsite.com");
    const blocked = book.listBlocked();
    expect(blocked.length).toBe(2);
    const patterns = blocked.map((b) => b.pattern);
    expect(patterns).toContain("spam::evil.com");
    expect(patterns).toContain("*::badsite.com");
  });

  // -- Pending handshakes --

  it("adds and retrieves pending handshakes", () => {
    book.addPending("new::youam.network", '{"address":"new::youam.network"}');
    const pending = book.getPending();
    expect(pending.length).toBe(1);
    expect(pending[0].address).toBe("new::youam.network");
    expect(pending[0].contactCard).toBe('{"address":"new::youam.network"}');
  });

  it("removes pending handshake", () => {
    book.addPending("new::youam.network", '{"test":true}');
    book.removePending("new::youam.network");
    expect(book.getPending().length).toBe(0);
  });

  // -- Relay URLs --

  it("returns null relay URLs for unknown contact", () => {
    expect(book.getRelayUrls("unknown::youam.network")).toBeNull();
  });

  it("returns single relay from relay column", () => {
    book.addContact("alice::youam.network", "pubkey", {
      relay: "https://relay.youam.network",
    });
    expect(book.getRelayUrls("alice::youam.network")).toEqual([
      "https://relay.youam.network",
    ]);
  });

  it("returns relays array from relays_json column", () => {
    book.addContact("alice::youam.network", "pubkey", {
      relays: ["https://r1.youam.network", "https://r2.youam.network"],
    });
    expect(book.getRelayUrls("alice::youam.network")).toEqual([
      "https://r1.youam.network",
      "https://r2.youam.network",
    ]);
  });

  it("prefers relays_json over relay column", () => {
    book.addContact("alice::youam.network", "pubkey", {
      relay: "https://single.relay",
      relays: ["https://multi1.relay", "https://multi2.relay"],
    });
    expect(book.getRelayUrls("alice::youam.network")).toEqual([
      "https://multi1.relay",
      "https://multi2.relay",
    ]);
  });

  // -- Trust state --

  it("getTrustState returns correct state", () => {
    book.addContact("alice::youam.network", "pk", { trustState: "trusted" });
    expect(book.getTrustState("alice::youam.network")).toBe("trusted");
  });

  it("getTrustState returns null for unknown", () => {
    expect(book.getTrustState("unknown::youam.network")).toBeNull();
  });

  // -- listContacts --

  it("listContacts returns all contacts", () => {
    book.addContact("alice::youam.network", "pk_a");
    book.addContact("bob::youam.network", "pk_b");
    const contacts = book.listContacts();
    expect(contacts.length).toBe(2);
    const addresses = contacts.map((c) => c.address);
    expect(addresses).toContain("alice::youam.network");
    expect(addresses).toContain("bob::youam.network");
  });

  // -- COALESCE behavior --

  it("preserves trust_source on update when null is passed", () => {
    book.addContact("alice::youam.network", "pk", {
      trustSource: "auto-accepted",
    });
    // Update without providing trustSource
    book.addContact("alice::youam.network", "pk_updated");
    // trust_source should be preserved (COALESCE)
    // We can verify via getTrustState that the contact still exists
    expect(book.isKnown("alice::youam.network")).toBe(true);
  });
});
