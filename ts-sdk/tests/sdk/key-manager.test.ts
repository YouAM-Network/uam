/**
 * Tests for KeyManager.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, statSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { sodiumReady } from "../../src/protocol/index.js";
import { KeyManager } from "../../src/sdk/key-manager.js";

describe("KeyManager", () => {
  let tempDir: string;

  beforeAll(async () => {
    await sodiumReady;
  });

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "uam-km-test-"));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it("throws if accessed before loadOrGenerate", () => {
    const km = new KeyManager(tempDir);
    expect(() => km.signingKey).toThrow("No keypair loaded");
    expect(() => km.verifyKey).toThrow("No keypair loaded");
    expect(() => km.seed).toThrow("No keypair loaded");
  });

  it("generates new keys on first run", () => {
    const km = new KeyManager(tempDir);
    km.loadOrGenerate("testagent");

    // Keys should now be accessible
    expect(km.signingKey).toBeInstanceOf(Uint8Array);
    expect(km.signingKey.length).toBe(64);
    expect(km.verifyKey).toBeInstanceOf(Uint8Array);
    expect(km.verifyKey.length).toBe(32);
    expect(km.seed).toBeInstanceOf(Uint8Array);
    expect(km.seed.length).toBe(32);

    // Files should exist
    expect(existsSync(join(tempDir, "testagent.key"))).toBe(true);
    expect(existsSync(join(tempDir, "testagent.pub"))).toBe(true);
  });

  it("sets 0o600 permissions on private key", () => {
    const km = new KeyManager(tempDir);
    km.loadOrGenerate("testperm");

    const keyPath = join(tempDir, "testperm.key");
    const mode = statSync(keyPath).mode & 0o777;
    expect(mode).toBe(0o600);
  });

  it("loads existing keys on second run", () => {
    // First run: generate
    const km1 = new KeyManager(tempDir);
    km1.loadOrGenerate("persist");
    const vk1 = new Uint8Array(km1.verifyKey);
    const seed1 = new Uint8Array(km1.seed);

    // Second run: load
    const km2 = new KeyManager(tempDir);
    km2.loadOrGenerate("persist");
    const vk2 = new Uint8Array(km2.verifyKey);
    const seed2 = new Uint8Array(km2.seed);

    // Keys should be identical
    expect(vk2).toEqual(vk1);
    expect(seed2).toEqual(seed1);
  });

  it("stores key as base64-encoded seed (32 bytes)", () => {
    const km = new KeyManager(tempDir);
    km.loadOrGenerate("seedcheck");

    const keyContent = readFileSync(join(tempDir, "seedcheck.key"), "utf-8").trim();
    // base64url of 32 bytes is 43 chars (without padding)
    expect(keyContent.length).toBeGreaterThanOrEqual(42);
    expect(keyContent.length).toBeLessThanOrEqual(44);
  });

  it("saves and loads token", () => {
    const km = new KeyManager(tempDir);
    km.saveToken("myagent", "tok_abc123");

    const loaded = km.loadToken("myagent");
    expect(loaded).toBe("tok_abc123");
  });

  it("returns null for missing token", () => {
    const km = new KeyManager(tempDir);
    expect(km.loadToken("nonexistent")).toBeNull();
  });

  it("loads legacy .api_key file", () => {
    const km = new KeyManager(tempDir);
    // Write legacy format
    const { writeFileSync } = require("node:fs");
    writeFileSync(join(tempDir, "legacy.api_key"), "legacy_token_123");

    const loaded = km.loadToken("legacy");
    expect(loaded).toBe("legacy_token_123");
  });

  it("prefers .token over .api_key", () => {
    const km = new KeyManager(tempDir);
    const { writeFileSync } = require("node:fs");
    writeFileSync(join(tempDir, "both.api_key"), "old_token");
    writeFileSync(join(tempDir, "both.token"), "new_token");

    const loaded = km.loadToken("both");
    expect(loaded).toBe("new_token");
  });

  it("creates keyDir recursively if it does not exist", () => {
    const nestedDir = join(tempDir, "deep", "nested", "keys");
    const km = new KeyManager(nestedDir);
    km.loadOrGenerate("deeptest");

    expect(existsSync(join(nestedDir, "deeptest.key"))).toBe(true);
  });
});

describe("KeyManager token and relay", () => {
  const RELAY = "http://relay.test";
  let dir: string;
  let km: KeyManager;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "uam-token-relay-"));
    km = new KeyManager(dir);
    km.saveToken("bob", "a-token");
  });

  afterEach(() => {
    delete process.env["UAM_TOKEN"];
    rmSync(dir, { recursive: true, force: true });
  });

  function addressFile(content: string): void {
    writeFileSync(join(dir, "bob.address"), content);
  }

  it("gives the token to the relay that issued it", () => {
    km.saveAddress("bob", "bob::youam.test", RELAY);
    expect(km.loadToken("bob", RELAY)).toBe("a-token");
  });

  it("ignores trailing slashes on either side", () => {
    km.saveAddress("bob", "bob::youam.test", `${RELAY}/`);
    expect(km.loadToken("bob", RELAY)).toBe("a-token");
    expect(km.loadToken("bob", `${RELAY}//`)).toBe("a-token");
  });

  it("keeps it from a different relay", () => {
    km.saveAddress("bob", "bob::youam.test", RELAY);
    expect(km.loadToken("bob", "http://elsewhere.test")).toBeNull();
  });

  it("keeps a legacy .api_key from a different relay too", () => {
    rmSync(join(dir, "bob.token"));
    writeFileSync(join(dir, "bob.api_key"), "old-key");
    km.saveAddress("bob", "bob::youam.test", RELAY);
    expect(km.loadToken("bob", "http://elsewhere.test")).toBeNull();
    expect(km.loadToken("bob", RELAY)).toBe("old-key");
  });

  it("lets UAM_TOKEN win whatever the file says", () => {
    km.saveAddress("bob", "bob::youam.test", RELAY);
    process.env["UAM_TOKEN"] = "env-token";
    expect(km.loadToken("bob", "http://elsewhere.test")).toBe("env-token");
  });

  it("has no objection when there is no address file", () => {
    expect(km.loadToken("bob", "http://elsewhere.test")).toBe("a-token");
  });

  it.each([
    ["an old plain-text address", "bob::youam.test"],
    ["broken JSON", '{"address": '],
    ["a JSON null", "null"],
    ["a JSON list", "[]"],
    ["no relay", JSON.stringify({ address: "bob::youam.test" })],
    ["a relay that isn't a string", JSON.stringify({ relay_url: 42 })],
  ])("has no objection to a file with %s", (_name, content) => {
    addressFile(content);
    expect(km.loadToken("bob", "http://elsewhere.test")).toBe("a-token");
  });

  it("has no objection to an address file it can't read", () => {
    mkdirSync(join(dir, "bob.address"));
    expect(km.loadToken("bob", "http://elsewhere.test")).toBe("a-token");
  });

  it("loads the token for showing when no relay is named", () => {
    km.saveAddress("bob", "bob::youam.test", RELAY);
    expect(km.loadToken("bob")).toBe("a-token");
  });
});
