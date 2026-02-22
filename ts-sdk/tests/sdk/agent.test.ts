/**
 * Tests for Agent class (unit-level, no live relay).
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { sodiumReady, generateKeypair, serializeSigningKey, serializeVerifyKey } from "../../src/protocol/index.js";
import { Agent } from "../../src/sdk/agent.js";
import { SDKConfig } from "../../src/sdk/config.js";

describe("Agent", () => {
  let tempDir: string;

  beforeAll(async () => {
    await sodiumReady;
  });

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), "uam-agent-test-"));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  // -- Constructor --------------------------------------------------------

  it("constructor sets default config correctly", () => {
    const agent = new Agent("testagent", {
      keyDir: join(tempDir, "keys"),
    });
    expect(agent._config.name).toBe("testagent");
    expect(agent._config.relayUrl).toBe("https://relay.youam.network");
    expect(agent._config.transportType).toBe("websocket");
    expect(agent._config.trustPolicy).toBe("auto-accept");
    expect(agent._config.displayName).toBe("testagent");
  });

  it("constructor accepts custom relay URL", () => {
    const agent = new Agent("testagent", {
      relay: "https://custom.relay.com",
      keyDir: join(tempDir, "keys"),
    });
    expect(agent._config.relayUrl).toBe("https://custom.relay.com");
    expect(agent._config.relayDomain).toBe("custom.relay.com");
  });

  it("constructor accepts custom domain", () => {
    const agent = new Agent("testagent", {
      domain: "my.domain",
      keyDir: join(tempDir, "keys"),
    });
    expect(agent._config.relayDomain).toBe("my.domain");
  });

  it("constructor accepts http transport", () => {
    const agent = new Agent("testagent", {
      transport: "http",
      keyDir: join(tempDir, "keys"),
    });
    expect(agent._config.transportType).toBe("http");
  });

  it("constructor accepts approval-required policy", () => {
    const agent = new Agent("testagent", {
      trustPolicy: "approval-required",
      keyDir: join(tempDir, "keys"),
    });
    expect(agent._config.trustPolicy).toBe("approval-required");
  });

  it("constructor accepts custom display name", () => {
    const agent = new Agent("testagent", {
      displayName: "Test Agent X",
      keyDir: join(tempDir, "keys"),
    });
    expect(agent._config.displayName).toBe("Test Agent X");
  });

  // -- Properties before connect ------------------------------------------

  it("address throws before connect", () => {
    const agent = new Agent("testagent", {
      keyDir: join(tempDir, "keys"),
    });
    expect(() => agent.address).toThrow("Agent not yet connected");
  });

  it("isConnected is false before connect", () => {
    const agent = new Agent("testagent", {
      keyDir: join(tempDir, "keys"),
    });
    expect(agent.isConnected).toBe(false);
  });

  it("version returns a string", () => {
    const agent = new Agent("testagent", {
      keyDir: join(tempDir, "keys"),
    });
    expect(typeof agent.version).toBe("string");
    expect(agent.version).toBe("0.1.0");
  });

  it("publicKey throws before keys are loaded", () => {
    const agent = new Agent("testagent", {
      keyDir: join(tempDir, "keys"),
    });
    expect(() => agent.publicKey).toThrow("No keypair loaded");
  });

  it("contactCard throws before connect", async () => {
    const agent = new Agent("testagent", {
      keyDir: join(tempDir, "keys"),
    });
    await expect(agent.contactCard()).rejects.toThrow(
      "Agent not connected"
    );
  });

  // -- KeyManager integration ---------------------------------------------

  it("generates keys when loadOrGenerate is called", () => {
    const keysDir = join(tempDir, "keys");
    const agent = new Agent("keytest", {
      keyDir: keysDir,
    });
    // Manually load keys (connect would also do this but needs a relay)
    agent._keyManager.loadOrGenerate("keytest");
    expect(agent.publicKey).toBeTruthy();
    expect(typeof agent.publicKey).toBe("string");
  });

  // -- ContactBook integration --------------------------------------------

  it("contact book is initialized but not opened", () => {
    const agent = new Agent("cbtest", {
      keyDir: join(tempDir, "keys"),
    });
    // ContactBook is created but not open yet (open happens in connect)
    expect(agent._contactBook).toBeTruthy();
  });

  // -- Handshake manager --------------------------------------------------

  it("handshake manager has correct trust policy", () => {
    const agent = new Agent("hstest", {
      trustPolicy: "allowlist-only",
      keyDir: join(tempDir, "keys"),
    });
    expect(agent._handshake._trustPolicy).toBe("allowlist-only");
  });

  // -- Transport factory (unit) -------------------------------------------

  it("transport is null before connect", () => {
    const agent = new Agent("ttest", {
      keyDir: join(tempDir, "keys"),
    });
    expect(agent._transport).toBeNull();
  });

  // -- Auto-register disabled --------------------------------------------

  it("connect throws when no token and autoRegister=false", async () => {
    const keysDir = join(tempDir, "keys2");
    const agent = new Agent("noregtest", {
      keyDir: keysDir,
      autoRegister: false,
      relay: "http://localhost:9999",
    });

    await expect(agent.connect()).rejects.toThrow(
      "No stored token and autoRegister=false"
    );
  });

  // -- Returning user with stored token -----------------------------------

  it("connect uses stored token without hitting relay", async () => {
    // Pre-create keys and token so connect doesn't need a relay
    const keysDir = join(tempDir, "returning-keys");
    const kp = generateKeypair();
    const { mkdirSync } = require("node:fs");
    mkdirSync(keysDir, { recursive: true });
    writeFileSync(join(keysDir, "returnuser.key"), serializeSigningKey(kp.seed));
    writeFileSync(join(keysDir, "returnuser.pub"), serializeVerifyKey(kp.verifyKey));
    writeFileSync(join(keysDir, "returnuser.token"), "stored_tok_xyz");

    const dataDir = join(tempDir, "returning-data");
    const agent = new Agent("returnuser", {
      keyDir: keysDir,
      relay: "http://localhost:9999",
      // Use HTTP transport to avoid WebSocket connection attempt
      transport: "http",
    });

    // Override dataDir via creating SDKConfig manually is complex,
    // but we can directly set data dir through the contact book path
    // For this test, we just verify the token loading logic works
    // by checking that connect() succeeds without contacting the relay
    // (HTTP transport connect is a no-op)

    // We need to make sure the contact book can open
    // The agent will use its config's dataDir. Let's create the contacts dir
    mkdirSync(join(agent._config.dataDir, "contacts"), { recursive: true });

    await agent.connect();

    expect(agent.isConnected).toBe(true);
    expect(agent.address).toBe("returnuser::localhost");
    await agent.close();
  });
});
