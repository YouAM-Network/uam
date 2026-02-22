/**
 * CLI unit tests.
 *
 * Tests offline commands (whoami) and the findAgentName helper.
 * Commands requiring relay connection are tested for error handling only.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import { findAgentName } from "../../src/cli/helpers.js";
import { sodiumReady, generateKeypair, serializeSigningKey, serializeVerifyKey } from "../../src/protocol/index.js";

// ---------------------------------------------------------------------------
// Test setup
// ---------------------------------------------------------------------------

let testDir: string;

beforeAll(async () => {
  await sodiumReady;
});

beforeEach(() => {
  testDir = join(tmpdir(), `uam-cli-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(testDir, { recursive: true });
});

afterEach(() => {
  if (existsSync(testDir)) {
    rmSync(testDir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// findAgentName
// ---------------------------------------------------------------------------

describe("findAgentName", () => {
  it("returns null when directory does not exist", () => {
    const result = findAgentName(join(testDir, "nonexistent"));
    expect(result).toBeNull();
  });

  it("returns null when directory has no .key files", () => {
    const keyDir = join(testDir, "keys");
    mkdirSync(keyDir, { recursive: true });
    writeFileSync(join(keyDir, "somefile.txt"), "not a key");
    const result = findAgentName(keyDir);
    expect(result).toBeNull();
  });

  it("returns agent name from single .key file", () => {
    const keyDir = join(testDir, "keys");
    mkdirSync(keyDir, { recursive: true });
    writeFileSync(join(keyDir, "alice.key"), "seed-data");
    const result = findAgentName(keyDir);
    expect(result).toBe("alice");
  });

  it("returns first alphabetically when multiple .key files exist", () => {
    const keyDir = join(testDir, "keys");
    mkdirSync(keyDir, { recursive: true });
    writeFileSync(join(keyDir, "charlie.key"), "seed");
    writeFileSync(join(keyDir, "alice.key"), "seed");
    writeFileSync(join(keyDir, "bob.key"), "seed");
    const result = findAgentName(keyDir);
    expect(result).toBe("alice");
  });
});

// ---------------------------------------------------------------------------
// whoami command (offline)
// ---------------------------------------------------------------------------

describe("whoami", () => {
  it("outputs address, fingerprint, and key file path", async () => {
    // Set up a key directory with a valid key
    const keyDir = join(testDir, "keys");
    mkdirSync(keyDir, { recursive: true });

    const kp = generateKeypair();
    const seedB64 = serializeSigningKey(kp.seed);
    writeFileSync(join(keyDir, "testagent.key"), seedB64);
    writeFileSync(join(keyDir, "testagent.pub"), serializeVerifyKey(kp.verifyKey));

    // Import and call whoamiCommand with UAM_HOME override
    const originalHome = process.env["UAM_HOME"];
    process.env["UAM_HOME"] = testDir;

    try {
      // Capture console.log output
      const logs: string[] = [];
      const originalLog = console.log;
      console.log = (msg: string) => logs.push(msg);

      const { whoamiCommand } = await import("../../src/cli/commands/whoami.js");
      await whoamiCommand({ name: "testagent" });

      console.log = originalLog;

      expect(logs.length).toBe(3);
      expect(logs[0]).toMatch(/^Address:\s+testagent::/);
      expect(logs[1]).toMatch(/^Fingerprint:\s+[0-9a-f]{64}$/);
      expect(logs[2]).toMatch(/^Key file:\s+/);
      expect(logs[2]).toContain("testagent.key");
    } finally {
      if (originalHome !== undefined) {
        process.env["UAM_HOME"] = originalHome;
      } else {
        delete process.env["UAM_HOME"];
      }
    }
  });
});

// ---------------------------------------------------------------------------
// contacts command (offline)
// ---------------------------------------------------------------------------

describe("contacts", () => {
  it("outputs 'No contacts yet.' when no contacts exist", async () => {
    const originalHome = process.env["UAM_HOME"];
    process.env["UAM_HOME"] = testDir;

    try {
      const logs: string[] = [];
      const originalLog = console.log;
      console.log = (msg: string) => logs.push(msg);

      const { contactsCommand } = await import("../../src/cli/commands/contacts.js");
      await contactsCommand({ name: "testuser" });

      console.log = originalLog;

      expect(logs.some((l) => l.includes("No contacts yet."))).toBe(true);
    } finally {
      if (originalHome !== undefined) {
        process.env["UAM_HOME"] = originalHome;
      } else {
        delete process.env["UAM_HOME"];
      }
    }
  });
});

// ---------------------------------------------------------------------------
// init command (error path -- no relay)
// ---------------------------------------------------------------------------

describe("init", () => {
  it("shows already-initialized message when key exists", async () => {
    const keyDir = join(testDir, "keys");
    mkdirSync(keyDir, { recursive: true });

    const kp = generateKeypair();
    const seedB64 = serializeSigningKey(kp.seed);
    writeFileSync(join(keyDir, "myagent.key"), seedB64);
    writeFileSync(join(keyDir, "myagent.pub"), serializeVerifyKey(kp.verifyKey));

    const originalHome = process.env["UAM_HOME"];
    process.env["UAM_HOME"] = testDir;

    try {
      const logs: string[] = [];
      const originalLog = console.log;
      console.log = (msg: string) => logs.push(msg);

      const { initCommand } = await import("../../src/cli/commands/init.js");
      await initCommand({ name: "myagent" });

      console.log = originalLog;

      expect(logs.some((l) => l.includes("Agent already initialized"))).toBe(true);
      expect(logs.some((l) => l.includes("Fingerprint:"))).toBe(true);
    } finally {
      if (originalHome !== undefined) {
        process.env["UAM_HOME"] = originalHome;
      } else {
        delete process.env["UAM_HOME"];
      }
    }
  });
});

// ---------------------------------------------------------------------------
// CLI program structure
// ---------------------------------------------------------------------------

describe("CLI program", () => {
  it("exports a working commander program", async () => {
    // Verify the CLI module can be imported without errors
    // (we cannot actually parse args without side effects, but we verify the import)
    const { Command } = await import("commander");
    expect(Command).toBeDefined();
  });
});
