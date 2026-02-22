/**
 * Tests for SDKConfig.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { SDKConfig } from "../../src/sdk/config.js";
import { homedir } from "node:os";
import { join } from "node:path";

describe("SDKConfig", () => {
  // Save and restore env vars
  const savedEnv: Record<string, string | undefined> = {};
  const envKeys = [
    "UAM_RELAY_URL",
    "UAM_RELAY_DOMAIN",
    "UAM_HOME",
    "UAM_TRUST_POLICY",
  ];

  beforeEach(() => {
    for (const key of envKeys) {
      savedEnv[key] = process.env[key];
      delete process.env[key];
    }
  });

  afterEach(() => {
    for (const key of envKeys) {
      if (savedEnv[key] !== undefined) {
        process.env[key] = savedEnv[key];
      } else {
        delete process.env[key];
      }
    }
  });

  it("uses default relay URL when none provided", () => {
    const cfg = new SDKConfig({ name: "alice" });
    expect(cfg.relayUrl).toBe("https://relay.youam.network");
  });

  it("derives relayWsUrl from relayUrl", () => {
    const cfg = new SDKConfig({ name: "alice" });
    expect(cfg.relayWsUrl).toBe("wss://relay.youam.network/ws");
  });

  it("derives relayWsUrl from http URL", () => {
    const cfg = new SDKConfig({
      name: "alice",
      relayUrl: "http://localhost:8080",
    });
    expect(cfg.relayWsUrl).toBe("ws://localhost:8080/ws");
  });

  it("uses explicit relayWsUrl when provided", () => {
    const cfg = new SDKConfig({
      name: "alice",
      relayWsUrl: "wss://custom.relay/ws",
    });
    expect(cfg.relayWsUrl).toBe("wss://custom.relay/ws");
  });

  it("derives relayDomain from relay URL hostname", () => {
    const cfg = new SDKConfig({ name: "alice" });
    expect(cfg.relayDomain).toBe("relay.youam.network");
  });

  it("uses explicit relayDomain", () => {
    const cfg = new SDKConfig({
      name: "alice",
      relayDomain: "custom.domain",
    });
    expect(cfg.relayDomain).toBe("custom.domain");
  });

  it("prefers UAM_RELAY_DOMAIN env var over URL", () => {
    process.env["UAM_RELAY_DOMAIN"] = "env-domain.com";
    const cfg = new SDKConfig({ name: "alice" });
    expect(cfg.relayDomain).toBe("env-domain.com");
  });

  it("uses UAM_RELAY_URL env var", () => {
    process.env["UAM_RELAY_URL"] = "https://env-relay.com";
    const cfg = new SDKConfig({ name: "alice" });
    expect(cfg.relayUrl).toBe("https://env-relay.com");
  });

  it("default key/data dirs use homedir", () => {
    const cfg = new SDKConfig({ name: "alice" });
    expect(cfg.keyDir).toBe(join(homedir(), ".uam", "keys"));
    expect(cfg.dataDir).toBe(join(homedir(), ".uam"));
  });

  it("UAM_HOME env var overrides base directory", () => {
    process.env["UAM_HOME"] = "/tmp/testuam";
    const cfg = new SDKConfig({ name: "alice" });
    expect(cfg.keyDir).toBe(join("/tmp/testuam", "keys"));
    expect(cfg.dataDir).toBe("/tmp/testuam");
  });

  it("uses custom keyDir when provided", () => {
    const cfg = new SDKConfig({ name: "alice", keyDir: "/custom/keys" });
    expect(cfg.keyDir).toBe("/custom/keys");
  });

  it("displayName defaults to name", () => {
    const cfg = new SDKConfig({ name: "alice" });
    expect(cfg.displayName).toBe("alice");
  });

  it("uses custom displayName", () => {
    const cfg = new SDKConfig({ name: "alice", displayName: "Alice Agent" });
    expect(cfg.displayName).toBe("Alice Agent");
  });

  it("default trust policy is auto-accept", () => {
    const cfg = new SDKConfig({ name: "alice" });
    expect(cfg.trustPolicy).toBe("auto-accept");
  });

  it("uses custom trust policy", () => {
    const cfg = new SDKConfig({
      name: "alice",
      trustPolicy: "approval-required",
    });
    expect(cfg.trustPolicy).toBe("approval-required");
  });

  it("UAM_TRUST_POLICY env var overrides constructor", () => {
    process.env["UAM_TRUST_POLICY"] = "allowlist-only";
    const cfg = new SDKConfig({ name: "alice" });
    expect(cfg.trustPolicy).toBe("allowlist-only");
  });

  it("rejects invalid trust policy", () => {
    expect(
      () => new SDKConfig({ name: "alice", trustPolicy: "invalid" })
    ).toThrow("Invalid trust_policy");
  });

  it("default transport is websocket", () => {
    const cfg = new SDKConfig({ name: "alice" });
    expect(cfg.transportType).toBe("websocket");
  });

  it("uses custom transport type", () => {
    const cfg = new SDKConfig({ name: "alice", transportType: "http" });
    expect(cfg.transportType).toBe("http");
  });
});
