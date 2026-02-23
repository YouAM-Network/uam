/**
 * SDK configuration (matching Python config.py).
 *
 * Priority (highest wins): constructor arg > env var > default.
 * TOML config file support is Python-only for now (unnecessary complexity for TS MVP).
 */

import { homedir } from "node:os";
import { join } from "node:path";

const DEFAULT_RELAY_URL = "https://relay.youam.network";

const VALID_POLICIES = new Set([
  "auto-accept",
  "approval-required",
  "allowlist-only",
  "require_verify",
]);

export class SDKConfig {
  readonly name: string;
  readonly relayUrl: string;
  readonly relayWsUrl: string;
  readonly keyDir: string;
  readonly dataDir: string;
  readonly displayName: string;
  readonly transportType: string;
  readonly trustPolicy: string;
  readonly relayDomain: string;

  constructor(options: {
    name: string;
    relayUrl?: string | null;
    relayWsUrl?: string | null;
    keyDir?: string | null;
    dataDir?: string | null;
    displayName?: string | null;
    transportType?: string;
    trustPolicy?: string;
    relayDomain?: string;
  }) {
    this.name = options.name;

    // Relay URL: constructor arg > env var > default
    this.relayUrl =
      options.relayUrl ?? process.env["UAM_RELAY_URL"] ?? DEFAULT_RELAY_URL;

    // Derive relayWsUrl from relayUrl if not explicitly set
    if (options.relayWsUrl) {
      this.relayWsUrl = options.relayWsUrl;
    } else {
      let wsUrl = this.relayUrl
        .replace("https://", "wss://")
        .replace("http://", "ws://");
      if (!wsUrl.endsWith("/ws")) {
        wsUrl = wsUrl.replace(/\/+$/, "") + "/ws";
      }
      this.relayWsUrl = wsUrl;
    }

    // Derive relayDomain: env var > constructor arg > URL hostname
    const envDomain = process.env["UAM_RELAY_DOMAIN"];
    if (envDomain) {
      this.relayDomain = envDomain;
    } else if (options.relayDomain) {
      this.relayDomain = options.relayDomain;
    } else {
      // Extract hostname from relayUrl
      try {
        const parsed = new URL(this.relayUrl);
        this.relayDomain = parsed.hostname || "localhost";
      } catch {
        // Fallback for malformed URLs
        const afterScheme = this.relayUrl.split("://").pop() || "";
        this.relayDomain = afterScheme.split("/")[0] || "localhost";
      }
    }

    // Default key_dir and data_dir.
    // UAM_HOME env var overrides ~/.uam (useful for testing / isolation).
    const uamHome = process.env["UAM_HOME"];
    const defaultHome = uamHome || join(homedir(), ".uam");

    this.keyDir = options.keyDir ?? join(defaultHome, "keys");
    this.dataDir = options.dataDir ?? defaultHome;

    // Display name defaults to agent name
    this.displayName = options.displayName ?? this.name;

    // Transport type
    this.transportType = options.transportType ?? "websocket";

    // Trust policy: constructor arg > env var > default
    let policy = options.trustPolicy ?? "auto-accept";
    const envPolicy = process.env["UAM_TRUST_POLICY"];
    if (envPolicy) {
      policy = envPolicy;
    }

    if (!VALID_POLICIES.has(policy)) {
      throw new Error(
        `Invalid trust_policy '${policy}'. ` +
          `Must be one of: ${JSON.stringify([...VALID_POLICIES].sort())}`
      );
    }

    this.trustPolicy = policy;
  }
}
