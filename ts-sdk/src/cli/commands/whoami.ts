/**
 * uam whoami -- Display your agent address and public key fingerprint.
 *
 * OFFLINE: no connect() needed, just reads key files from disk.
 * Matches Python CLI whoami command output format.
 */

import { existsSync } from "node:fs";
import { join } from "node:path";

import { sodiumReady, publicKeyFingerprint } from "../../protocol/index.js";
import { SDKConfig } from "../../sdk/config.js";
import { KeyManager } from "../../sdk/key-manager.js";
import { findAgentName, cliError } from "../helpers.js";

export async function whoamiCommand(options: {
  name?: string;
}): Promise<void> {
  const agentName = options.name ?? findAgentName();
  if (!agentName) {
    cliError("No agent initialized. Run `uam init` first.");
  }

  const cfg = new SDKConfig({ name: agentName });
  const keyPath = join(cfg.keyDir, `${agentName}.key`);
  if (!existsSync(keyPath)) {
    cliError("No agent initialized. Run `uam init` first.");
  }

  // Ensure sodium ready for fingerprint computation
  await sodiumReady;

  const km = new KeyManager(cfg.keyDir);
  km.loadOrGenerate(agentName);
  const address = `${agentName}::${cfg.relayDomain}`;
  const fp = publicKeyFingerprint(km.verifyKey);

  console.log(`Address:     ${address}`);
  console.log(`Fingerprint: ${fp}`);
  console.log(`Key file:    ${keyPath}`);
}
