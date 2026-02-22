/**
 * uam init -- Initialize a new agent: generate keys and register with relay.
 *
 * Matches Python CLI init command output format.
 */

import { hostname } from "node:os";
import { existsSync } from "node:fs";
import { join } from "node:path";

import { publicKeyFingerprint } from "../../protocol/index.js";
import { SDKConfig } from "../../sdk/config.js";
import { KeyManager } from "../../sdk/key-manager.js";
import { Agent } from "../../sdk/agent.js";
import { cliError } from "../helpers.js";

export async function initCommand(options: {
  name?: string;
  relay?: string;
}): Promise<void> {
  let agentName = options.name;
  if (!agentName) {
    agentName = hostname().split(".")[0].toLowerCase();
  }

  try {
    // Check if already initialized
    const cfg = new SDKConfig({ name: agentName, relayUrl: options.relay });
    const km = new KeyManager(cfg.keyDir);
    const keyPath = join(cfg.keyDir, `${agentName}.key`);

    if (existsSync(keyPath)) {
      km.loadOrGenerate(agentName);
      const address = `${agentName}::${cfg.relayDomain}`;
      const fp = publicKeyFingerprint(km.verifyKey);
      console.log(`Agent already initialized: ${address}`);
      console.log(`Fingerprint: ${fp}`);
      return;
    }

    // New agent -- connect to register
    const agent = new Agent(agentName, { relay: options.relay });
    await agent.connect();
    const address = agent.address;
    const fp = publicKeyFingerprint(agent._keyManager.verifyKey);
    await agent.close();
    console.log(`Initialized agent: ${address}`);
    console.log(`Fingerprint: ${fp}`);
  } catch (err) {
    cliError(`Error: ${err instanceof Error ? err.message : String(err)}`);
  }
}
