/**
 * uam deny <address> -- Deny a pending handshake request.
 *
 * Matches Python CLI deny command (HAND-06).
 */

import { Agent } from "../../sdk/agent.js";
import { findAgentName, cliError } from "../helpers.js";

export async function denyCommand(
  address: string,
  options: { name?: string }
): Promise<void> {
  const agentName = options.name ?? findAgentName();
  if (!agentName) {
    cliError("No agent initialized. Run `uam init` first.");
  }

  try {
    const agent = new Agent(agentName);
    await agent.connect();
    await agent.deny(address);
    await agent.close();
    console.log(`Denied: ${address}`);
  } catch (err) {
    cliError(`Error: ${err instanceof Error ? err.message : err}`);
  }
}
