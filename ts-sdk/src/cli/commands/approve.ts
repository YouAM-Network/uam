/**
 * uam approve <address> -- Approve a pending handshake request.
 *
 * Matches Python CLI approve command (HAND-06).
 */

import { Agent } from "../../sdk/agent.js";
import { findAgentName, cliError } from "../helpers.js";

export async function approveCommand(
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
    await agent.approve(address);
    await agent.close();
    console.log(`Approved: ${address}`);
  } catch (err) {
    cliError(`Error: ${err instanceof Error ? err.message : err}`);
  }
}
