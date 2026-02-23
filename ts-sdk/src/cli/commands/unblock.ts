/**
 * uam unblock <pattern> -- Remove a block on an address or domain pattern.
 *
 * Matches Python CLI unblock command (HAND-06).
 */

import { Agent } from "../../sdk/agent.js";
import { findAgentName, cliError } from "../helpers.js";

export async function unblockCommand(
  pattern: string,
  options: { name?: string }
): Promise<void> {
  const agentName = options.name ?? findAgentName();
  if (!agentName) {
    cliError("No agent initialized. Run `uam init` first.");
  }

  try {
    const agent = new Agent(agentName);
    await agent.connect();
    await agent.unblock(pattern);
    await agent.close();
    console.log(`Unblocked: ${pattern}`);
  } catch (err) {
    cliError(`Error: ${err instanceof Error ? err.message : err}`);
  }
}
