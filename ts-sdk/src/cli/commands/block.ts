/**
 * uam block <pattern> -- Block an address or domain pattern.
 *
 * Matches Python CLI block command (HAND-06).
 * Pattern format: exact address (e.g., spammer::evil.com) or domain wildcard (*::evil.com).
 */

import { Agent } from "../../sdk/agent.js";
import { findAgentName, cliError } from "../helpers.js";

export async function blockCommand(
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
    await agent.block(pattern);
    await agent.close();
    console.log(`Blocked: ${pattern}`);
    console.log("Pattern formats: exact address (user::domain) or wildcard (*::domain)");
  } catch (err) {
    cliError(`Error: ${err instanceof Error ? err.message : err}`);
  }
}
