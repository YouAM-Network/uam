/**
 * uam card -- Display your signed contact card as JSON.
 *
 * Matches Python CLI card command output format.
 */

import { Agent } from "../../sdk/agent.js";
import { findAgentName, cliError } from "../helpers.js";

export async function cardCommand(options: {
  name?: string;
}): Promise<void> {
  const agentName = options.name ?? findAgentName();
  if (!agentName) {
    cliError("No agent initialized. Run `uam init` first.");
  }

  try {
    const agent = new Agent(agentName);
    await agent.connect();
    const card = await agent.contactCard();
    await agent.close();
    console.log(JSON.stringify(card, null, 2));
  } catch (err) {
    cliError(`Error: ${err instanceof Error ? err.message : String(err)}`);
  }
}
