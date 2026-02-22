/**
 * uam send -- Send a message to another agent.
 *
 * Matches Python CLI send command output format.
 */

import { Agent } from "../../sdk/agent.js";
import { findAgentName, cliError } from "../helpers.js";

export async function sendCommand(
  address: string,
  message: string,
  options: { name?: string }
): Promise<void> {
  const agentName = options.name ?? findAgentName();
  if (!agentName) {
    cliError("No agent initialized. Run `uam init` first.");
  }

  try {
    const agent = new Agent(agentName);
    await agent.connect();
    const msgId = await agent.send(address, message);
    await agent.close();
    console.log(`Message sent to ${address} (id: ${msgId})`);
  } catch (err) {
    cliError(`Error: ${err instanceof Error ? err.message : String(err)}`);
  }
}
