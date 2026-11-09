/**
 * uam send -- Send a message to another agent.
 *
 * Matches the Python CLI's send output: the relay's status, and on
 * "pending" the note not to resend.
 */

import { Agent } from "../../sdk/agent.js";
import { pendingNote } from "../../sdk/message.js";
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
    const result = await agent.send(address, message);
    await agent.close();
    console.log(`Message to ${address}: ${result.status} (id: ${result.messageId})`);
    if (result.status === "pending") {
      console.log(pendingNote(address));
    }
  } catch (err) {
    cliError(`Error: ${err instanceof Error ? err.message : String(err)}`);
  }
}
