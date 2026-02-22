/**
 * uam inbox -- Check your inbox for pending messages.
 *
 * Matches Python CLI inbox command output format.
 */

import { Agent } from "../../sdk/agent.js";
import { findAgentName, cliError } from "../helpers.js";

export async function inboxCommand(options: {
  name?: string;
  limit?: number;
}): Promise<void> {
  const agentName = options.name ?? findAgentName();
  if (!agentName) {
    cliError("No agent initialized. Run `uam init` first.");
  }

  const limit = options.limit ?? 20;

  try {
    const agent = new Agent(agentName);
    await agent.connect();
    const messages = await agent.inbox(limit);
    await agent.close();

    if (messages.length === 0) {
      console.log("No pending messages.");
      return;
    }

    for (const msg of messages) {
      console.log(`From: ${msg.fromAddress}`);
      console.log(`Time: ${msg.timestamp}`);
      console.log("---");
      console.log(msg.content);
      console.log();
    }
  } catch (err) {
    cliError(`Error: ${err instanceof Error ? err.message : String(err)}`);
  }
}
