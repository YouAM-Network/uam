/**
 * uam pending -- List pending handshake requests awaiting approval.
 *
 * Matches Python CLI pending command (HAND-06).
 */

import { Agent } from "../../sdk/agent.js";
import { findAgentName, cliError } from "../helpers.js";

export async function pendingCommand(options: {
  name?: string;
}): Promise<void> {
  const agentName = options.name ?? findAgentName();
  if (!agentName) {
    cliError("No agent initialized. Run `uam init` first.");
  }

  try {
    const agent = new Agent(agentName);
    await agent.connect();
    const items = await agent.pending();
    await agent.close();

    if (items.length === 0) {
      console.log("No pending handshake requests.");
      return;
    }

    console.log(`${"ADDRESS".padEnd(35)} RECEIVED`);
    for (const item of items) {
      const addr = item.address;
      const received = item.receivedAt ?? "";
      console.log(`${addr.padEnd(35)} ${received}`);
    }
  } catch (err) {
    cliError(`Error: ${err instanceof Error ? err.message : err}`);
  }
}
