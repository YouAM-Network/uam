/**
 * uam contacts -- List known contacts from the local contact book.
 *
 * Matches Python CLI contacts command output format.
 */

import { SDKConfig } from "../../sdk/config.js";
import { ContactBook } from "../../sdk/contact-book.js";
import { findAgentName } from "../helpers.js";

export async function contactsCommand(options: {
  name?: string;
}): Promise<void> {
  const agentName = options.name ?? findAgentName();

  // Determine data_dir
  const cfg = new SDKConfig({ name: agentName ?? "_probe" });
  const book = new ContactBook(cfg.dataDir);

  try {
    book.open();
    const rows = book.listContacts();
    book.close();

    if (rows.length === 0) {
      console.log("No contacts yet.");
      return;
    }

    // Print table header
    console.log(
      `${"ADDRESS".padEnd(30)} ${"TRUST".padEnd(18)} LAST SEEN`
    );
    for (const row of rows) {
      const addr = row.address;
      const trust = row.trustState;
      const last = row.lastSeen ?? "";
      console.log(
        `${addr.padEnd(30)} ${trust.padEnd(18)} ${last}`
      );
    }
  } catch {
    console.log("No contacts yet.");
  }
}
