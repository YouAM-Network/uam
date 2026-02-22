/**
 * UAM CLI -- Universal Agent Messaging command-line interface.
 *
 * TypeScript port of the Python CLI (src/uam/cli/main.py).
 * Uses commander instead of click.
 */

import { Command } from "commander";

import { initCommand } from "./commands/init.js";
import { sendCommand } from "./commands/send.js";
import { inboxCommand } from "./commands/inbox.js";
import { cardCommand } from "./commands/card.js";
import { whoamiCommand } from "./commands/whoami.js";
import { contactsCommand } from "./commands/contacts.js";

const program = new Command();

program
  .name("uam")
  .description("Universal Agent Messaging CLI")
  .version("0.1.0");

// Global option: --name/-n for agent name (auto-detected if not provided)
program.option("-n, --name <name>", "Agent name (auto-detected from ~/.uam/keys/)");

// ---- init ------------------------------------------------------------------
program
  .command("init")
  .description("Initialize a new agent: generate keys and register with relay")
  .option("-n, --name <name>", "Agent name")
  .option("-r, --relay <url>", "Relay URL (default: relay.youam.network)")
  .action(async (opts) => {
    const globalName = program.opts().name;
    await initCommand({
      name: opts.name ?? globalName,
      relay: opts.relay,
    });
  });

// ---- send ------------------------------------------------------------------
program
  .command("send <address> <message>")
  .description("Send a message to another agent")
  .action(async (address: string, message: string) => {
    const globalName = program.opts().name;
    await sendCommand(address, message, { name: globalName });
  });

// ---- inbox -----------------------------------------------------------------
program
  .command("inbox")
  .description("Check your inbox for pending messages")
  .option("-l, --limit <number>", "Max messages to retrieve", "20")
  .action(async (opts) => {
    const globalName = program.opts().name;
    await inboxCommand({
      name: globalName,
      limit: parseInt(opts.limit, 10),
    });
  });

// ---- card ------------------------------------------------------------------
program
  .command("card")
  .description("Display your signed contact card as JSON")
  .action(async () => {
    const globalName = program.opts().name;
    await cardCommand({ name: globalName });
  });

// ---- whoami ----------------------------------------------------------------
program
  .command("whoami")
  .description("Display your agent address and public key fingerprint (offline)")
  .action(async () => {
    const globalName = program.opts().name;
    await whoamiCommand({ name: globalName });
  });

// ---- contacts --------------------------------------------------------------
program
  .command("contacts")
  .description("List known contacts from the local contact book")
  .action(async () => {
    const globalName = program.opts().name;
    await contactsCommand({ name: globalName });
  });

program.parse(process.argv);
