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
import { pendingCommand } from "./commands/pending.js";
import { approveCommand } from "./commands/approve.js";
import { denyCommand } from "./commands/deny.js";
import { blockCommand } from "./commands/block.js";
import { unblockCommand } from "./commands/unblock.js";
import {
  contactFingerprintCommand,
  contactVerifyCommand,
  contactRemoveCommand,
} from "./commands/contact.js";
import { verifyDomainCommand } from "./commands/verify-domain.js";

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

// ---- contact (subcommands) -------------------------------------------------
const contactCmd = program
  .command("contact")
  .description("Contact management commands (fingerprint, verify, remove)");

contactCmd
  .command("fingerprint <address>")
  .description("Display the fingerprint for a known contact's public key")
  .action(async (address: string) => {
    const globalName = program.opts().name;
    await contactFingerprintCommand(address, { name: globalName });
  });

contactCmd
  .command("verify <address>")
  .description("Manually verify a contact, upgrading trust state to verified")
  .option("-y, --yes", "Skip confirmation prompt")
  .action(async (address: string, opts) => {
    const globalName = program.opts().name;
    await contactVerifyCommand(address, { name: globalName, yes: opts.yes });
  });

contactCmd
  .command("remove <address>")
  .description("Remove a contact from the contact book")
  .action(async (address: string) => {
    const globalName = program.opts().name;
    await contactRemoveCommand(address, { name: globalName });
  });

// ---- verify-domain ---------------------------------------------------------
program
  .command("verify-domain <domain>")
  .description("Verify domain ownership for Tier 2 DNS-verified status")
  .option("-t, --timeout <seconds>", "Polling timeout in seconds", "300")
  .option("--poll-interval <seconds>", "Polling interval in seconds", "10")
  .action(async (domain: string, opts) => {
    const globalName = program.opts().name;
    await verifyDomainCommand(domain, {
      name: globalName,
      timeout: parseInt(opts.timeout, 10),
      pollInterval: parseInt(opts.pollInterval, 10),
    });
  });

// ---- pending ---------------------------------------------------------------
program
  .command("pending")
  .description("List pending handshake requests awaiting approval")
  .action(async () => {
    const globalName = program.opts().name;
    await pendingCommand({ name: globalName });
  });

// ---- approve ---------------------------------------------------------------
program
  .command("approve <address>")
  .description("Approve a pending handshake request")
  .action(async (address: string) => {
    const globalName = program.opts().name;
    await approveCommand(address, { name: globalName });
  });

// ---- deny ------------------------------------------------------------------
program
  .command("deny <address>")
  .description("Deny a pending handshake request")
  .action(async (address: string) => {
    const globalName = program.opts().name;
    await denyCommand(address, { name: globalName });
  });

// ---- block -----------------------------------------------------------------
program
  .command("block <pattern>")
  .description("Block an address or domain pattern (e.g., spammer::evil.com or *::evil.com)")
  .action(async (pattern: string) => {
    const globalName = program.opts().name;
    await blockCommand(pattern, { name: globalName });
  });

// ---- unblock ---------------------------------------------------------------
program
  .command("unblock <pattern>")
  .description("Remove a block on an address or domain pattern")
  .action(async (pattern: string) => {
    const globalName = program.opts().name;
    await unblockCommand(pattern, { name: globalName });
  });

program.parse(process.argv);
