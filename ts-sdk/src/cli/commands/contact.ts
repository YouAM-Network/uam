/**
 * uam contact -- Contact management subcommands (fingerprint, verify, remove).
 *
 * Matches Python CLI contact commands (TOFU-04).
 */

import { SDKConfig } from "../../sdk/config.js";
import { ContactBook } from "../../sdk/contact-book.js";
import {
  deserializeVerifyKey,
  publicKeyFingerprint,
} from "../../protocol/index.js";
import { findAgentName, cliError } from "../helpers.js";

/**
 * uam contact fingerprint <address>
 *
 * Display the fingerprint for a known contact's public key.
 * Offline operation -- no agent.connect() needed.
 */
export async function contactFingerprintCommand(
  address: string,
  options: { name?: string }
): Promise<void> {
  const agentName = options.name ?? findAgentName();
  const cfg = new SDKConfig({ name: agentName ?? "_probe" });
  const book = new ContactBook(cfg.dataDir);

  try {
    book.open();
    const pkStr = book.getPublicKey(address);
    book.close();

    if (pkStr === null) {
      cliError(`Contact not found: ${address}`);
    }

    const vk = deserializeVerifyKey(pkStr);
    const fp = publicKeyFingerprint(vk);
    // Format as 4-char groups
    const shortFp = fp.slice(0, 16);

    console.log(`Address:     ${address}`);
    console.log(`Fingerprint: ${shortFp}`);
    console.log(`Full:        ${fp}`);
  } catch (err) {
    if (err instanceof Error && err.message.startsWith("Contact not found")) {
      throw err;
    }
    cliError(`Error: ${err instanceof Error ? err.message : err}`);
  }
}

/**
 * uam contact verify <address>
 *
 * Manually verify a contact, upgrading their trust state to "verified".
 * Uses --yes flag to skip confirmation prompt.
 */
export async function contactVerifyCommand(
  address: string,
  options: { name?: string; yes?: boolean }
): Promise<void> {
  const agentName = options.name ?? findAgentName();
  const cfg = new SDKConfig({ name: agentName ?? "_probe" });
  const book = new ContactBook(cfg.dataDir);

  try {
    book.open();
    const pkStr = book.getPublicKey(address);

    if (pkStr === null) {
      book.close();
      cliError(`Contact not found: ${address}`);
    }

    // Show fingerprint for verification
    const vk = deserializeVerifyKey(pkStr);
    const fp = publicKeyFingerprint(vk);
    console.log(`Fingerprint for ${address}: ${fp.slice(0, 16)}`);

    // Upgrade trust state to verified
    book.addContact(address, pkStr, {
      trustState: "verified",
      trustSource: "manual-verify",
    });
    book.close();

    console.log(`Contact ${address} verified. Trust state: verified`);
  } catch (err) {
    cliError(`Error: ${err instanceof Error ? err.message : err}`);
  }
}

/**
 * uam contact remove <address>
 *
 * Remove a contact from the contact book.
 */
export async function contactRemoveCommand(
  address: string,
  options: { name?: string }
): Promise<void> {
  const agentName = options.name ?? findAgentName();
  const cfg = new SDKConfig({ name: agentName ?? "_probe" });
  const book = new ContactBook(cfg.dataDir);

  try {
    book.open();
    const removed = book.removeContact(address);
    book.close();

    if (!removed) {
      cliError(`Contact not found: ${address}`);
    }

    console.log(
      `Contact ${address} removed. Future messages will re-resolve the public key.`
    );
  } catch (err) {
    cliError(`Error: ${err instanceof Error ? err.message : err}`);
  }
}
