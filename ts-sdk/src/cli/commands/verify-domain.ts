/**
 * uam verify-domain <domain> -- Verify domain ownership for Tier 2 DNS-verified status.
 *
 * Matches Python CLI verify-domain command (DNS-05).
 */

import { Agent } from "../../sdk/agent.js";
import { generateTxtRecord } from "../../sdk/dns-verifier.js";
import { findAgentName, cliError } from "../helpers.js";

export async function verifyDomainCommand(
  domain: string,
  options: {
    name?: string;
    timeout?: number;
    pollInterval?: number;
  }
): Promise<void> {
  const agentName = options.name ?? findAgentName();
  if (!agentName) {
    cliError("No agent initialized. Run `uam init` first.");
  }

  const timeout = options.timeout ?? 300;
  const pollInterval = options.pollInterval ?? 10;

  try {
    const agent = new Agent(agentName);
    await agent.connect();

    const pubkey = agent.publicKey;
    const relayUrl = agent._config.relayUrl;
    const txtValue = generateTxtRecord(pubkey, relayUrl);

    console.log(`Add this DNS TXT record to verify ${domain}:`);
    console.log();
    console.log(`  Host:  _uam.${domain}`);
    console.log(`  Type:  TXT`);
    console.log(`  Value: ${txtValue}`);
    console.log();
    console.log(`Or serve this HTTPS fallback:`);
    console.log();
    console.log(`  URL: https://${domain}/.well-known/uam.json`);
    console.log();
    console.log(`See documentation for .well-known/uam.json format.`);
    console.log();
    console.log("Polling for verification...");

    const verified = await agent.verifyDomain(domain, {
      timeout: timeout * 1000,
      pollInterval: pollInterval * 1000,
    });
    await agent.close();

    if (verified) {
      console.log(
        `Verified! ${agent.address} is now Tier 2 via ${domain}.`
      );
    } else {
      console.log(
        `Verification timed out after ${timeout}s. ` +
          `Check your DNS records and try again.`
      );
    }
  } catch (err) {
    cliError(`Error: ${err instanceof Error ? err.message : err}`);
  }
}
