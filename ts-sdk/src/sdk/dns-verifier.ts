/**
 * DNS domain verification for UAM Tier 2 addresses (DNS-01, DNS-03).
 *
 * Provides TXT record parsing, HTTPS .well-known fallback resolution,
 * and helper functions for domain ownership verification.
 *
 * TXT record format (at `_uam.{domain}`):
 *
 *     v=uam1; key=ed25519:<base64-pubkey>; relay=<relay-url>
 *
 * Matches Python dns_verifier.py API surface.
 */

import { resolveTxt as dnsResolveTxt } from "node:dns/promises";

/**
 * Parse a UAM TXT record value into tag-value pairs.
 *
 * Format: `v=uam1; key=ed25519:<base64>; relay=https://...`
 *
 * Tag names are lowercased for case-insensitive matching.
 * Unknown tags are preserved (forward compatibility).
 */
export function parseUamTxt(txtValue: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const part of txtValue.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx !== -1) {
      const tag = trimmed.slice(0, eqIdx).trim().toLowerCase();
      const value = trimmed.slice(eqIdx + 1).trim();
      tags[tag] = value;
    }
  }
  return tags;
}

/**
 * Extract the base64 public key from parsed UAM TXT tags.
 *
 * Strips the `ed25519:` prefix.  Returns `null` if the key
 * tag is missing or does not have the expected prefix.
 */
export function extractPublicKey(
  tags: Record<string, string>
): string | null {
  const keyValue = tags["key"] ?? "";
  if (keyValue.startsWith("ed25519:")) {
    return keyValue.slice("ed25519:".length);
  }
  return null;
}

/**
 * Query `_uam.{domain}` for UAM TXT records.
 *
 * Returns a list of TXT record values that start with `v=uam1`.
 * Returns an empty list if no matching records are found or on any
 * DNS error.
 */
export async function queryUamTxt(
  domain: string,
  timeout?: number
): Promise<string[]> {
  // Node dns/promises does not support per-call timeout natively.
  // We use AbortController for cancellation.
  const controller = new AbortController();
  const timer =
    timeout != null
      ? setTimeout(() => controller.abort(), timeout)
      : undefined;

  try {
    const records = await dnsResolveTxt(`_uam.${domain}`);

    // Each record is an array of strings (multi-part TXT).
    // Concatenate parts and filter for v=uam1.
    const results: string[] = [];
    for (const parts of records) {
      const txtValue = parts.join("");
      if (txtValue.trim().startsWith("v=uam1")) {
        results.push(txtValue);
      }
    }
    return results;
  } catch {
    // NXDOMAIN, SERVFAIL, etc. -- return empty
    return [];
  } finally {
    if (timer != null) clearTimeout(timer);
  }
}

/**
 * Resolve an agent's public key from `.well-known/uam.json` HTTPS fallback.
 *
 * Returns the base64 public key string, or `null` if the agent is not
 * found or the request fails.
 */
export async function resolveKeyViaHttps(
  agentName: string,
  domain: string,
  timeout?: number
): Promise<string | null> {
  const url = `https://${domain}/.well-known/uam.json`;

  try {
    const resp = await fetch(url, {
      signal: AbortSignal.timeout(timeout ?? 10000),
    });
    if (!resp.ok) return null;

    const data = (await resp.json()) as Record<string, unknown>;
    if (data["v"] !== "uam1") return null;

    const agents = (data["agents"] ?? {}) as Record<
      string,
      Record<string, unknown>
    >;
    const entry = agents[agentName];
    if (!entry) return null;

    let keyValue = (entry["key"] as string) ?? "";
    if (keyValue.startsWith("ed25519:")) {
      keyValue = keyValue.slice("ed25519:".length);
    }
    return keyValue || null;
  } catch {
    return null;
  }
}

/**
 * Generate the TXT record value an agent should publish at `_uam.{domain}`.
 *
 * Returns a formatted string like:
 * `v=uam1; key=ed25519:<publicKey>; relay=<relayUrl>`
 */
export function generateTxtRecord(
  publicKey: string,
  relayUrl: string
): string {
  return `v=uam1; key=ed25519:${publicKey}; relay=${relayUrl}`;
}
