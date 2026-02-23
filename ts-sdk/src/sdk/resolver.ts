/**
 * Pluggable address resolver with Tier 1 relay lookup (SDK-08).
 *
 * Matches Python resolver.py: SmartResolver routes by domain format.
 */

import { UAMError } from "../protocol/index.js";
import { parseAddress } from "../protocol/address.js";
import { Tier3Resolver, type Tier3Config } from "./tier3.js";
import {
  queryUamTxt,
  parseUamTxt,
  extractPublicKey,
  resolveKeyViaHttps,
} from "./dns-verifier.js";

/**
 * Pluggable address resolver interface.
 */
export abstract class AddressResolver {
  /**
   * Resolve an agent address to its public key (base64).
   *
   * @throws {UAMError} If the address cannot be resolved.
   */
  abstract resolvePublicKey(
    address: string,
    token: string,
    relayUrl: string
  ): Promise<string>;
}

/**
 * Tier 1: resolve via relay HTTP API.
 *
 * Calls GET /api/v1/agents/{address}/public-key.
 */
export class Tier1Resolver extends AddressResolver {
  async resolvePublicKey(
    address: string,
    _token: string,
    relayUrl: string
  ): Promise<string> {
    const resp = await fetch(
      `${relayUrl}/api/v1/agents/${address}/public-key`
    );
    if (resp.status === 404) {
      throw new UAMError(`Agent not found: ${address}`);
    }
    if (!resp.ok) {
      throw new UAMError(
        `Resolver request failed: ${resp.status} ${resp.statusText}`
      );
    }
    const data = (await resp.json()) as Record<string, unknown>;
    return data["public_key"] as string;
  }
}

/**
 * Tier 2: DNS TXT record resolution (DNS-01).
 *
 * Resolution order:
 *   1. Query _uam.{domain} TXT records for v=uam1 entries
 *   2. Fallback to HTTPS .well-known/uam.json
 *   3. Throw UAMError if both fail
 */
export class Tier2Resolver extends AddressResolver {
  async resolvePublicKey(
    address: string,
    _token: string,
    _relayUrl: string
  ): Promise<string> {
    const parsed = parseAddress(address);

    // 1. Try DNS TXT at _uam.{domain}
    const txtRecords = await queryUamTxt(parsed.domain);
    for (const txt of txtRecords) {
      const tags = parseUamTxt(txt);
      if (tags["v"] === "uam1") {
        const key = extractPublicKey(tags);
        if (key) return key;
      }
    }

    // 2. Fallback to HTTPS .well-known
    const httpsKey = await resolveKeyViaHttps(parsed.agent, parsed.domain);
    if (httpsKey) return httpsKey;

    throw new UAMError(
      `Could not resolve public key for ${address} via DNS or HTTPS`
    );
  }
}

/**
 * Automatic tier-based resolver that routes by domain format (RESOLVE-01).
 *
 * Routing rules:
 *   - domain == relayDomain  -> Tier 1 (relay HTTP API lookup)
 *   - domain contains a '.'  -> Tier 2 (DNS -- stub)
 *   - domain has no dots     -> Tier 3 (on-chain namespace lookup)
 */
export class SmartResolver extends AddressResolver {
  private _relayDomain: string;
  private _tier1: Tier1Resolver;
  private _tier2: Tier2Resolver;
  private _tier3: Tier3Resolver | null;

  constructor(relayDomain: string, tier3Config?: Tier3Config) {
    super();
    this._relayDomain = relayDomain;
    this._tier1 = new Tier1Resolver();
    this._tier2 = new Tier2Resolver();
    this._tier3 = tier3Config ? new Tier3Resolver(tier3Config) : null;
  }

  async resolvePublicKey(
    address: string,
    token: string,
    relayUrl: string
  ): Promise<string> {
    const parsed = parseAddress(address);
    const domain = parsed.domain;

    if (domain === this._relayDomain) {
      return this._tier1.resolvePublicKey(address, token, relayUrl);
    }

    if (domain.includes(".")) {
      return this._tier2.resolvePublicKey(address, token, relayUrl);
    }

    if (!this._tier3) {
      throw new UAMError(
        `Tier 3 resolution requires contract config. ` +
          `Cannot resolve dot-free domain: '${domain}'`
      );
    }
    return this._tier3.resolvePublicKey(address, token, relayUrl);
  }
}

// Re-export Tier3 types for convenience
export { Tier3Resolver, type Tier3Config } from "./tier3.js";
