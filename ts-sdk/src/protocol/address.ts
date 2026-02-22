/**
 * UAM address parsing and validation.
 *
 * A UAM address has the form `agent::domain` (e.g. `alice::youam.network`).
 */

import { InvalidAddressError } from "./errors.js";

/**
 * A parsed UAM address (always lowercase).
 */
export interface Address {
  readonly agent: string;
  readonly domain: string;
  readonly full: string;
}

// Agent: 1-64 chars, lowercase alphanumeric + hyphen + underscore.
// Cannot start or end with hyphen.
// Domain: standard DNS-style, 1-255 chars.
const ADDRESS_RE =
  /^(?<agent>[a-z0-9][a-z0-9_-]{0,62}[a-z0-9]|[a-z0-9])::(?<domain>[a-z0-9](?:[a-z0-9.-]{0,253}[a-z0-9])?)$/;

const MAX_AGENT_LEN = 64;
const MAX_ADDRESS_LEN = 128;

/**
 * Parse and validate a UAM address string.
 *
 * Strips whitespace, lowercases, and validates format.
 * Enforces max lengths: agent <= 64 chars, full address <= 128 chars.
 *
 * @throws {InvalidAddressError} If `raw` is not a valid `agent::domain` address.
 */
export function parseAddress(raw: string): Address {
  const normalized = raw.trim().toLowerCase();
  if (normalized.length > MAX_ADDRESS_LEN) {
    throw new InvalidAddressError(
      `Address exceeds ${MAX_ADDRESS_LEN} characters: ${JSON.stringify(raw)}`
    );
  }
  const m = ADDRESS_RE.exec(normalized);
  if (!m || !m.groups) {
    throw new InvalidAddressError(
      `Invalid UAM address: ${JSON.stringify(raw)}`
    );
  }
  const agent = m.groups.agent;
  if (agent.length > MAX_AGENT_LEN) {
    throw new InvalidAddressError(
      `Agent name exceeds ${MAX_AGENT_LEN} characters: ${JSON.stringify(raw)}`
    );
  }
  return {
    agent,
    domain: m.groups.domain,
    get full() {
      return `${this.agent}::${this.domain}`;
    },
  };
}
