/**
 * When to believe the relay about mail that waited in storage.
 *
 * A signed timestamp cannot tell "signed, stored, delivered later" from an
 * old envelope sent again. The relay's relay_meta stamp can, so long as the
 * recipient's own relay wrote it.
 *
 * Matches the Python SDK's freshness.py.
 */

import { MAX_ENVELOPE_AGE } from "../protocol/types.js";

/** Listed in GET /api/v1/versions by relays that write relay_meta. */
export const RELAY_META_FEATURE = "relay_meta";

/** How long stored mail stays deliverable, in seconds. */
export const STORED_MAIL_MAX_AGE = 7 * 86400;

// A full ISO 8601 time with a zone. Date.parse alone also takes loose formats
// and reads a time with no zone as local.
const ISO_TIME =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/**
 * True if `raw` carries a stamp showing it was stored soon after signing.
 *
 * This only reads the stamp. The caller must also know that the relay writes
 * these stamps, or a sender could have written this one.
 *
 * @param signedAt - The envelope's signed time, in ms since the epoch
 * @param now - The current time, in ms since the epoch
 */
export function relayVouches(
  raw: Record<string, unknown>,
  signedAt: number,
  now: number,
  relayDomain: string
): boolean {
  const meta = raw["relay_meta"];
  if (typeof meta !== "object" || meta === null || Array.isArray(meta)) {
    return false;
  }
  const stamp = meta as Record<string, unknown>;
  if (stamp["v"] !== 1 || stamp["relay"] !== relayDomain) return false;
  if (stamp["stored"] !== true) return false;

  const received = stamp["received_at"];
  if (typeof received !== "string" || !ISO_TIME.test(received)) return false;
  const receivedAt = Date.parse(received);
  if (Number.isNaN(receivedAt)) return false;

  const window = MAX_ENVELOPE_AGE * 1000;
  const age = now - signedAt;
  return (
    Math.abs(receivedAt - signedAt) <= window &&
    age >= 0 &&
    age <= STORED_MAIL_MAX_AGE * 1000 + window
  );
}
