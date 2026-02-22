/**
 * UAM contact cards -- self-signed agent identity documents.
 *
 * A contact card advertises an agent's address, public key, relay endpoint,
 * and optional metadata. The card is signed by the agent's own signing key
 * so that any recipient can verify authenticity using the embedded public key.
 */

import { parseAddress } from "./address.js";
import {
  canonicalize,
  deserializeVerifyKey,
  publicKeyFingerprint,
  serializeVerifyKey,
  signMessage,
  verifySignature,
} from "./crypto.js";
import { InvalidContactCardError } from "./errors.js";
import { UAM_VERSION } from "./types.js";

/**
 * A self-signed agent identity card.
 */
export interface ContactCard {
  readonly version: string;
  readonly address: string;
  readonly displayName: string;
  readonly description?: string;
  readonly system?: string;
  readonly connectionEndpoint?: string;
  readonly relay: string;
  readonly publicKey: string;
  readonly signature: string;
  readonly verifiedDomain?: string;
  readonly payloadFormats?: string[];
  readonly fingerprint?: string;
  /** CARD-04: Multi-relay support. Outside signature scope. */
  readonly relays?: string[];
}

/**
 * Build the dict used for signature computation.
 *
 * Includes all fields except signature, payload_formats, fingerprint, relays.
 * Excludes undefined-valued optional fields.
 */
function buildSignableDict(card: ContactCard): Record<string, unknown> {
  const d: Record<string, unknown> = {
    version: card.version,
    address: card.address,
    display_name: card.displayName,
    relay: card.relay,
    public_key: card.publicKey,
  };
  if (card.description !== undefined) d["description"] = card.description;
  if (card.system !== undefined) d["system"] = card.system;
  if (card.connectionEndpoint !== undefined) {
    d["connection_endpoint"] = card.connectionEndpoint;
  }
  if (card.verifiedDomain !== undefined) {
    d["verified_domain"] = card.verifiedDomain;
  }
  return d;
}

/**
 * Serialize a contact card to a plain dict.
 *
 * Uses snake_case names on the wire, excludes undefined-valued optional fields.
 */
export function contactCardToDict(
  card: ContactCard
): Record<string, unknown> {
  const d = buildSignableDict(card);
  d["signature"] = card.signature;
  if (card.payloadFormats !== undefined) {
    d["payload_formats"] = card.payloadFormats;
  }
  if (card.fingerprint !== undefined) {
    d["fingerprint"] = card.fingerprint;
  }
  if (card.relays !== undefined) {
    d["relays"] = card.relays;
  }
  return d;
}

/**
 * Deserialize a contact card from a dict.
 *
 * When verify is true (the default), the card's signature is checked
 * immediately after deserialization.
 *
 * @throws {InvalidContactCardError} If required fields are missing.
 * @throws {SignatureVerificationError} If verify is true and the signature is invalid.
 */
export function contactCardFromDict(
  d: Record<string, unknown>,
  options?: { verify?: boolean }
): ContactCard {
  const verify = options?.verify ?? true;

  const required = new Set([
    "version",
    "address",
    "display_name",
    "relay",
    "public_key",
    "signature",
  ]);
  const keys = new Set(Object.keys(d));
  const missing: string[] = [];
  for (const field of required) {
    if (!keys.has(field)) missing.push(field);
  }
  if (missing.length > 0) {
    missing.sort();
    throw new InvalidContactCardError(
      `Missing required fields: ${JSON.stringify(missing)}`
    );
  }

  const card: ContactCard = Object.freeze({
    version: d["version"] as string,
    address: d["address"] as string,
    displayName: d["display_name"] as string,
    description: d["description"] as string | undefined,
    system: d["system"] as string | undefined,
    connectionEndpoint: d["connection_endpoint"] as string | undefined,
    relay: d["relay"] as string,
    publicKey: d["public_key"] as string,
    signature: d["signature"] as string,
    verifiedDomain: d["verified_domain"] as string | undefined,
    payloadFormats: d["payload_formats"] as string[] | undefined,
    fingerprint: d["fingerprint"] as string | undefined,
    relays: d["relays"] as string[] | undefined,
  });

  if (verify) {
    verifyContactCard(card);
  }

  return card;
}

/**
 * Create a self-signed contact card.
 *
 * payloadFormats defaults to ["text/plain", "text/markdown"] when not specified.
 * The fingerprint is always auto-computed as the SHA-256 hex digest of the
 * Ed25519 public key bytes.
 *
 * @throws {InvalidAddressError} If address is not valid.
 */
export async function createContactCard(
  address: string,
  displayName: string,
  relay: string,
  signingKey: Uint8Array,
  options?: {
    description?: string;
    system?: string;
    connectionEndpoint?: string;
    verifiedDomain?: string;
    payloadFormats?: string[];
    relays?: string[];
  }
): Promise<ContactCard> {
  // Validate address
  parseAddress(address);

  // Derive public key and fingerprint
  // The verify key is the last 32 bytes of the 64-byte signing key
  const verifyKey = signingKey.slice(32);
  const pubKeyB64 = serializeVerifyKey(verifyKey);
  const fp = publicKeyFingerprint(verifyKey);

  // Default payload formats
  const payloadFormats = options?.payloadFormats ?? [
    "text/plain",
    "text/markdown",
  ];

  // Build temporary card without signature
  const tempCard: ContactCard = {
    version: UAM_VERSION,
    address,
    displayName,
    description: options?.description,
    system: options?.system,
    connectionEndpoint: options?.connectionEndpoint,
    relay,
    publicKey: pubKeyB64,
    signature: "",
    verifiedDomain: options?.verifiedDomain,
    payloadFormats,
    fingerprint: fp,
    relays: options?.relays,
  };

  // Sign (payload_formats, fingerprint, relays are NOT in signable dict)
  const signable = buildSignableDict(tempCard);
  const signature = signMessage(canonicalize(signable), signingKey);

  // Return final card
  return Object.freeze({
    version: UAM_VERSION,
    address,
    displayName,
    description: options?.description,
    system: options?.system,
    connectionEndpoint: options?.connectionEndpoint,
    relay,
    publicKey: pubKeyB64,
    signature,
    verifiedDomain: options?.verifiedDomain,
    payloadFormats,
    fingerprint: fp,
    relays: options?.relays,
  });
}

/**
 * Verify a contact card's signature using its embedded public key.
 *
 * @throws {InvalidContactCardError} If the address is invalid.
 * @throws {SignatureVerificationError} If the signature is invalid.
 */
export function verifyContactCard(card: ContactCard): void {
  // Validate address format
  try {
    parseAddress(card.address);
  } catch (err) {
    throw new InvalidContactCardError(
      `Invalid address in contact card: ${err instanceof Error ? err.message : String(err)}`
    );
  }

  // Deserialize the embedded public key
  const vk = deserializeVerifyKey(card.publicKey);

  // Verify signature
  const signable = buildSignableDict(card);
  verifySignature(canonicalize(signable), card.signature, vk);
}
