/**
 * UAM message envelope -- creation, signing, verification, wire format.
 *
 * An envelope wraps every UAM message with cryptographic signatures and
 * encrypted payloads, using fromAddress/toAddress naming internally
 * ("from"/"to" on the wire).
 */

import { randomUUID } from "node:crypto";

import { parseAddress } from "./address.js";
import {
  canonicalize,
  encryptPayload,
  encryptPayloadAnonymous,
  generateNonce,
  signMessage,
  verifySignature,
} from "./crypto.js";
import { EnvelopeTooLargeError, InvalidEnvelopeError } from "./errors.js";
import { MAX_ENVELOPE_SIZE, MessageType, UAM_VERSION, utcTimestamp } from "./types.js";

/**
 * Required wire-format field names (using "from"/"to").
 */
const REQUIRED_WIRE_FIELDS = new Set([
  "uam_version",
  "message_id",
  "from",
  "to",
  "timestamp",
  "type",
  "nonce",
  "payload",
  "signature",
]);

/**
 * A signed, encrypted UAM message envelope.
 */
export interface MessageEnvelope {
  // Required fields
  readonly uamVersion: string;
  readonly messageId: string;
  readonly fromAddress: string;
  readonly toAddress: string;
  readonly timestamp: string;
  readonly type: string;
  readonly nonce: string;
  readonly payload: string;
  readonly signature: string;

  // Optional fields
  readonly threadId?: string;
  readonly replyTo?: string;
  readonly expires?: string;
  readonly mediaType?: string;
  readonly metadata?: Record<string, unknown>;

  // v1.1 fields -- NOT in signature scope
  readonly attachments?: Array<Record<string, unknown>>;
}

/**
 * Build the dict used for signature computation.
 *
 * Maps TypeScript names to wire names (fromAddress -> "from").
 * Excludes signature and any optional field that is undefined.
 */
function buildSignableDict(
  envelope: MessageEnvelope
): Record<string, unknown> {
  const d: Record<string, unknown> = {
    uam_version: envelope.uamVersion,
    message_id: envelope.messageId,
    from: envelope.fromAddress,
    to: envelope.toAddress,
    timestamp: envelope.timestamp,
    type: envelope.type,
    nonce: envelope.nonce,
    payload: envelope.payload,
  };
  if (envelope.threadId !== undefined) d["thread_id"] = envelope.threadId;
  if (envelope.replyTo !== undefined) d["reply_to"] = envelope.replyTo;
  if (envelope.expires !== undefined) d["expires"] = envelope.expires;
  if (envelope.mediaType !== undefined) d["media_type"] = envelope.mediaType;
  if (envelope.metadata !== undefined) d["metadata"] = envelope.metadata;
  return d;
}

/**
 * Convert an envelope to a wire-format dict.
 *
 * Maps fromAddress -> "from" and toAddress -> "to".
 * Excludes undefined-valued optional fields.
 */
export function toWireDict(
  envelope: MessageEnvelope
): Record<string, unknown> {
  const d = buildSignableDict(envelope);
  d["signature"] = envelope.signature;
  if (envelope.attachments !== undefined) {
    d["attachments"] = envelope.attachments;
  }
  return d;
}

/**
 * Restore an envelope from a wire-format dict.
 *
 * @throws {InvalidEnvelopeError} If any required field is missing.
 */
export function fromWireDict(
  d: Record<string, unknown>
): MessageEnvelope {
  const keys = new Set(Object.keys(d));
  const missing: string[] = [];
  for (const field of REQUIRED_WIRE_FIELDS) {
    if (!keys.has(field)) missing.push(field);
  }
  if (missing.length > 0) {
    missing.sort();
    throw new InvalidEnvelopeError(
      `Missing required fields: ${JSON.stringify(missing)}`
    );
  }

  return Object.freeze({
    uamVersion: d["uam_version"] as string,
    messageId: d["message_id"] as string,
    fromAddress: d["from"] as string,
    toAddress: d["to"] as string,
    timestamp: d["timestamp"] as string,
    type: d["type"] as string,
    nonce: d["nonce"] as string,
    payload: d["payload"] as string,
    signature: d["signature"] as string,
    threadId: d["thread_id"] as string | undefined,
    replyTo: d["reply_to"] as string | undefined,
    expires: d["expires"] as string | undefined,
    mediaType: d["media_type"] as string | undefined,
    metadata: d["metadata"] as Record<string, unknown> | undefined,
    attachments: d["attachments"] as Array<Record<string, unknown>> | undefined,
  });
}

/**
 * Check that the serialized envelope does not exceed MAX_ENVELOPE_SIZE.
 *
 * @throws {EnvelopeTooLargeError} If the wire JSON exceeds 64 KB.
 */
export function validateEnvelopeSize(envelope: MessageEnvelope): void {
  const wire = toWireDict(envelope);
  const json = JSON.stringify(wire);
  const size = new TextEncoder().encode(json).length;
  if (size > MAX_ENVELOPE_SIZE) {
    throw new EnvelopeTooLargeError(
      `Envelope size ${size} bytes exceeds maximum ${MAX_ENVELOPE_SIZE} bytes`
    );
  }
}

/**
 * Create a signed, encrypted message envelope.
 *
 * @throws {InvalidAddressError} If either address is invalid.
 * @throws {EnvelopeTooLargeError} If the serialized envelope exceeds 64 KB.
 */
export async function createEnvelope(
  fromAddress: string,
  toAddress: string,
  messageType: MessageType | string,
  payloadPlaintext: Uint8Array,
  signingKey: Uint8Array,
  recipientVerifyKey: Uint8Array,
  options?: {
    threadId?: string;
    replyTo?: string;
    expires?: string;
    mediaType?: string;
    metadata?: Record<string, unknown>;
    attachments?: Array<Record<string, unknown>>;
  }
): Promise<MessageEnvelope> {
  // Normalize message type
  const typeValue =
    typeof messageType === "string"
      ? messageType
      : (messageType as string);

  // Step 1: Validate addresses
  parseAddress(fromAddress);
  parseAddress(toAddress);

  // Step 2: Generate identifiers
  const messageId = randomUUID();
  const nonce = generateNonce();
  const timestamp = utcTimestamp();

  // Step 3: Encrypt payload
  let encryptedPayload: string;
  if (typeValue === MessageType.HANDSHAKE_REQUEST) {
    encryptedPayload = encryptPayloadAnonymous(payloadPlaintext, recipientVerifyKey);
  } else {
    encryptedPayload = encryptPayload(
      payloadPlaintext,
      signingKey,
      recipientVerifyKey
    );
  }

  // Build temporary envelope without signature
  const tempEnvelope: MessageEnvelope = {
    uamVersion: UAM_VERSION,
    messageId,
    fromAddress,
    toAddress,
    timestamp,
    type: typeValue,
    nonce,
    payload: encryptedPayload,
    signature: "",
    threadId: options?.threadId,
    replyTo: options?.replyTo,
    expires: options?.expires,
    mediaType: options?.mediaType,
    metadata: options?.metadata,
    attachments: options?.attachments,
  };

  // Step 4: Build signable dict, canonicalize, and sign
  const signable = buildSignableDict(tempEnvelope);
  const signature = signMessage(canonicalize(signable), signingKey);

  // Step 5: Build final envelope
  const finalEnvelope: MessageEnvelope = Object.freeze({
    uamVersion: UAM_VERSION,
    messageId,
    fromAddress,
    toAddress,
    timestamp,
    type: typeValue,
    nonce,
    payload: encryptedPayload,
    signature,
    threadId: options?.threadId,
    replyTo: options?.replyTo,
    expires: options?.expires,
    mediaType: options?.mediaType,
    metadata: options?.metadata,
    attachments: options?.attachments,
  });

  // Step 6: Validate size
  validateEnvelopeSize(finalEnvelope);

  return finalEnvelope;
}

/**
 * Verify the cryptographic signature on an envelope.
 *
 * @throws {SignatureVerificationError} If the signature is invalid.
 */
export function verifyEnvelope(
  envelope: MessageEnvelope,
  senderVerifyKey: Uint8Array
): void {
  const signable = buildSignableDict(envelope);
  verifySignature(canonicalize(signable), envelope.signature, senderVerifyKey);
}
