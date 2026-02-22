/**
 * Core types, constants, and utility functions for UAM protocol.
 */

/** Protocol version. */
export const UAM_VERSION = "0.1";

/** Maximum envelope size in bytes (64 KB). */
export const MAX_ENVELOPE_SIZE = 65536;

/** All UAM message types. */
export enum MessageType {
  MESSAGE = "message",
  HANDSHAKE_REQUEST = "handshake.request",
  HANDSHAKE_ACCEPT = "handshake.accept",
  HANDSHAKE_DENY = "handshake.deny",
  RECEIPT_DELIVERED = "receipt.delivered",
  RECEIPT_READ = "receipt.read",
  RECEIPT_FAILED = "receipt.failed",
  SESSION_REQUEST = "session.request",
  SESSION_ACCEPT = "session.accept",
  SESSION_DECLINE = "session.decline",
  SESSION_END = "session.end",
}

/**
 * URL-safe base64 encode, stripping padding.
 */
export function b64Encode(data: Uint8Array): string {
  return Buffer.from(data).toString("base64url");
}

/**
 * URL-safe base64 decode, tolerating missing padding.
 */
export function b64Decode(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

/**
 * Return a canonical UTC timestamp: YYYY-MM-DDTHH:MM:SS.mmmZ
 */
export function utcTimestamp(): string {
  return new Date().toISOString();
}
