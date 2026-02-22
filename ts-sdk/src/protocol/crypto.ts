/**
 * Cryptographic primitives for UAM protocol.
 *
 * Wraps libsodium-wrappers for Ed25519 signing, Curve25519 key exchange,
 * NaCl Box (authenticated encryption), and NaCl SealedBox (anonymous encryption).
 *
 * This module never hand-rolls crypto -- every operation delegates to libsodium.
 */

import sodium from "libsodium-wrappers";
import { createHash } from "node:crypto";

import {
  DecryptionError,
  EncryptionError,
  SignatureVerificationError,
} from "./errors.js";
import { b64Decode, b64Encode } from "./types.js";

// ---------------------------------------------------------------------------
// Sodium initialization
// ---------------------------------------------------------------------------

/**
 * Promise that resolves when libsodium is ready.
 * Callers must await this before first use of any crypto function.
 */
export const sodiumReady: Promise<void> = sodium.ready;

// ---------------------------------------------------------------------------
// Key type aliases
// ---------------------------------------------------------------------------

/** 64-byte Ed25519 secret key (seed + public). */
export type SigningKey = Uint8Array;

/** 32-byte Ed25519 public key. */
export type VerifyKey = Uint8Array;

/** 32-byte seed. */
export type Seed = Uint8Array;

// ---------------------------------------------------------------------------
// Key generation and serialization
// ---------------------------------------------------------------------------

export interface Keypair {
  signingKey: Uint8Array;
  verifyKey: Uint8Array;
  seed: Uint8Array;
}

/**
 * Generate an Ed25519 keypair.
 */
export function generateKeypair(): Keypair {
  const seed = sodium.randombytes_buf(32);
  const kp = sodium.crypto_sign_seed_keypair(seed);
  return {
    signingKey: kp.privateKey,
    verifyKey: kp.publicKey,
    seed,
  };
}

/**
 * Serialize a signing key to URL-safe base64 (32-byte seed).
 *
 * Matches Python: PyNaCl's SigningKey.encode() returns the 32-byte seed.
 */
export function serializeSigningKey(seed: Uint8Array): string {
  return b64Encode(seed);
}

/**
 * Restore a signing key from its base64-encoded seed.
 */
export function deserializeSigningKey(s: string): Keypair {
  const seed = b64Decode(s);
  const kp = sodium.crypto_sign_seed_keypair(seed);
  return {
    signingKey: kp.privateKey,
    verifyKey: kp.publicKey,
    seed,
  };
}

/**
 * Serialize a verify (public) key to URL-safe base64.
 */
export function serializeVerifyKey(key: Uint8Array): string {
  return b64Encode(key);
}

/**
 * Restore a verify key from its base64 encoding.
 */
export function deserializeVerifyKey(s: string): Uint8Array {
  return b64Decode(s);
}

/**
 * Return the SHA-256 hex digest of the verify key bytes.
 *
 * This 64-character string serves as the agent's identity fingerprint.
 */
export function publicKeyFingerprint(verifyKey: Uint8Array): string {
  return createHash("sha256").update(Buffer.from(verifyKey)).digest("hex");
}

// ---------------------------------------------------------------------------
// Canonical JSON
// ---------------------------------------------------------------------------

/**
 * Recursively sort all object keys and produce compact JSON.
 *
 * Matches Python: json.dumps(data, sort_keys=True, separators=(',',':'), ensure_ascii=True)
 */
function sortedStringify(value: unknown): string {
  if (value === null || value === undefined) {
    return "null";
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (Array.isArray(value)) {
    const items = value.map((v) => sortedStringify(v));
    return "[" + items.join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    const pairs = keys.map((k) => JSON.stringify(k) + ":" + sortedStringify(obj[k]));
    return "{" + pairs.join(",") + "}";
  }
  return String(value);
}

/**
 * Produce deterministic JSON bytes for signing.
 *
 * - Excludes the "signature" key.
 * - Excludes keys whose value is null or undefined.
 * - Sorts keys, uses compact separators, ensures ASCII encoding.
 */
export function canonicalize(data: Record<string, unknown>): Uint8Array {
  const filtered: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(data)) {
    if (k !== "signature" && v !== null && v !== undefined) {
      filtered[k] = v;
    }
  }
  const json = sortedStringify(filtered);
  return new TextEncoder().encode(json);
}

// ---------------------------------------------------------------------------
// Signing and verification
// ---------------------------------------------------------------------------

/**
 * Sign data with the Ed25519 signing key.
 *
 * @returns The 64-byte signature as a URL-safe base64 string.
 */
export function signMessage(data: Uint8Array, signingKey: Uint8Array): string {
  const signature = sodium.crypto_sign_detached(data, signingKey);
  return b64Encode(signature);
}

/**
 * Verify an Ed25519 signature.
 *
 * @throws {SignatureVerificationError} If the signature is invalid.
 */
export function verifySignature(
  data: Uint8Array,
  signatureB64: string,
  verifyKey: Uint8Array
): void {
  try {
    const sigBytes = b64Decode(signatureB64);
    const valid = sodium.crypto_sign_verify_detached(sigBytes, data, verifyKey);
    if (!valid) {
      throw new SignatureVerificationError("Signature verification failed");
    }
  } catch (err) {
    if (err instanceof SignatureVerificationError) {
      throw err;
    }
    throw new SignatureVerificationError(
      err instanceof Error ? err.message : String(err)
    );
  }
}

// ---------------------------------------------------------------------------
// Nonce generation
// ---------------------------------------------------------------------------

/**
 * Generate 24 cryptographically random bytes, returned as base64.
 */
export function generateNonce(): string {
  return b64Encode(sodium.randombytes_buf(24));
}

// ---------------------------------------------------------------------------
// NaCl Box encryption (authenticated, both parties known)
// ---------------------------------------------------------------------------

/**
 * Encrypt plaintext using NaCl Box (authenticated encryption).
 *
 * Both parties are known; the sender signs implicitly via key exchange.
 * Format: nonce (24 bytes) || ciphertext, matching PyNaCl Box.encrypt() output.
 *
 * @returns Base64-encoded ciphertext (nonce prepended).
 * @throws {EncryptionError} On any libsodium error.
 */
export function encryptPayload(
  plaintext: Uint8Array,
  senderSigningKey: Uint8Array,
  recipientVerifyKey: Uint8Array
): string {
  try {
    const senderCurve = sodium.crypto_sign_ed25519_sk_to_curve25519(senderSigningKey);
    const recipientCurve = sodium.crypto_sign_ed25519_pk_to_curve25519(recipientVerifyKey);
    const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    const encrypted = sodium.crypto_box_easy(plaintext, nonce, recipientCurve, senderCurve);
    // Concatenate nonce || ciphertext (matching PyNaCl format)
    const combined = new Uint8Array(nonce.length + encrypted.length);
    combined.set(nonce, 0);
    combined.set(encrypted, nonce.length);
    return b64Encode(combined);
  } catch (err) {
    if (err instanceof EncryptionError) throw err;
    throw new EncryptionError(err instanceof Error ? err.message : String(err));
  }
}

/**
 * Decrypt NaCl Box ciphertext.
 *
 * @returns The original plaintext bytes.
 * @throws {DecryptionError} On any libsodium error (wrong keys, tampered data).
 */
export function decryptPayload(
  ciphertextB64: string,
  recipientSigningKey: Uint8Array,
  senderVerifyKey: Uint8Array
): Uint8Array {
  try {
    const combined = b64Decode(ciphertextB64);
    const nonce = combined.slice(0, sodium.crypto_box_NONCEBYTES);
    const ciphertext = combined.slice(sodium.crypto_box_NONCEBYTES);
    const recipientCurve = sodium.crypto_sign_ed25519_sk_to_curve25519(recipientSigningKey);
    const senderCurve = sodium.crypto_sign_ed25519_pk_to_curve25519(senderVerifyKey);
    return sodium.crypto_box_open_easy(ciphertext, nonce, senderCurve, recipientCurve);
  } catch (err) {
    if (err instanceof DecryptionError) throw err;
    throw new DecryptionError(err instanceof Error ? err.message : String(err));
  }
}

// ---------------------------------------------------------------------------
// NaCl SealedBox encryption (anonymous sender)
// ---------------------------------------------------------------------------

/**
 * Encrypt plaintext using NaCl SealedBox (anonymous sender).
 *
 * Only the recipient's public key is required; no sender authentication.
 *
 * @returns Base64-encoded ciphertext.
 */
export function encryptPayloadAnonymous(
  plaintext: Uint8Array,
  recipientVerifyKey: Uint8Array
): string {
  const recipientCurve = sodium.crypto_sign_ed25519_pk_to_curve25519(recipientVerifyKey);
  const ciphertext = sodium.crypto_box_seal(plaintext, recipientCurve);
  return b64Encode(ciphertext);
}

/**
 * Decrypt NaCl SealedBox ciphertext.
 *
 * @returns The original plaintext bytes.
 * @throws {DecryptionError} On any libsodium error.
 */
export function decryptPayloadAnonymous(
  ciphertextB64: string,
  recipientSigningKey: Uint8Array
): Uint8Array {
  try {
    const ciphertext = b64Decode(ciphertextB64);
    const recipientCurveSk = sodium.crypto_sign_ed25519_sk_to_curve25519(recipientSigningKey);
    // Extract the public key from the signing key (last 32 bytes of the 64-byte Ed25519 secret key)
    const recipientVerifyKey = recipientSigningKey.slice(32);
    const recipientCurvePk = sodium.crypto_sign_ed25519_pk_to_curve25519(recipientVerifyKey);
    return sodium.crypto_box_seal_open(ciphertext, recipientCurvePk, recipientCurveSk);
  } catch (err) {
    if (err instanceof DecryptionError) throw err;
    throw new DecryptionError(err instanceof Error ? err.message : String(err));
  }
}
