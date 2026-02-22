/**
 * Cross-language crypto test vectors.
 *
 * Loads docs/protocol/test-vectors.json and verifies byte-identical
 * output with the Python implementation for all deterministic operations.
 */

import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import sodium from "libsodium-wrappers";

import {
  sodiumReady,
  canonicalize,
  signMessage,
  verifySignature,
  publicKeyFingerprint,
  encryptPayload,
  decryptPayload,
  encryptPayloadAnonymous,
  decryptPayloadAnonymous,
} from "../../src/protocol/crypto.js";
import { b64Encode, b64Decode } from "../../src/protocol/types.js";

// Load test vectors
const vectorsPath = resolve(__dirname, "../../../docs/protocol/test-vectors.json");
const vectors = JSON.parse(readFileSync(vectorsPath, "utf-8"));

function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

beforeAll(async () => {
  await sodiumReady;
});

describe("canonicalize vectors", () => {
  for (const v of vectors.vectors.canonicalize) {
    it(`${v.id}: ${v.description}`, () => {
      const result = canonicalize(v.input);
      const resultHex = bytesToHex(result);
      expect(resultHex).toBe(v.expected_bytes_hex);
      // Also verify the string representation
      const resultStr = new TextDecoder().decode(result);
      expect(resultStr).toBe(v.expected_string);
    });
  }
});

describe("key derivation vectors", () => {
  for (const v of vectors.vectors.key_derivation) {
    it(`${v.id}: ${v.description}`, () => {
      const seed = hexToBytes(v.seed_hex);
      const kp = sodium.crypto_sign_seed_keypair(seed);

      // Verify key matches
      const verifyKeyB64 = b64Encode(kp.publicKey);
      expect(verifyKeyB64).toBe(v.verify_key_b64);

      // Verify hex
      const verifyKeyHex = bytesToHex(kp.publicKey);
      expect(verifyKeyHex).toBe(v.verify_key_hex);

      // Verify fingerprint
      const fp = publicKeyFingerprint(kp.publicKey);
      expect(fp).toBe(v.fingerprint);
    });
  }
});

describe("sign/verify vectors", () => {
  for (const v of vectors.vectors.sign_verify) {
    it(`${v.id}: ${v.description}`, () => {
      const seed = hexToBytes(v.seed_hex);
      const kp = sodium.crypto_sign_seed_keypair(seed);
      const message = hexToBytes(v.message_hex);

      // Verify public key matches
      const pubB64 = b64Encode(kp.publicKey);
      expect(pubB64).toBe(v.public_key_b64);

      // Sign and verify byte-identical signature
      const sig = signMessage(message, kp.privateKey);
      expect(sig).toBe(v.signature_b64);

      // Verify signature validates
      expect(() => verifySignature(message, sig, kp.publicKey)).not.toThrow();
    });
  }
});

describe("b64 encode/decode vectors", () => {
  for (const v of vectors.vectors.b64_encode_decode) {
    it(`${v.id}: ${v.description}`, () => {
      const input = hexToBytes(v.input_hex);
      const encoded = b64Encode(input);
      expect(encoded).toBe(v.expected_b64);

      // Verify roundtrip
      const decoded = b64Decode(encoded);
      expect(bytesToHex(decoded)).toBe(v.input_hex);
    });
  }
});

describe("envelope signature vectors", () => {
  for (const v of vectors.vectors.envelope_signature) {
    it(`${v.id}: ${v.description}`, () => {
      const seed = hexToBytes(v.seed_hex);
      const kp = sodium.crypto_sign_seed_keypair(seed);

      // Build the signable dict (remove signature field)
      const wireDict = { ...v.envelope_wire };
      delete wireDict.signature;

      // Canonicalize and verify byte-identical output
      const canonical = canonicalize(wireDict);
      const canonicalHex = bytesToHex(canonical);
      expect(canonicalHex).toBe(v.canonical_json_hex);

      // Sign and verify byte-identical signature
      const sig = signMessage(canonical, kp.privateKey);
      expect(sig).toBe(v.expected_signature_b64);
    });
  }
});

describe("contact card signature vectors", () => {
  for (const v of vectors.vectors.contact_card_signature) {
    it(`${v.id}: ${v.description}`, () => {
      const seed = hexToBytes(v.seed_hex);
      const kp = sodium.crypto_sign_seed_keypair(seed);

      // Canonicalize the signable dict
      const canonical = canonicalize(v.card_signable);
      const canonicalHex = bytesToHex(canonical);
      expect(canonicalHex).toBe(v.canonical_json_hex);

      // Sign and verify byte-identical signature
      const sig = signMessage(canonical, kp.privateKey);
      expect(sig).toBe(v.expected_signature_b64);
    });
  }
});

describe("box encrypt/decrypt vectors (roundtrip)", () => {
  for (const v of vectors.vectors.encrypt_decrypt_box) {
    it(`${v.id}: ${v.description}`, () => {
      const senderSeed = hexToBytes(v.sender_seed_hex);
      const recipientSeed = hexToBytes(v.recipient_seed_hex);
      const senderKp = sodium.crypto_sign_seed_keypair(senderSeed);
      const recipientKp = sodium.crypto_sign_seed_keypair(recipientSeed);
      const plaintext = hexToBytes(v.plaintext_hex);

      // Encrypt and decrypt roundtrip
      const encrypted = encryptPayload(plaintext, senderKp.privateKey, recipientKp.publicKey);
      const decrypted = decryptPayload(encrypted, recipientKp.privateKey, senderKp.publicKey);
      expect(bytesToHex(decrypted)).toBe(v.plaintext_hex);
    });
  }
});

describe("sealedbox encrypt/decrypt vectors (roundtrip)", () => {
  for (const v of vectors.vectors.encrypt_decrypt_sealedbox) {
    it(`${v.id}: ${v.description}`, () => {
      const recipientSeed = hexToBytes(v.recipient_seed_hex);
      const recipientKp = sodium.crypto_sign_seed_keypair(recipientSeed);
      const plaintext = hexToBytes(v.plaintext_hex);

      // Encrypt and decrypt roundtrip
      const encrypted = encryptPayloadAnonymous(plaintext, recipientKp.publicKey);
      const decrypted = decryptPayloadAnonymous(encrypted, recipientKp.privateKey);
      expect(bytesToHex(decrypted)).toBe(v.plaintext_hex);
    });
  }
});
