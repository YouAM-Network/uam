import { describe, it, expect, beforeAll } from "vitest";
import {
  sodiumReady,
  generateKeypair,
  serializeSigningKey,
  deserializeSigningKey,
  serializeVerifyKey,
  deserializeVerifyKey,
  publicKeyFingerprint,
  canonicalize,
  signMessage,
  verifySignature,
  generateNonce,
  encryptPayload,
  decryptPayload,
  encryptPayloadAnonymous,
  decryptPayloadAnonymous,
} from "../../src/protocol/crypto.js";
import { SignatureVerificationError, DecryptionError } from "../../src/protocol/errors.js";
import { b64Decode } from "../../src/protocol/types.js";

beforeAll(async () => {
  await sodiumReady;
});

describe("generateKeypair", () => {
  it("produces correct key sizes", () => {
    const kp = generateKeypair();
    expect(kp.seed.length).toBe(32);
    expect(kp.signingKey.length).toBe(64);
    expect(kp.verifyKey.length).toBe(32);
  });

  it("produces different keypairs each call", () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    expect(Buffer.from(kp1.seed).equals(Buffer.from(kp2.seed))).toBe(false);
  });
});

describe("key serialization", () => {
  it("roundtrips signing key through serialize/deserialize", () => {
    const kp = generateKeypair();
    const serialized = serializeSigningKey(kp.seed);
    const restored = deserializeSigningKey(serialized);
    expect(Buffer.from(restored.seed).equals(Buffer.from(kp.seed))).toBe(true);
    expect(Buffer.from(restored.signingKey).equals(Buffer.from(kp.signingKey))).toBe(true);
    expect(Buffer.from(restored.verifyKey).equals(Buffer.from(kp.verifyKey))).toBe(true);
  });

  it("roundtrips verify key through serialize/deserialize", () => {
    const kp = generateKeypair();
    const serialized = serializeVerifyKey(kp.verifyKey);
    const restored = deserializeVerifyKey(serialized);
    expect(Buffer.from(restored).equals(Buffer.from(kp.verifyKey))).toBe(true);
  });
});

describe("publicKeyFingerprint", () => {
  it("produces 64-char hex string", () => {
    const kp = generateKeypair();
    const fp = publicKeyFingerprint(kp.verifyKey);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic for same key", () => {
    const kp = generateKeypair();
    expect(publicKeyFingerprint(kp.verifyKey)).toBe(publicKeyFingerprint(kp.verifyKey));
  });
});

describe("canonicalize", () => {
  it("sorts keys and uses compact separators", () => {
    const result = new TextDecoder().decode(
      canonicalize({ b: "2", a: "1" })
    );
    expect(result).toBe('{"a":"1","b":"2"}');
  });

  it("excludes signature key", () => {
    const result = new TextDecoder().decode(
      canonicalize({ a: "1", signature: "sig" })
    );
    expect(result).toBe('{"a":"1"}');
  });

  it("excludes null/undefined values", () => {
    const result = new TextDecoder().decode(
      canonicalize({ a: "1", b: null, c: undefined } as Record<string, unknown>)
    );
    expect(result).toBe('{"a":"1"}');
  });

  it("handles nested objects with sorted keys", () => {
    const result = new TextDecoder().decode(
      canonicalize({ z: { b: "2", a: "1" }, a: "x" })
    );
    expect(result).toBe('{"a":"x","z":{"a":"1","b":"2"}}');
  });

  it("handles empty object", () => {
    const result = new TextDecoder().decode(canonicalize({}));
    expect(result).toBe("{}");
  });
});

describe("sign/verify", () => {
  it("roundtrips successfully", () => {
    const kp = generateKeypair();
    const data = new TextEncoder().encode("hello world");
    const sig = signMessage(data, kp.signingKey);
    expect(() => verifySignature(data, sig, kp.verifyKey)).not.toThrow();
  });

  it("rejects tampered data", () => {
    const kp = generateKeypair();
    const data = new TextEncoder().encode("hello world");
    const sig = signMessage(data, kp.signingKey);
    const tampered = new TextEncoder().encode("hello world!");
    expect(() => verifySignature(tampered, sig, kp.verifyKey)).toThrow(
      SignatureVerificationError
    );
  });

  it("rejects wrong key", () => {
    const kp1 = generateKeypair();
    const kp2 = generateKeypair();
    const data = new TextEncoder().encode("hello world");
    const sig = signMessage(data, kp1.signingKey);
    expect(() => verifySignature(data, sig, kp2.verifyKey)).toThrow(
      SignatureVerificationError
    );
  });
});

describe("generateNonce", () => {
  it("returns a base64 string", () => {
    const nonce = generateNonce();
    expect(typeof nonce).toBe("string");
    // 24 random bytes base64-encoded = 32 chars
    const decoded = b64Decode(nonce);
    expect(decoded.length).toBe(24);
  });
});

describe("NaCl Box encrypt/decrypt", () => {
  it("roundtrips correctly", () => {
    const sender = generateKeypair();
    const recipient = generateKeypair();
    const plaintext = new TextEncoder().encode("hello from sender to recipient");
    const encrypted = encryptPayload(plaintext, sender.signingKey, recipient.verifyKey);
    const decrypted = decryptPayload(encrypted, recipient.signingKey, sender.verifyKey);
    expect(new TextDecoder().decode(decrypted)).toBe("hello from sender to recipient");
  });

  it("fails with wrong recipient key", () => {
    const sender = generateKeypair();
    const recipient = generateKeypair();
    const wrongRecipient = generateKeypair();
    const plaintext = new TextEncoder().encode("secret");
    const encrypted = encryptPayload(plaintext, sender.signingKey, recipient.verifyKey);
    expect(() =>
      decryptPayload(encrypted, wrongRecipient.signingKey, sender.verifyKey)
    ).toThrow(DecryptionError);
  });

  it("handles empty plaintext", () => {
    const sender = generateKeypair();
    const recipient = generateKeypair();
    const plaintext = new Uint8Array(0);
    const encrypted = encryptPayload(plaintext, sender.signingKey, recipient.verifyKey);
    const decrypted = decryptPayload(encrypted, recipient.signingKey, sender.verifyKey);
    expect(decrypted.length).toBe(0);
  });
});

describe("NaCl SealedBox encrypt/decrypt", () => {
  it("roundtrips correctly", () => {
    const recipient = generateKeypair();
    const plaintext = new TextEncoder().encode("anonymous message");
    const encrypted = encryptPayloadAnonymous(plaintext, recipient.verifyKey);
    const decrypted = decryptPayloadAnonymous(encrypted, recipient.signingKey);
    expect(new TextDecoder().decode(decrypted)).toBe("anonymous message");
  });

  it("fails with wrong key", () => {
    const recipient = generateKeypair();
    const wrongRecipient = generateKeypair();
    const plaintext = new TextEncoder().encode("secret");
    const encrypted = encryptPayloadAnonymous(plaintext, recipient.verifyKey);
    expect(() =>
      decryptPayloadAnonymous(encrypted, wrongRecipient.signingKey)
    ).toThrow(DecryptionError);
  });
});
