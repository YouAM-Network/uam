/**
 * Cross-language tests: TypeScript verifies Python-generated fixtures.
 *
 * These tests prove that the TypeScript SDK can:
 * 1. Derive identical keys from the same seed as Python
 * 2. Verify envelope signatures created by Python
 * 3. Decrypt payloads encrypted by Python (both NaCl Box and SealedBox)
 * 4. Parse and verify contact cards created by Python
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it, expect, beforeAll } from "vitest";
import {
  sodiumReady,
  deserializeSigningKey,
  serializeVerifyKey,
  publicKeyFingerprint,
  fromWireDict,
  verifyEnvelope,
  decryptPayload,
  decryptPayloadAnonymous,
  contactCardFromDict,
  b64Decode,
} from "../../src/protocol/index.js";

const FIXTURES_DIR = resolve(__dirname, "fixtures");

function loadFixture(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(FIXTURES_DIR, name), "utf-8"));
}

describe("TypeScript verifies Python fixtures", () => {
  beforeAll(async () => {
    await sodiumReady;
  });

  describe("Key derivation", () => {
    it("should derive identical keys from same seed as Python", () => {
      const keys = loadFixture("python-keys.json") as {
        alice: { seed_b64: string; verify_key_b64: string; fingerprint: string };
        bob: { seed_b64: string; verify_key_b64: string; fingerprint: string };
      };

      // Alice
      const aliceKp = deserializeSigningKey(keys.alice.seed_b64);
      expect(serializeVerifyKey(aliceKp.verifyKey)).toBe(keys.alice.verify_key_b64);
      expect(publicKeyFingerprint(aliceKp.verifyKey)).toBe(keys.alice.fingerprint);

      // Bob
      const bobKp = deserializeSigningKey(keys.bob.seed_b64);
      expect(serializeVerifyKey(bobKp.verifyKey)).toBe(keys.bob.verify_key_b64);
      expect(publicKeyFingerprint(bobKp.verifyKey)).toBe(keys.bob.fingerprint);
    });
  });

  describe("Envelope verification", () => {
    it("should verify and decrypt a Python-created message envelope", () => {
      const keys = loadFixture("python-keys.json") as {
        alice: { seed_b64: string };
        bob: { seed_b64: string };
      };
      const envelopeWire = loadFixture("python-envelope.json") as Record<string, unknown>;

      const aliceKp = deserializeSigningKey(keys.alice.seed_b64);
      const bobKp = deserializeSigningKey(keys.bob.seed_b64);

      // Parse wire format
      const envelope = fromWireDict(envelopeWire);
      expect(envelope.fromAddress).toBe("alice::test.example.com");
      expect(envelope.toAddress).toBe("bob::test.example.com");
      expect(envelope.type).toBe("message");
      expect(envelope.mediaType).toBe("text/plain");

      // Verify signature using alice's verify key
      verifyEnvelope(envelope, aliceKp.verifyKey);

      // Decrypt payload using bob's signing key and alice's verify key
      const plaintext = decryptPayload(
        envelope.payload,
        bobKp.signingKey,
        aliceKp.verifyKey,
      );
      expect(new TextDecoder().decode(plaintext)).toBe("Hello from Python!");
    });

    it("should verify and decrypt a Python-created handshake envelope (SealedBox)", () => {
      const keys = loadFixture("python-keys.json") as {
        alice: { seed_b64: string };
        bob: { seed_b64: string };
      };
      const envelopeWire = loadFixture("python-handshake-envelope.json") as Record<string, unknown>;

      const aliceKp = deserializeSigningKey(keys.alice.seed_b64);
      const bobKp = deserializeSigningKey(keys.bob.seed_b64);

      // Parse wire format
      const envelope = fromWireDict(envelopeWire);
      expect(envelope.type).toBe("handshake.request");

      // Verify signature using alice's verify key
      verifyEnvelope(envelope, aliceKp.verifyKey);

      // Decrypt payload using bob's signing key (SealedBox -- anonymous sender)
      const plaintext = decryptPayloadAnonymous(
        envelope.payload,
        bobKp.signingKey,
      );
      const parsed = JSON.parse(new TextDecoder().decode(plaintext));
      expect(parsed.type).toBe("handshake");
      expect(parsed.from).toBe("alice");
    });
  });

  describe("Contact card verification", () => {
    it("should parse and verify a Python-created contact card", () => {
      const cardDict = loadFixture("python-contact-card.json") as Record<string, unknown>;

      // Parse with verification (default: verify=true)
      const card = contactCardFromDict(cardDict);
      expect(card.address).toBe("alice::test.example.com");
      expect(card.displayName).toBe("Alice (Python)");
      expect(card.relay).toBe("wss://relay.test.example.com/ws");
      expect(card.description).toBe("Test agent created by Python");

      // Verify the fingerprint matches what we compute from the public key
      const keys = loadFixture("python-keys.json") as {
        alice: { seed_b64: string; fingerprint: string };
      };
      expect(card.fingerprint).toBe(keys.alice.fingerprint);
    });
  });

  describe("NaCl Box payload decryption", () => {
    it("should decrypt a Python-encrypted NaCl Box payload", () => {
      const fixture = loadFixture("python-box-payload.json") as {
        plaintext: string;
        ciphertext_b64: string;
        sender_seed_b64: string;
        recipient_seed_b64: string;
      };

      const aliceKp = deserializeSigningKey(fixture.sender_seed_b64);
      const bobKp = deserializeSigningKey(fixture.recipient_seed_b64);

      const decrypted = decryptPayload(
        fixture.ciphertext_b64,
        bobKp.signingKey,
        aliceKp.verifyKey,
      );
      expect(new TextDecoder().decode(decrypted)).toBe("Box encrypted by Python");
    });
  });

  describe("NaCl SealedBox payload decryption", () => {
    it("should decrypt a Python-encrypted SealedBox payload", () => {
      const fixture = loadFixture("python-sealedbox-payload.json") as {
        plaintext: string;
        ciphertext_b64: string;
        recipient_seed_b64: string;
      };

      const bobKp = deserializeSigningKey(fixture.recipient_seed_b64);

      const decrypted = decryptPayloadAnonymous(
        fixture.ciphertext_b64,
        bobKp.signingKey,
      );
      expect(new TextDecoder().decode(decrypted)).toBe("SealedBox encrypted by Python");
    });
  });
});
