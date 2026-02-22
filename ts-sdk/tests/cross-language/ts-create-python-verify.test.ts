/**
 * Cross-language tests: TypeScript creates fixtures for Python to verify.
 *
 * This test file:
 * 1. Creates envelopes, contact cards, and encrypted payloads from TypeScript
 * 2. Writes them to the fixtures/ directory for Python tests to consume
 * 3. Verifies that TypeScript-derived keys match Python-derived keys (same seed -> same output)
 */
import { writeFileSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it, expect, beforeAll } from "vitest";
import sodium from "libsodium-wrappers";
import {
  sodiumReady,
  deserializeSigningKey,
  serializeVerifyKey,
  publicKeyFingerprint,
  b64Encode,
  createEnvelope,
  toWireDict,
  createContactCard,
  contactCardToDict,
  encryptPayload,
  encryptPayloadAnonymous,
  MessageType,
} from "../../src/protocol/index.js";

const FIXTURES_DIR = resolve(__dirname, "fixtures");

function loadFixture(name: string): Record<string, unknown> {
  return JSON.parse(readFileSync(resolve(FIXTURES_DIR, name), "utf-8"));
}

function writeFixture(name: string, data: unknown): void {
  writeFileSync(
    resolve(FIXTURES_DIR, name),
    JSON.stringify(data, null, 2),
    "utf-8",
  );
}

describe("TypeScript creates fixtures for Python verification", () => {
  // Same fixed seeds as the Python generator
  const ALICE_SEED = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
  const BOB_SEED = new Uint8Array(Array.from({ length: 32 }, (_, i) => i + 32));

  let aliceSigningKey: Uint8Array;
  let aliceVerifyKey: Uint8Array;
  let bobSigningKey: Uint8Array;
  let bobVerifyKey: Uint8Array;

  beforeAll(async () => {
    await sodiumReady;

    const aliceKp = deserializeSigningKey(b64Encode(ALICE_SEED));
    aliceSigningKey = aliceKp.signingKey;
    aliceVerifyKey = aliceKp.verifyKey;

    const bobKp = deserializeSigningKey(b64Encode(BOB_SEED));
    bobSigningKey = bobKp.signingKey;
    bobVerifyKey = bobKp.verifyKey;
  });

  it("should produce keys matching Python-derived keys", () => {
    const pythonKeys = loadFixture("python-keys.json") as {
      alice: { verify_key_b64: string; fingerprint: string };
      bob: { verify_key_b64: string; fingerprint: string };
    };

    // Verify alice
    expect(serializeVerifyKey(aliceVerifyKey)).toBe(pythonKeys.alice.verify_key_b64);
    expect(publicKeyFingerprint(aliceVerifyKey)).toBe(pythonKeys.alice.fingerprint);

    // Verify bob
    expect(serializeVerifyKey(bobVerifyKey)).toBe(pythonKeys.bob.verify_key_b64);
    expect(publicKeyFingerprint(bobVerifyKey)).toBe(pythonKeys.bob.fingerprint);
  });

  it("should create an envelope fixture for Python to verify", async () => {
    const envelope = await createEnvelope(
      "alice::test.example.com",
      "bob::test.example.com",
      MessageType.MESSAGE,
      new TextEncoder().encode("Hello from TypeScript!"),
      aliceSigningKey,
      bobVerifyKey,
      { mediaType: "text/plain" },
    );

    const wireDict = toWireDict(envelope);
    writeFixture("ts-envelope.json", wireDict);

    // Verify the fixture was written
    const loaded = loadFixture("ts-envelope.json") as Record<string, unknown>;
    expect(loaded["from"]).toBe("alice::test.example.com");
    expect(loaded["to"]).toBe("bob::test.example.com");
    expect(loaded["type"]).toBe("message");
  });

  it("should create a contact card fixture for Python to verify", async () => {
    const card = await createContactCard(
      "alice::test.example.com",
      "Alice (TypeScript)",
      "wss://relay.test.example.com/ws",
      aliceSigningKey,
      { description: "Test agent created by TypeScript" },
    );

    const cardDict = contactCardToDict(card);
    writeFixture("ts-contact-card.json", cardDict);

    // Verify the fixture was written
    const loaded = loadFixture("ts-contact-card.json") as Record<string, unknown>;
    expect(loaded["address"]).toBe("alice::test.example.com");
    expect(loaded["display_name"]).toBe("Alice (TypeScript)");
  });

  it("should create a NaCl Box encrypted payload fixture for Python to verify", () => {
    const plaintext = "Box encrypted by TypeScript";
    const ciphertext = encryptPayload(
      new TextEncoder().encode(plaintext),
      aliceSigningKey,
      bobVerifyKey,
    );

    writeFixture("ts-box-payload.json", {
      plaintext,
      ciphertext_b64: ciphertext,
      sender_seed_b64: b64Encode(ALICE_SEED),
      recipient_seed_b64: b64Encode(BOB_SEED),
    });

    // Verify the fixture was written
    const loaded = loadFixture("ts-box-payload.json") as {
      plaintext: string;
      ciphertext_b64: string;
    };
    expect(loaded.plaintext).toBe(plaintext);
    expect(loaded.ciphertext_b64).toBeTruthy();
  });

  it("should create a SealedBox encrypted payload fixture for Python to verify", () => {
    const plaintext = "SealedBox encrypted by TypeScript";
    const ciphertext = encryptPayloadAnonymous(
      new TextEncoder().encode(plaintext),
      bobVerifyKey,
    );

    writeFixture("ts-sealedbox-payload.json", {
      plaintext,
      ciphertext_b64: ciphertext,
      recipient_seed_b64: b64Encode(BOB_SEED),
    });

    // Verify the fixture was written
    const loaded = loadFixture("ts-sealedbox-payload.json") as {
      plaintext: string;
      ciphertext_b64: string;
    };
    expect(loaded.plaintext).toBe(plaintext);
    expect(loaded.ciphertext_b64).toBeTruthy();
  });
});
