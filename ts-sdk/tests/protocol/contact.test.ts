import { describe, it, expect, beforeAll } from "vitest";
import {
  sodiumReady,
  generateKeypair,
  type Keypair,
} from "../../src/protocol/crypto.js";
import {
  createContactCard,
  verifyContactCard,
  contactCardToDict,
  contactCardFromDict,
  type ContactCard,
} from "../../src/protocol/contact.js";
import {
  InvalidContactCardError,
  SignatureVerificationError,
} from "../../src/protocol/errors.js";

let keypair: Keypair;

beforeAll(async () => {
  await sodiumReady;
  keypair = generateKeypair();
});

describe("createContactCard", () => {
  it("produces valid signed card", async () => {
    const card = await createContactCard(
      "alice::example.com",
      "Alice Agent",
      "https://relay.example.com",
      keypair.signingKey
    );

    expect(card.version).toBe("0.1");
    expect(card.address).toBe("alice::example.com");
    expect(card.displayName).toBe("Alice Agent");
    expect(card.relay).toBe("https://relay.example.com");
    expect(card.publicKey).toBeTruthy();
    expect(card.signature).toBeTruthy();
    expect(card.fingerprint).toBeTruthy();
    expect(card.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });

  it("uses default payload formats", async () => {
    const card = await createContactCard(
      "alice::example.com",
      "Alice Agent",
      "https://relay.example.com",
      keypair.signingKey
    );

    expect(card.payloadFormats).toEqual(["text/plain", "text/markdown"]);
  });

  it("accepts custom payload formats", async () => {
    const card = await createContactCard(
      "alice::example.com",
      "Alice Agent",
      "https://relay.example.com",
      keypair.signingKey,
      { payloadFormats: ["application/json"] }
    );

    expect(card.payloadFormats).toEqual(["application/json"]);
  });

  it("includes optional fields when provided", async () => {
    const card = await createContactCard(
      "alice::example.com",
      "Alice Agent",
      "https://relay.example.com",
      keypair.signingKey,
      {
        description: "A helpful assistant",
        system: "openai-gpt4",
        connectionEndpoint: "https://alice.example.com/uam",
        verifiedDomain: "example.com",
      }
    );

    expect(card.description).toBe("A helpful assistant");
    expect(card.system).toBe("openai-gpt4");
    expect(card.connectionEndpoint).toBe("https://alice.example.com/uam");
    expect(card.verifiedDomain).toBe("example.com");
  });
});

describe("verifyContactCard", () => {
  it("accepts self-created card", async () => {
    const card = await createContactCard(
      "alice::example.com",
      "Alice Agent",
      "https://relay.example.com",
      keypair.signingKey
    );

    expect(() => verifyContactCard(card)).not.toThrow();
  });

  it("rejects tampered card", async () => {
    const card = await createContactCard(
      "alice::example.com",
      "Alice Agent",
      "https://relay.example.com",
      keypair.signingKey
    );

    // Tamper with display name
    const tampered: ContactCard = {
      ...card,
      displayName: "Evil Agent",
    };

    expect(() => verifyContactCard(tampered)).toThrow(
      SignatureVerificationError
    );
  });

  it("rejects card with invalid address", async () => {
    const card = await createContactCard(
      "alice::example.com",
      "Alice Agent",
      "https://relay.example.com",
      keypair.signingKey
    );

    // Tamper with address
    const tampered: ContactCard = {
      ...card,
      address: "not valid address",
    };

    expect(() => verifyContactCard(tampered)).toThrow(
      InvalidContactCardError
    );
  });
});

describe("contactCardToDict / contactCardFromDict", () => {
  it("roundtrips correctly", async () => {
    const card = await createContactCard(
      "alice::example.com",
      "Alice Agent",
      "https://relay.example.com",
      keypair.signingKey,
      { description: "Test" }
    );

    const dict = contactCardToDict(card);
    const restored = contactCardFromDict(dict);

    expect(restored.version).toBe(card.version);
    expect(restored.address).toBe(card.address);
    expect(restored.displayName).toBe(card.displayName);
    expect(restored.description).toBe(card.description);
    expect(restored.relay).toBe(card.relay);
    expect(restored.publicKey).toBe(card.publicKey);
    expect(restored.signature).toBe(card.signature);
    expect(restored.fingerprint).toBe(card.fingerprint);
    expect(restored.payloadFormats).toEqual(card.payloadFormats);
  });

  it("uses snake_case names on wire", async () => {
    const card = await createContactCard(
      "alice::example.com",
      "Alice Agent",
      "https://relay.example.com",
      keypair.signingKey,
      { verifiedDomain: "example.com" }
    );

    const dict = contactCardToDict(card);
    expect(dict["display_name"]).toBe("Alice Agent");
    expect(dict["public_key"]).toBeTruthy();
    expect(dict["payload_formats"]).toEqual(["text/plain", "text/markdown"]);
    expect(dict["verified_domain"]).toBe("example.com");
    // camelCase should not appear
    expect(dict["displayName"]).toBeUndefined();
    expect(dict["publicKey"]).toBeUndefined();
    expect(dict["payloadFormats"]).toBeUndefined();
    expect(dict["verifiedDomain"]).toBeUndefined();
  });

  it("rejects missing required fields", () => {
    expect(() =>
      contactCardFromDict({
        version: "0.1",
        address: "alice::example.com",
      })
    ).toThrow(InvalidContactCardError);
  });

  it("allows skip verify", async () => {
    const card = await createContactCard(
      "alice::example.com",
      "Alice Agent",
      "https://relay.example.com",
      keypair.signingKey
    );

    const dict = contactCardToDict(card);
    dict["display_name"] = "Tampered"; // tamper
    // Should not throw with verify: false
    const restored = contactCardFromDict(dict, { verify: false });
    expect(restored.displayName).toBe("Tampered");
  });
});

describe("relays field (outside signature scope)", () => {
  it("relays field is outside signature scope", async () => {
    const card = await createContactCard(
      "alice::example.com",
      "Alice Agent",
      "https://relay.example.com",
      keypair.signingKey
    );

    // Add relays after creation - signature should still verify
    const withRelays: ContactCard = {
      ...card,
      relays: ["https://relay2.example.com", "https://relay3.example.com"],
    };

    expect(() => verifyContactCard(withRelays)).not.toThrow();
  });

  it("relays field roundtrips through dict", async () => {
    const card = await createContactCard(
      "alice::example.com",
      "Alice Agent",
      "https://relay.example.com",
      keypair.signingKey,
      { relays: ["https://relay2.example.com"] }
    );

    const dict = contactCardToDict(card);
    expect(dict["relays"]).toEqual(["https://relay2.example.com"]);

    const restored = contactCardFromDict(dict);
    expect(restored.relays).toEqual(["https://relay2.example.com"]);
  });
});
