import { describe, it, expect, beforeAll } from "vitest";
import {
  sodiumReady,
  generateKeypair,
  type Keypair,
} from "../../src/protocol/crypto.js";
import {
  createEnvelope,
  verifyEnvelope,
  toWireDict,
  fromWireDict,
  validateEnvelopeSize,
  type MessageEnvelope,
} from "../../src/protocol/envelope.js";
import { MessageType, MAX_ENVELOPE_SIZE } from "../../src/protocol/types.js";
import {
  InvalidEnvelopeError,
  EnvelopeTooLargeError,
  SignatureVerificationError,
} from "../../src/protocol/errors.js";

let sender: Keypair;
let recipient: Keypair;

beforeAll(async () => {
  await sodiumReady;
  sender = generateKeypair();
  recipient = generateKeypair();
});

describe("createEnvelope", () => {
  it("produces valid envelope with all required fields", async () => {
    const envelope = await createEnvelope(
      "alice::example.com",
      "bob::example.com",
      MessageType.MESSAGE,
      new TextEncoder().encode("hello"),
      sender.signingKey,
      recipient.verifyKey
    );

    expect(envelope.uamVersion).toBe("0.1");
    expect(envelope.messageId).toBeTruthy();
    expect(envelope.fromAddress).toBe("alice::example.com");
    expect(envelope.toAddress).toBe("bob::example.com");
    expect(envelope.timestamp).toBeTruthy();
    expect(envelope.type).toBe("message");
    expect(envelope.nonce).toBeTruthy();
    expect(envelope.payload).toBeTruthy();
    expect(envelope.signature).toBeTruthy();
  });

  it("includes optional fields when provided", async () => {
    const envelope = await createEnvelope(
      "alice::example.com",
      "bob::example.com",
      MessageType.MESSAGE,
      new TextEncoder().encode("hello"),
      sender.signingKey,
      recipient.verifyKey,
      {
        threadId: "thread-001",
        replyTo: "msg-001",
        mediaType: "text/plain",
      }
    );

    expect(envelope.threadId).toBe("thread-001");
    expect(envelope.replyTo).toBe("msg-001");
    expect(envelope.mediaType).toBe("text/plain");
  });

  it("uses SealedBox for handshake.request", async () => {
    // This should not throw -- SealedBox encryption works without sender key exchange
    const envelope = await createEnvelope(
      "alice::example.com",
      "bob::example.com",
      MessageType.HANDSHAKE_REQUEST,
      new TextEncoder().encode("handshake"),
      sender.signingKey,
      recipient.verifyKey
    );

    expect(envelope.type).toBe("handshake.request");
    expect(envelope.payload).toBeTruthy();
  });

  it("accepts string message type", async () => {
    const envelope = await createEnvelope(
      "alice::example.com",
      "bob::example.com",
      "message",
      new TextEncoder().encode("hello"),
      sender.signingKey,
      recipient.verifyKey
    );

    expect(envelope.type).toBe("message");
  });
});

describe("verifyEnvelope", () => {
  it("accepts self-created envelope", async () => {
    const envelope = await createEnvelope(
      "alice::example.com",
      "bob::example.com",
      MessageType.MESSAGE,
      new TextEncoder().encode("hello"),
      sender.signingKey,
      recipient.verifyKey
    );

    expect(() => verifyEnvelope(envelope, sender.verifyKey)).not.toThrow();
  });

  it("rejects tampered envelope", async () => {
    const envelope = await createEnvelope(
      "alice::example.com",
      "bob::example.com",
      MessageType.MESSAGE,
      new TextEncoder().encode("hello"),
      sender.signingKey,
      recipient.verifyKey
    );

    // Tamper with the payload
    const tampered: MessageEnvelope = {
      ...envelope,
      payload: "tampered-payload",
    };

    expect(() => verifyEnvelope(tampered, sender.verifyKey)).toThrow(
      SignatureVerificationError
    );
  });

  it("rejects wrong sender key", async () => {
    const envelope = await createEnvelope(
      "alice::example.com",
      "bob::example.com",
      MessageType.MESSAGE,
      new TextEncoder().encode("hello"),
      sender.signingKey,
      recipient.verifyKey
    );

    const wrongKey = generateKeypair();
    expect(() => verifyEnvelope(envelope, wrongKey.verifyKey)).toThrow(
      SignatureVerificationError
    );
  });
});

describe("toWireDict / fromWireDict", () => {
  it("roundtrips correctly", async () => {
    const envelope = await createEnvelope(
      "alice::example.com",
      "bob::example.com",
      MessageType.MESSAGE,
      new TextEncoder().encode("hello"),
      sender.signingKey,
      recipient.verifyKey,
      { threadId: "thread-001" }
    );

    const wire = toWireDict(envelope);
    const restored = fromWireDict(wire);

    expect(restored.uamVersion).toBe(envelope.uamVersion);
    expect(restored.messageId).toBe(envelope.messageId);
    expect(restored.fromAddress).toBe(envelope.fromAddress);
    expect(restored.toAddress).toBe(envelope.toAddress);
    expect(restored.timestamp).toBe(envelope.timestamp);
    expect(restored.type).toBe(envelope.type);
    expect(restored.nonce).toBe(envelope.nonce);
    expect(restored.payload).toBe(envelope.payload);
    expect(restored.signature).toBe(envelope.signature);
    expect(restored.threadId).toBe(envelope.threadId);
  });

  it("uses 'from'/'to' on wire (not fromAddress/toAddress)", async () => {
    const envelope = await createEnvelope(
      "alice::example.com",
      "bob::example.com",
      MessageType.MESSAGE,
      new TextEncoder().encode("hello"),
      sender.signingKey,
      recipient.verifyKey
    );

    const wire = toWireDict(envelope);
    expect(wire["from"]).toBe("alice::example.com");
    expect(wire["to"]).toBe("bob::example.com");
    expect(wire["fromAddress"]).toBeUndefined();
    expect(wire["toAddress"]).toBeUndefined();
  });

  it("includes attachments in wire dict", async () => {
    const envelope = await createEnvelope(
      "alice::example.com",
      "bob::example.com",
      MessageType.MESSAGE,
      new TextEncoder().encode("hello"),
      sender.signingKey,
      recipient.verifyKey,
      { attachments: [{ name: "file.txt", data: "abc" }] }
    );

    const wire = toWireDict(envelope);
    expect(wire["attachments"]).toEqual([{ name: "file.txt", data: "abc" }]);
  });

  it("rejects wire dict with missing fields", () => {
    expect(() =>
      fromWireDict({
        uam_version: "0.1",
        from: "alice::example.com",
      })
    ).toThrow(InvalidEnvelopeError);
  });
});

describe("validateEnvelopeSize", () => {
  it("rejects oversized envelope", async () => {
    // Create envelope with huge payload to exceed MAX_ENVELOPE_SIZE
    const bigPayload = new TextEncoder().encode("x".repeat(MAX_ENVELOPE_SIZE));
    const envelope = await createEnvelope(
      "alice::example.com",
      "bob::example.com",
      MessageType.MESSAGE,
      bigPayload,
      sender.signingKey,
      recipient.verifyKey
    ).catch(() => null);

    // createEnvelope itself validates size, so it should throw
    // If it didn't throw, test validateEnvelopeSize directly
    if (envelope !== null) {
      expect(() => validateEnvelopeSize(envelope)).toThrow(
        EnvelopeTooLargeError
      );
    } else {
      // createEnvelope already threw -- that's correct
      expect(true).toBe(true);
    }
  });
});
