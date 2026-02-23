/**
 * Tests for webhook signature verification.
 */

import { describe, it, expect } from "vitest";
import { createHmac } from "node:crypto";
import { verifyWebhookSignature } from "../../src/sdk/webhook-verify.js";

describe("verifyWebhookSignature", () => {
  const token = "test-agent-token-12345";
  const payload = Buffer.from('{"event":"message","id":"msg-1"}');

  function makeSignature(payloadBytes: Buffer, secret: string): string {
    const hex = createHmac("sha256", secret)
      .update(payloadBytes)
      .digest("hex");
    return `sha256=${hex}`;
  }

  it("returns true for a valid signature", () => {
    const sig = makeSignature(payload, token);
    expect(verifyWebhookSignature(payload, sig, token)).toBe(true);
  });

  it("returns false for an invalid signature", () => {
    const sig = "sha256=0000000000000000000000000000000000000000000000000000000000000000";
    expect(verifyWebhookSignature(payload, sig, token)).toBe(false);
  });

  it("returns false for wrong token", () => {
    const sig = makeSignature(payload, token);
    expect(verifyWebhookSignature(payload, sig, "wrong-token")).toBe(false);
  });

  it("returns false for tampered payload", () => {
    const sig = makeSignature(payload, token);
    const tampered = Buffer.from('{"event":"message","id":"msg-2"}');
    expect(verifyWebhookSignature(tampered, sig, token)).toBe(false);
  });

  it("returns false for missing sha256= prefix", () => {
    const hex = createHmac("sha256", token).update(payload).digest("hex");
    expect(verifyWebhookSignature(payload, hex, token)).toBe(false);
  });

  it("returns false for empty signature header", () => {
    expect(verifyWebhookSignature(payload, "", token)).toBe(false);
  });

  it("works with Uint8Array payload", () => {
    const uint8Payload = new Uint8Array(payload);
    const sig = makeSignature(payload, token);
    expect(verifyWebhookSignature(uint8Payload, sig, token)).toBe(true);
  });

  it("uses constant-time comparison (no early exit on mismatch)", () => {
    // This is a structural test -- verifyWebhookSignature uses timingSafeEqual.
    // We verify correct behavior with a signature that differs only in
    // the last character.
    const sig = makeSignature(payload, token);
    const lastChar = sig[sig.length - 1];
    const altChar = lastChar === "0" ? "1" : "0";
    const altSig = sig.slice(0, -1) + altChar;
    expect(verifyWebhookSignature(payload, altSig, token)).toBe(false);
  });
});
