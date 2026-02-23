/**
 * Receiver-side webhook signature verification (HOOK-03).
 *
 * Small utility for webhook receivers to verify that incoming webhook
 * payloads were signed by the UAM relay.  Uses HMAC-SHA256 with the
 * agent's token as the shared secret.
 *
 * Matches Python webhook_verify.py API surface.
 *
 * Usage:
 *
 *     import { verifyWebhookSignature } from "uam";
 *
 *     const payload = Buffer.from(requestBody);
 *     const signature = request.headers["x-uam-signature"];
 *     const token = "your-agent-token";
 *
 *     if (verifyWebhookSignature(payload, signature, token)) {
 *       // payload is authentic
 *     }
 */

import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Verify an HMAC-SHA256 webhook signature.
 *
 * @param payload - Raw request body bytes
 * @param signatureHeader - "sha256=<hex>" format (X-UAM-Signature header)
 * @param token - Shared secret (agent token)
 * @returns `true` if valid, `false` otherwise.
 *
 * Uses `crypto.timingSafeEqual()` for constant-time comparison
 * to prevent timing attacks.
 */
export function verifyWebhookSignature(
  payload: Buffer | Uint8Array,
  signatureHeader: string,
  token: string
): boolean {
  if (!signatureHeader.startsWith("sha256=")) {
    return false;
  }

  const expected = createHmac("sha256", token)
    .update(payload)
    .digest("hex");
  const received = signatureHeader.slice("sha256=".length);

  // Constant-time comparison requires equal-length buffers
  const expectedBuf = Buffer.from(expected, "utf-8");
  const receivedBuf = Buffer.from(received, "utf-8");

  if (expectedBuf.length !== receivedBuf.length) {
    return false;
  }

  return timingSafeEqual(expectedBuf, receivedBuf);
}
