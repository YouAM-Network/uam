/**
 * ReceivedMessage -- frozen data object for inbound messages.
 *
 * Matches Python message.py: a readonly interface for decrypted messages.
 * The toString() omission is deliberate prompt-injection isolation (SDK-10).
 */

/**
 * A decrypted, verified inbound message.
 *
 * This is a DATA OBJECT. Framework integrations must explicitly
 * extract .content to use in prompts. The SDK never concatenates
 * message content into LLM context automatically.
 */
export interface ReceivedMessage {
  readonly messageId: string;
  readonly fromAddress: string;
  readonly toAddress: string;
  readonly content: string;
  readonly timestamp: string;
  readonly type: string;
  readonly threadId?: string;
  readonly replyTo?: string;
  readonly mediaType?: string;
  readonly verified: boolean;
}

/** What a relay can say it did with a sent message (as the Python SDK). */
export const SEND_STATUSES = [
  "delivered",
  "stored",
  "relayed",
  "queued",
  "duplicate",
  "dropped",
  "pending",
  "accepted",
  "unknown",
] as const;

export type SendStatus = (typeof SEND_STATUSES)[number];

/**
 * What Agent.send() returns.
 *
 * `status` is one of SEND_STATUSES: "pending" means the recipient only
 * takes messages from approved contacts and the relay kept nothing.
 * `delivered` is true only when the relay says the recipient has it.
 */
export interface SendResult {
  readonly messageId: string;
  readonly status: SendStatus;
  readonly delivered: boolean;
}

/**
 * The status in a relay's answer to a send (HTTP body or WebSocket ack).
 *
 * null (no answer in time) is "unknown". An answer without a known status
 * comes from a relay before 1.1: "accepted".
 */
export function sendStatus(answer: Record<string, unknown> | null): SendStatus {
  if (answer === null) return "unknown";
  const status = answer["status"];
  if (
    typeof status === "string" &&
    (SEND_STATUSES as readonly string[]).includes(status) &&
    status !== "accepted" &&
    status !== "unknown"
  ) {
    return status as SendStatus;
  }
  return "accepted";
}

/**
 * True when a relay's features include `name` at `version` or later.
 *
 * "name" is version 1; "name:N" means version N or later.
 */
export function supports(
  features: Iterable<string>,
  name: string,
  version: number = 1
): boolean {
  const prefix = `${name}:`;
  for (const feature of features) {
    if (feature === name && version <= 1) return true;
    if (feature.startsWith(prefix)) {
      const rest = feature.slice(prefix.length);
      if (/^\d+$/.test(rest) && Number(rest) >= version) return true;
    }
  }
  return false;
}

/** What to tell whoever sent a message the relay answered "pending". */
export const PENDING_NOTE =
  "Not delivered: {to} only accepts messages from approved contacts. " +
  "Do not resend it.";

export function pendingNote(to: string): string {
  return PENDING_NOTE.replace("{to}", to);
}
