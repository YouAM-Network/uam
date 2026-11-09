/**
 * UAM -- Universal Agent Messaging.
 *
 * Top-level package exports: Agent, ContactBook, verifyWebhookSignature,
 * ReceivedMessage, protocol.
 */

export { Agent, ContactBook, verifyWebhookSignature } from "./sdk/index.js";
export type { ReceivedMessage, SendResult, SendStatus } from "./sdk/index.js";
export { PENDING_NOTE, SEND_STATUSES, pendingNote, supports } from "./sdk/index.js";
export * as protocol from "./protocol/index.js";
