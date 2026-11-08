/**
 * UAM -- Universal Agent Messaging.
 *
 * Top-level package exports: Agent, ContactBook, verifyWebhookSignature,
 * ReceivedMessage, protocol.
 */

export { Agent, ContactBook, verifyWebhookSignature } from "./sdk/index.js";
export type { ReceivedMessage } from "./sdk/index.js";
export * as protocol from "./protocol/index.js";
