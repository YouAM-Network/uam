/**
 * UAM SDK -- the agent-facing API.
 */

export { Agent } from "./agent.js";
export type { ReceivedMessage } from "./message.js";
export { SDKConfig } from "./config.js";
export { KeyManager } from "./key-manager.js";
export { ContactBook } from "./contact-book.js";
export { HandshakeManager, bindCardToEnvelope } from "./handshake.js";
export { EnvelopeReplayCache, PersistentReplayCache } from "./replay-cache.js";
export { RELAY_META_FEATURE, STORED_MAIL_MAX_AGE, relayVouches } from "./freshness.js";
export { AddressResolver, SmartResolver, Tier1Resolver, Tier2Resolver, Tier3Resolver, type Tier3Config } from "./resolver.js";
export { TransportBase, HTTPTransport, WebSocketTransport, createTransport } from "./transport/index.js";
export { verifyWebhookSignature } from "./webhook-verify.js";
export { parseUamTxt, extractPublicKey, queryUamTxt, resolveKeyViaHttps, generateTxtRecord } from "./dns-verifier.js";
