/**
 * UAM SDK -- the agent-facing API.
 */

export { Agent } from "./agent.js";
export type { ReceivedMessage } from "./message.js";
export { SDKConfig } from "./config.js";
export { KeyManager } from "./key-manager.js";
export { ContactBook } from "./contact-book.js";
export { HandshakeManager } from "./handshake.js";
export { AddressResolver, SmartResolver, Tier1Resolver, Tier2Resolver, Tier3Resolver, type Tier3Config } from "./resolver.js";
export { TransportBase, HTTPTransport, WebSocketTransport, createTransport } from "./transport/index.js";
export { verifyWebhookSignature } from "./webhook-verify.js";
export { parseUamTxt, extractPublicKey, queryUamTxt, resolveKeyViaHttps, generateTxtRecord } from "./dns-verifier.js";
