/**
 * UAM SDK transport layer.
 */

import type { SDKConfig } from "../config.js";
import { TransportBase } from "./base.js";
import { HTTPTransport } from "./http.js";
import { WebSocketTransport } from "./websocket.js";

export { TransportBase } from "./base.js";
export { HTTPTransport } from "./http.js";
export { WebSocketTransport } from "./websocket.js";

/**
 * Factory to create the appropriate transport based on config.
 */
export function createTransport(
  config: SDKConfig,
  token: string,
  address: string,
  onMessage?: (msg: Record<string, unknown>) => Promise<void>
): TransportBase {
  if (config.transportType === "http") {
    return new HTTPTransport(config.relayUrl, token, address);
  } else {
    return new WebSocketTransport(config.relayWsUrl, token, onMessage);
  }
}
