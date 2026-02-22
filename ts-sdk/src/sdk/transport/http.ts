/**
 * HTTP transport via native fetch (SDK-09).
 *
 * Sends envelopes via POST /api/v1/send and retrieves inbox
 * via GET /api/v1/inbox/{address}.
 *
 * Uses native fetch (Node.js 18+ has global fetch).
 */

import { TransportBase } from "./base.js";

export class HTTPTransport extends TransportBase {
  private _relayUrl: string;
  private _token: string;
  private _address: string;

  constructor(relayUrl: string, token: string, address: string) {
    super();
    this._relayUrl = relayUrl.replace(/\/+$/, "");
    this._token = token;
    this._address = address;
  }

  async connect(): Promise<void> {
    // No persistent connection needed for HTTP
  }

  async disconnect(): Promise<void> {
    // No-op
  }

  async send(envelope: Record<string, unknown>): Promise<void> {
    const resp = await fetch(`${this._relayUrl}/api/v1/send`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this._token}`,
      },
      body: JSON.stringify({ envelope }),
    });
    if (!resp.ok) {
      throw new Error(
        `HTTP send failed: ${resp.status} ${resp.statusText}`
      );
    }
  }

  async receive(limit: number = 50): Promise<Record<string, unknown>[]> {
    const url = new URL(
      `${this._relayUrl}/api/v1/inbox/${this._address}`
    );
    url.searchParams.set("limit", String(limit));

    const resp = await fetch(url.toString(), {
      headers: {
        Authorization: `Bearer ${this._token}`,
      },
    });
    if (!resp.ok) {
      throw new Error(
        `HTTP receive failed: ${resp.status} ${resp.statusText}`
      );
    }
    const data = (await resp.json()) as Record<string, unknown>;
    return (data["messages"] as Record<string, unknown>[]) ?? [];
  }

  async listen(
    _callback: (msg: Record<string, unknown>) => Promise<void>
  ): Promise<void> {
    throw new Error(
      "HTTP transport does not support real-time listening. " +
        "Use receive() for polling or switch to WebSocket transport."
    );
  }
}
