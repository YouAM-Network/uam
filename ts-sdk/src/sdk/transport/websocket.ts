/**
 * WebSocket transport with exponential backoff and jitter (SDK-05).
 *
 * Maintains a persistent connection to the relay, automatically
 * reconnecting on disconnection with exponential backoff plus
 * random jitter to prevent thundering herd.
 */

import WebSocket from "ws";
import { log } from "../log.js";
import { TransportBase } from "./base.js";

// Reconnection constants
const BASE_DELAY = 1.0; // Initial delay in seconds
const MAX_DELAY = 60.0; // Maximum delay cap
const JITTER_RANGE = 1.0; // Random jitter 0 to JITTER_RANGE

/** How long a close waits for the relay to answer sends, in seconds. */
export const SEND_SETTLE_SECONDS = 5;

export class WebSocketTransport extends TransportBase {
  private _url: string;
  private _token: string;
  private _onMessage:
    | ((msg: Record<string, unknown>) => Promise<void>)
    | null;
  private _ws: WebSocket | null = null;
  private _pending: Record<string, unknown>[] = [];
  private _connected: boolean = false;
  private _connectResolve: (() => void) | null = null;
  private _connectReject: ((err: Error) => void) | null = null;
  private _running: boolean = false;
  private _reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
  /** Envelopes sent that the relay hasn't answered yet. */
  private _unanswered: number = 0;
  private _settling: Promise<void> | null = null;
  private _settled: (() => void) | null = null;

  /** @internal How long a close waits, in ms. Replaceable in tests. */
  _settleMs: number = SEND_SETTLE_SECONDS * 1000;

  constructor(
    wsUrl: string,
    token: string,
    onMessage?: (msg: Record<string, unknown>) => Promise<void>
  ) {
    super();
    // The token travels in the `bearer.<token>` WebSocket subprotocol, not
    // in a ?token= query string, so it stays out of HTTP access logs and
    // proxy logs. The relay accepts this form and echoes the subprotocol
    // back (relay/ws.py); the Python SDK does the same.
    this._url = wsUrl;
    this._token = token;
    this._onMessage = onMessage ?? null;
  }

  async connect(): Promise<void> {
    this._running = true;
    return new Promise<void>((resolve, reject) => {
      this._connectResolve = resolve;
      this._connectReject = reject;
      this._startConnectionLoop();

      // 30s timeout for initial connection
      const timeout = setTimeout(() => {
        this._connectReject = null;
        this._connectResolve = null;
        reject(new Error("WebSocket connection timeout (30s)"));
      }, 30000);

      // Patch resolve to clear timeout
      const origResolve = this._connectResolve;
      this._connectResolve = () => {
        clearTimeout(timeout);
        origResolve?.();
      };
    });
  }

  /**
   * Close the connection, once the relay has answered what was sent.
   *
   * The relay stops reading a socket when it can't write an ack to it, so
   * closing straight after send() loses every frame but the first.
   */
  async disconnect(): Promise<void> {
    await this._allAnswered();
    this._running = false;
    if (this._reconnectTimeout !== null) {
      clearTimeout(this._reconnectTimeout);
      this._reconnectTimeout = null;
    }
    if (this._ws) {
      this._ws.removeAllListeners();
      this._ws.close();
      this._ws = null;
    }
    this._connected = false;
  }

  async send(envelope: Record<string, unknown>): Promise<void> {
    if (!this._ws || this._ws.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket not connected");
    }
    this._ws.send(JSON.stringify(envelope));
    this._unanswered += 1;
  }

  async receive(limit: number = 50): Promise<Record<string, unknown>[]> {
    const result = this._pending.slice(0, limit);
    this._pending = this._pending.slice(limit);
    return result;
  }

  async listen(
    callback: (msg: Record<string, unknown>) => Promise<void>
  ): Promise<void> {
    this._onMessage = callback;
  }

  /** Resolves when nothing is unanswered, or after _settleMs regardless. */
  private _allAnswered(): Promise<void> {
    if (this._unanswered === 0) return Promise.resolve();
    this._settling ??= new Promise<void>((resolve) => {
      const timeout = setTimeout(() => {
        log.warn(`Closing with ${this._unanswered} sends unanswered`);
        this._settled?.();
      }, this._settleMs);
      this._settled = () => {
        clearTimeout(timeout);
        this._settling = null;
        this._settled = null;
        resolve();
      };
    });
    return this._settling;
  }

  private _answered(): void {
    this._unanswered = Math.max(0, this._unanswered - 1);
    if (this._unanswered === 0) this._settled?.();
  }

  private _startConnectionLoop(): void {
    let attempt = 0;

    const tryConnect = () => {
      if (!this._running) return;

      const ws = new WebSocket(this._url, [`bearer.${this._token}`]);
      this._ws = ws;

      ws.on("open", () => {
        this._connected = true;
        attempt = 0; // Reset on successful connection
        if (this._connectResolve) {
          this._connectResolve();
          this._connectResolve = null;
          this._connectReject = null;
        }
      });

      ws.on("message", (data: WebSocket.Data) => {
        try {
          const msg = JSON.parse(data.toString()) as Record<string, unknown>;
          this._handleMessage(msg);
        } catch {
          // Ignore unparseable messages
        }
      });

      ws.on("close", () => {
        this._connected = false;
        this._ws = null;
        // Their answers went with the socket.
        this._unanswered = 0;
        this._settled?.();
        if (!this._running) return;

        attempt += 1;
        const delay = Math.min(BASE_DELAY * Math.pow(2, attempt), MAX_DELAY);
        const jitter = Math.random() * JITTER_RANGE;
        const totalDelay = (delay + jitter) * 1000;

        this._reconnectTimeout = setTimeout(tryConnect, totalDelay);
      });

      ws.on("error", (err: Error) => {
        // On first connect, reject the promise
        if (this._connectReject && !this._connected) {
          // Don't reject immediately; let 'close' handle retry
        }
        // Error will trigger close event
      });
    };

    tryConnect();
  }

  private _handleMessage(msg: Record<string, unknown>): void {
    const msgType = msg["type"] as string | undefined;

    // First: an envelope's type and keys are the sender's to choose.
    if ("uam_version" in msg) {
      if (this._onMessage) {
        this._onMessage(msg).catch(() => {
          // Fire-and-forget callback errors
        });
      } else {
        this._pending.push(msg);
      }
    } else if (msgType === "ping") {
      // Respond to relay heartbeat
      if (this._ws && this._ws.readyState === WebSocket.OPEN) {
        this._ws.send(JSON.stringify({ type: "pong" }));
      }
    } else if (msgType === "ack") {
      this._answered();
    } else if (msgType === "error" || "error" in msg) {
      this._answered();
    }
  }
}
