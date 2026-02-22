/**
 * WebSocket transport with exponential backoff and jitter (SDK-05).
 *
 * Maintains a persistent connection to the relay, automatically
 * reconnecting on disconnection with exponential backoff plus
 * random jitter to prevent thundering herd.
 */

import WebSocket from "ws";
import { TransportBase } from "./base.js";

// Reconnection constants
const BASE_DELAY = 1.0; // Initial delay in seconds
const MAX_DELAY = 60.0; // Maximum delay cap
const JITTER_RANGE = 1.0; // Random jitter 0 to JITTER_RANGE

export class WebSocketTransport extends TransportBase {
  private _url: string;
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

  constructor(
    wsUrl: string,
    token: string,
    onMessage?: (msg: Record<string, unknown>) => Promise<void>
  ) {
    super();
    this._url = `${wsUrl}?token=${token}`;
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

  async disconnect(): Promise<void> {
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

  private _startConnectionLoop(): void {
    let attempt = 0;

    const tryConnect = () => {
      if (!this._running) return;

      const ws = new WebSocket(this._url);
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

    if (msgType === "ping") {
      // Respond to relay heartbeat
      if (this._ws && this._ws.readyState === WebSocket.OPEN) {
        this._ws.send(JSON.stringify({ type: "pong" }));
      }
    } else if (msgType === "ack") {
      // Acknowledgment -- log silently
    } else if (msgType === "error" || "error" in msg) {
      // Relay error -- log silently
    } else if ("uam_version" in msg) {
      // Inbound envelope
      if (this._onMessage) {
        this._onMessage(msg).catch(() => {
          // Fire-and-forget callback errors
        });
      } else {
        this._pending.push(msg);
      }
    }
  }
}
