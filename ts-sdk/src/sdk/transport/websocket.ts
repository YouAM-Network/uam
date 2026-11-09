/**
 * WebSocket transport with exponential backoff and jitter (SDK-05).
 *
 * Maintains a persistent connection to the relay, automatically
 * reconnecting on disconnection with exponential backoff plus
 * random jitter to prevent thundering herd.
 */

import WebSocket from "ws";
import { SendRefusedError } from "../../protocol/errors.js";
import { log } from "../log.js";
import { TransportBase } from "./base.js";

// Reconnection constants
const BASE_DELAY = 1.0; // Initial delay in seconds
const MAX_DELAY = 60.0; // Maximum delay cap
const JITTER_RANGE = 1.0; // Random jitter 0 to JITTER_RANGE

/** How long a close waits for the relay to answer sends, in seconds. */
export const SEND_SETTLE_SECONDS = 5;

/** How long send() waits for the relay's answer, in seconds. */
export const ACK_TIMEOUT_SECONDS = 5;

type Answer = Record<string, unknown> | null;

interface Waiting {
  resolve: (answer: Answer) => void;
  reject: (err: Error) => void;
}

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
  /** Sends waiting for the relay's answer, by message_id. */
  private _waiting = new Map<string, Waiting>();

  /** @internal How long a close waits, in ms. Replaceable in tests. */
  _settleMs: number = SEND_SETTLE_SECONDS * 1000;

  /** @internal How long send() waits for an answer, in ms. Replaceable in tests. */
  _ackMs: number = ACK_TIMEOUT_SECONDS * 1000;

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
    this._abandonWaiting();
  }

  /**
   * Send an envelope and wait for the relay's answer.
   *
   * Resolves with the ack that names the message, or null when none came
   * within _ackMs or the socket went: the message may still have arrived.
   * Rejects with SendRefusedError when the relay refuses it by message_id
   * (relays before 1.1 don't name it, so their refusals end as null).
   */
  async send(envelope: Record<string, unknown>): Promise<Answer> {
    if (!this._ws || this._ws.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket not connected");
    }
    const messageId = envelope["message_id"];
    let answer: Promise<Answer> | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    if (typeof messageId === "string" && !this._waiting.has(messageId)) {
      // Registered first: the ack can arrive before ws.send returns.
      answer = new Promise<Answer>((resolve, reject) => {
        this._waiting.set(messageId, { resolve, reject });
        timer = setTimeout(() => {
          log.warn(
            `No answer from the relay for ${messageId} within ${this._ackMs / 1000}s`
          );
          this._settle(messageId, null);
        }, this._ackMs);
      });
    }
    this._ws.send(JSON.stringify(envelope));
    this._unanswered += 1;
    if (answer === null) return null;
    try {
      return await answer;
    } finally {
      clearTimeout(timer);
    }
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

  /** Hand the relay's answer (or a refusal) to the send waiting for it. */
  private _settle(messageId: unknown, answer: Answer, error?: Error): void {
    if (typeof messageId !== "string") return;
    const waiting = this._waiting.get(messageId);
    if (!waiting) return;
    this._waiting.delete(messageId);
    if (error) waiting.reject(error);
    else waiting.resolve(answer);
  }

  /** The socket went: no answers will come for what it carried. */
  private _abandonWaiting(): void {
    const waiting = [...this._waiting.values()];
    this._waiting.clear();
    for (const w of waiting) w.resolve(null);
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
        this._abandonWaiting();
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
      this._settle(msg["message_id"], msg);
    } else if (msgType === "relay.notice") {
      // A message the relay had queued for another relay won't be
      // delivered after all (e.g. the recipient only takes approved
      // contacts). Not an answer to a send in flight.
      log.warn(
        `Relay notice: message ${String(msg["message_id"])} is ${String(msg["status"])}`
      );
    } else if (msgType === "error" || "error" in msg) {
      this._answered();
      const code = String(msg["error"] ?? msg["code"] ?? "error");
      const detail = typeof msg["detail"] === "string" ? msg["detail"] : undefined;
      log.warn(`Relay error: [${code}] ${detail ?? ""}`.trimEnd());
      const messageId = msg["message_id"];
      if (typeof messageId === "string") {
        this._settle(messageId, null, new SendRefusedError(messageId, code, detail));
      }
    }
  }
}
