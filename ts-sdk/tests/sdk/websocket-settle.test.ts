/**
 * A WebSocket client answers for what it sent before it closes.
 *
 * Once the relay can't write an ack to a closing socket, its server stops
 * reading, so frames still in flight are lost however soon after send() the
 * agent closes. disconnect() therefore waits for the relay's answers. Uses a
 * real local ws server.
 */

import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type WebSocket, WebSocketServer } from "ws";

import {
  SEND_SETTLE_SECONDS,
  WebSocketTransport,
} from "../../src/sdk/transport/websocket.js";

let server: WebSocketServer;
let peer: WebSocket | undefined;
let frames: Array<Record<string, unknown>>;
let closed: boolean;
let transport: WebSocketTransport;

async function until(condition: () => boolean): Promise<void> {
  await vi.waitFor(() => expect(condition()).toBe(true), { timeout: 2000 });
}

/** Long enough for a close that wasn't held back to reach the server. */
const pause = () => new Promise((resolve) => setTimeout(resolve, 50));

/** Fail unless `closing` finishes well inside the settle time. */
async function finishes(closing: Promise<void>): Promise<void> {
  let done = false;
  void closing.then(() => {
    done = true;
  });
  await until(() => done);
}

function answer(frame: Record<string, unknown>): void {
  peer!.send(JSON.stringify(frame));
}

/** Send `count` envelopes and wait for them to reach the server. */
async function sendEnvelopes(count: number): Promise<void> {
  const target = frames.length + count;
  for (let i = 0; i < count; i += 1) {
    await transport.send({ message_id: `m${i}` });
  }
  await until(() => frames.length === target);
}

beforeEach(async () => {
  peer = undefined;
  frames = [];
  closed = false;
  server = new WebSocketServer({
    port: 0,
    host: "127.0.0.1",
    handleProtocols: (protocols) => [...protocols][0] ?? false,
  });
  server.on("connection", (ws) => {
    peer = ws;
    ws.on("message", (data) => frames.push(JSON.parse(data.toString())));
    ws.on("close", () => {
      // The last test's socket can finish closing during this one.
      if (ws === peer) closed = true;
    });
  });
  await new Promise<void>((resolve) => server.on("listening", () => resolve()));
  const { port } = server.address() as AddressInfo;
  transport = new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, "a-token");
  await transport.connect();
  await until(() => peer !== undefined);
});

afterEach(async () => {
  vi.restoreAllMocks();
  for (const client of server.clients) client.terminate();
  await transport.disconnect();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("closing after send()", () => {
  it("waits for every ack before closing", async () => {
    transport._settleMs = 60_000;
    await sendEnvelopes(2);
    const closing = transport.disconnect();

    answer({ type: "ack", message_id: "m0" });
    await pause();
    expect(closed).toBe(false);

    answer({ type: "ack", message_id: "m1" });
    await finishes(closing);
    await until(() => closed);
  });

  it("counts an error frame as an answer", async () => {
    transport._settleMs = 60_000;
    await sendEnvelopes(1);
    const closing = transport.disconnect();
    await pause();
    expect(closed).toBe(false);

    answer({ error: "rate_limited", detail: "slow down" });
    await finishes(closing);
    await until(() => closed);
  });

  it("counts a typed error frame too", async () => {
    transport._settleMs = 60_000;
    await sendEnvelopes(1);
    const closing = transport.disconnect();

    answer({ type: "error", code: "bad" });
    await finishes(closing);
    await until(() => closed);
  });

  it("closes anyway, with a warning, if the relay never answers", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    transport._settleMs = 20;
    await sendEnvelopes(1);

    await transport.disconnect();

    await until(() => closed);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("1 sends unanswered"));
  });

  it("waits five seconds by default", () => {
    expect(SEND_SETTLE_SECONDS).toBe(5);
    expect(transport._settleMs).toBe(5000);
  });

  it("doesn't wait when nothing was sent", async () => {
    transport._settleMs = 60_000;
    await finishes(transport.disconnect());
    await until(() => closed);
  });

  it("doesn't wait once everything is answered", async () => {
    transport._settleMs = 60_000;
    await sendEnvelopes(1);
    answer({ type: "ack", message_id: "m0" });
    await pause();

    await finishes(transport.disconnect());
    await until(() => closed);
  });

  it("doesn't let a stray answer cancel out a later send", async () => {
    transport._settleMs = 60_000;
    answer({ type: "ack", message_id: "stray" });
    await pause();
    await sendEnvelopes(1);

    const closing = transport.disconnect();
    await pause();
    expect(closed).toBe(false);

    answer({ type: "ack", message_id: "m0" });
    await finishes(closing);
  });

  it("releases the wait when the socket drops", async () => {
    transport._settleMs = 60_000;
    await sendEnvelopes(1);
    const closing = transport.disconnect();
    await pause();

    peer!.terminate();
    await finishes(closing);
  });

  it("releases the wait when the relay closes cleanly", async () => {
    transport._settleMs = 60_000;
    await sendEnvelopes(1);
    const closing = transport.disconnect();
    await pause();

    peer!.close();
    await finishes(closing);
  });

  it("forgets what was unanswered when the socket drops", async () => {
    transport._settleMs = 60_000;
    await sendEnvelopes(2);
    peer!.terminate();
    await until(() => closed);
    await pause();

    await finishes(transport.disconnect());
  });

  it.each([
    ["type ack", { uam_version: "0.1", type: "ack", message_id: "m9" }],
    ["type error", { uam_version: "0.1", type: "error", message_id: "m9" }],
    ["an error key", { uam_version: "0.1", type: "message", error: "x", message_id: "m9" }],
  ])("doesn't read an envelope with %s as an answer", async (_name, envelope) => {
    transport._settleMs = 60_000;
    await sendEnvelopes(1);
    const closing = transport.disconnect();

    answer(envelope);
    await pause();
    expect(closed).toBe(false);
    expect(await transport.receive()).toEqual([envelope]);

    answer({ type: "ack", message_id: "m0" });
    await finishes(closing);
  });

  it("queues an envelope with type ping as mail, without a pong", async () => {
    const envelope = { uam_version: "0.1", type: "ping", message_id: "m9" };
    answer(envelope);
    await pause();

    expect(frames).toEqual([]);
    expect(await transport.receive()).toEqual([envelope]);
  });

  it("still answers the relay's own ping", async () => {
    answer({ type: "ping" });
    await until(() => frames.length === 1);
    expect(frames).toEqual([{ type: "pong" }]);
  });

  it("lets two callers close together", async () => {
    transport._settleMs = 60_000;
    await sendEnvelopes(1);
    const closing = [transport.disconnect(), transport.disconnect()];

    answer({ type: "ack", message_id: "m0" });
    await finishes(Promise.all(closing).then(() => undefined));
  });
});
