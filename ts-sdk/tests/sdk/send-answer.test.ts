/**
 * send() hands back what the relay answered.
 *
 * Over HTTP that's the response body; over WebSocket it's the ack that names
 * the message. No answer in time (or the socket going) is null: the message
 * may still have arrived. A refusal that names the message is an error.
 * Uses a real local ws server and a stubbed fetch.
 */

import type { AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type WebSocket, WebSocketServer } from "ws";

import { SendRefusedError } from "../../src/protocol/errors.js";
import { HTTPTransport } from "../../src/sdk/transport/http.js";
import {
  ACK_TIMEOUT_SECONDS,
  WebSocketTransport,
} from "../../src/sdk/transport/websocket.js";

let server: WebSocketServer;
let peer: WebSocket | undefined;
let frames: Array<Record<string, unknown>>;
let transport: WebSocketTransport;

async function until(condition: () => boolean): Promise<void> {
  await vi.waitFor(() => expect(condition()).toBe(true), { timeout: 2000 });
}

const pause = () => new Promise((resolve) => setTimeout(resolve, 50));

function answer(frame: Record<string, unknown>): void {
  peer!.send(JSON.stringify(frame));
}

/**
 * Start a send and wait until its frame reaches the server. The send is
 * wrapped: an async function returning a promise would wait for it.
 */
async function sending(
  id: string
): Promise<{ answered: Promise<Record<string, unknown> | null> }> {
  const target = frames.length + 1;
  const answered = transport.send({ message_id: id });
  answered.catch(() => undefined); // asserted by the caller
  await until(() => frames.length === target);
  return { answered };
}

describe("over WebSocket", () => {
  beforeEach(async () => {
    peer = undefined;
    frames = [];
    server = new WebSocketServer({
      port: 0,
      host: "127.0.0.1",
      handleProtocols: (protocols) => [...protocols][0] ?? false,
    });
    server.on("connection", (ws) => {
      peer = ws;
      ws.on("message", (data) => frames.push(JSON.parse(data.toString())));
    });
    await new Promise<void>((resolve) => server.on("listening", () => resolve()));
    const { port } = server.address() as AddressInfo;
    transport = new WebSocketTransport(`ws://127.0.0.1:${port}/ws`, "a-token");
    transport._settleMs = 20;
    await transport.connect();
    await until(() => peer !== undefined);
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    for (const client of server.clients) client.terminate();
    await transport.disconnect();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("resolves with the ack that names the message", async () => {
    const { answered: pending } = await sending("m1");
    const ack = { type: "ack", message_id: "m1", status: "pending", delivered: false };
    answer(ack);
    expect(await pending).toEqual(ack);
  });

  it("gives each of two sends its own ack, in whatever order they come", async () => {
    const { answered: first } = await sending("m1");
    const { answered: second } = await sending("m2");
    answer({ type: "ack", message_id: "m2", status: "stored" });
    answer({ type: "ack", message_id: "m1", status: "delivered" });

    expect((await first)?.["status"]).toBe("delivered");
    expect((await second)?.["status"]).toBe("stored");
  });

  it("rejects when the relay refuses the message by id", async () => {
    const { answered: pending } = await sending("m1");
    answer({ type: "error", error: "rate_limited", detail: "slow down", message_id: "m1" });

    const err = await pending.then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(SendRefusedError);
    expect(err).toMatchObject({ messageId: "m1", code: "rate_limited", detail: "slow down" });
  });

  it("is null when no answer comes in time", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    transport._ackMs = 30;
    const { answered: pending } = await sending("m1");
    expect(await pending).toBeNull();
  });

  it("is null for an older relay's refusal that names no message", async () => {
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    transport._ackMs = 100;
    const { answered: pending } = await sending("m1");
    answer({ error: "rate_limited", detail: "slow down" });
    expect(await pending).toBeNull();
  });

  it("is null when the socket drops", async () => {
    transport._ackMs = 60_000;
    const { answered: pending } = await sending("m1");
    peer!.terminate();
    expect(await pending).toBeNull();
  });

  it("waits five seconds by default", () => {
    expect(ACK_TIMEOUT_SECONDS).toBe(5);
    expect(transport._ackMs).toBe(5000);
  });

  it("logs a relay notice and doesn't treat it as mail or an answer", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    transport._ackMs = 60_000;
    const { answered: pending } = await sending("m1");

    answer({ type: "relay.notice", message_id: "m0", status: "pending" });
    await pause();
    expect(await transport.receive()).toEqual([]);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("m0"));

    answer({ type: "ack", message_id: "m1", status: "stored" });
    expect((await pending)?.["status"]).toBe("stored");
  });
});

describe("over HTTP", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  function relayAnswers(body: string, status = 200): void {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(body, { status, statusText: "x" }))
    );
  }

  it("resolves with the response body", async () => {
    relayAnswers(JSON.stringify({ message_id: "m1", status: "pending", delivered: false }));
    const http = new HTTPTransport("http://relay.test", "t", "a::relay.test");
    expect(await http.send({ message_id: "m1" })).toEqual({
      message_id: "m1", status: "pending", delivered: false,
    });
  });

  it("is an empty answer when the body isn't JSON", async () => {
    relayAnswers("ok");
    const http = new HTTPTransport("http://relay.test", "t", "a::relay.test");
    expect(await http.send({ message_id: "m1" })).toEqual({});
  });

  it("still throws when the relay refuses it", async () => {
    relayAnswers("{}", 429);
    const http = new HTTPTransport("http://relay.test", "t", "a::relay.test");
    await expect(http.send({ message_id: "m1" })).rejects.toThrow(/429/);
  });
});
