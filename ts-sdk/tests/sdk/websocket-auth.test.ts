/**
 * WebSocketTransport authenticates with the `bearer.<token>` subprotocol
 * (as the Python SDK does), keeping the token out of the URL and therefore
 * out of server/proxy access logs. Uses a real local ws server.
 */

import { describe, it, expect, afterEach } from "vitest";
import type { AddressInfo } from "node:net";
import { WebSocketServer } from "ws";

import { WebSocketTransport } from "../../src/sdk/transport/websocket.js";

let server: WebSocketServer | null = null;
let transport: WebSocketTransport | null = null;

afterEach(async () => {
  await transport?.disconnect();
  transport = null;
  await new Promise<void>((resolve) => {
    if (server === null) return resolve();
    server.close(() => resolve());
  });
  server = null;
});

async function startServer(): Promise<{
  url: string;
  seen: Promise<{ url: string; protocols: string[] }>;
}> {
  let report!: (v: { url: string; protocols: string[] }) => void;
  const seen = new Promise<{ url: string; protocols: string[] }>(
    (r) => (report = r)
  );
  const s = new WebSocketServer({
    port: 0,
    host: "127.0.0.1",
    // Echo the bearer subprotocol back, as the relay does.
    handleProtocols: (protocols) =>
      [...protocols].find((p) => p.startsWith("bearer.")) ?? false,
  });
  s.on("connection", (_ws, req) => {
    const header = req.headers["sec-websocket-protocol"] ?? "";
    report({
      url: req.url ?? "",
      protocols: String(header)
        .split(",")
        .map((p) => p.trim())
        .filter(Boolean),
    });
  });
  await new Promise<void>((r) => s.on("listening", () => r()));
  server = s;
  const { port } = s.address() as AddressInfo;
  return { url: `ws://127.0.0.1:${port}/ws`, seen };
}

describe("WebSocketTransport auth", () => {
  it("sends the token as a bearer subprotocol, not in the URL", async () => {
    const { url, seen } = await startServer();
    transport = new WebSocketTransport(url, "tok_abc123");

    await transport.connect();
    const req = await seen;

    expect(req.protocols).toEqual(["bearer.tok_abc123"]);
    expect(req.url).toBe("/ws");
    expect(req.url).not.toContain("tok_abc123");
  });
});
