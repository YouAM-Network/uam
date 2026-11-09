/**
 * Agent.send() says what the relay did with the message.
 *
 * It returns { messageId, status, delivered }. `status` is the relay's word
 * ("pending" when the recipient only takes approved contacts); an answer
 * without a known status comes from an older relay ("accepted"); no answer
 * in time is "unknown". `delivered` is true only when the relay says the
 * recipient has it.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { sodiumReady } from "../../src/protocol/index.js";
import type { Agent } from "../../src/sdk/agent.js";
import {
  PENDING_NOTE,
  SEND_STATUSES,
  pendingNote,
  sendStatus,
  supports,
} from "../../src/sdk/message.js";
import { FakeRelay, cleanupAgents, makeAgent } from "./harness.js";

describe("sendStatus()", () => {
  it.each([
    [null, "unknown"],
    [{}, "accepted"],
    [{ status: "pending" }, "pending"],
    [{ status: "stored", delivered: false }, "stored"],
    [{ status: "delivered" }, "delivered"],
    [{ status: "something-new" }, "accepted"],
    [{ status: "unknown" }, "accepted"],
    [{ status: 7 }, "accepted"],
  ])("reads %j as %s", (answer, status) => {
    expect(sendStatus(answer as Record<string, unknown> | null)).toBe(status);
  });

  it("knows the same statuses as the Python SDK", () => {
    expect([...SEND_STATUSES]).toEqual([
      "delivered", "stored", "relayed", "queued", "duplicate",
      "dropped", "pending", "accepted", "unknown",
    ]);
  });
});

describe("supports()", () => {
  const features = new Set(["send_status", "send_status:2", "inbound_gate"]);

  it("reads a bare name as version 1", () => {
    expect(supports(features, "inbound_gate")).toBe(true);
    expect(supports(features, "inbound_gate", 2)).toBe(false);
  });

  it("reads name:N as version N or later", () => {
    expect(supports(features, "send_status", 2)).toBe(true);
    expect(supports(features, "send_status", 3)).toBe(false);
    expect(supports(new Set(["x:3"]), "x")).toBe(true);
    expect(supports(new Set(["x:3"]), "x", 2)).toBe(true);
  });

  it("ignores a version that isn't a number", () => {
    expect(supports(new Set(["x:two"]), "x", 2)).toBe(false);
  });

  it("is false for a feature the relay doesn't list", () => {
    expect(supports(features, "owner_grants")).toBe(false);
  });
});

describe("the pending note", () => {
  it("names the recipient and says not to resend", () => {
    expect(PENDING_NOTE).toBe(
      "Not delivered: {to} only accepts messages from approved contacts. Do not resend it."
    );
    expect(pendingNote("bob::relay.test")).toBe(
      "Not delivered: bob::relay.test only accepts messages from approved contacts. Do not resend it."
    );
  });
});

describe("Agent.send()", () => {
  let relay: FakeRelay;
  const agents: Agent[] = [];

  function agent(name: string): Agent {
    const a = makeAgent(relay, name);
    agents.push(a);
    return a;
  }

  beforeAll(async () => {
    await sodiumReady;
  });

  beforeEach(() => {
    relay = new FakeRelay();
  });

  afterEach(async () => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    await cleanupAgents(agents);
  });

  it("returns the message id with the relay's status", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    relay.answer = (wire) => ({ message_id: wire["message_id"], status: "pending", delivered: false });

    const result = await alice.send(bob.address, "hello");

    const sent = relay.sent.filter((w) => w["type"] === "message");
    expect(result).toEqual({
      messageId: sent[0]!["message_id"], status: "pending", delivered: false,
    });
  });

  it("is delivered only when the relay says so", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    relay.answer = () => ({ status: "delivered", delivered: true });
    expect((await alice.send(bob.address, "hi")).delivered).toBe(true);

    relay.answer = () => ({ status: "stored", delivered: false });
    expect((await alice.send(bob.address, "hi")).delivered).toBe(false);
  });

  it("is accepted when an older relay answers without a status", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    relay.answer = () => ({});
    expect((await alice.send(bob.address, "hi")).status).toBe("accepted");
  });

  it("is unknown when no answer came in time", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    relay.answer = () => null;
    expect((await alice.send(bob.address, "hi")).status).toBe("unknown");
  });

  it("reads the status from the relay it fails over to", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    vi.spyOn(alice as unknown as { _getRelayUrls: () => Promise<string[]> }, "_getRelayUrls")
      .mockResolvedValue(["https://down.test", "https://up.test"]);
    const fetch = vi.fn(async (url: string) => url.startsWith("https://down.test")
      ? new Response("{}", { status: 503 })
      : new Response(JSON.stringify({ status: "pending", delivered: false })));
    vi.stubGlobal("fetch", fetch);

    const result = await alice.send(bob.address, "hi");

    expect(result.status).toBe("pending");
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
