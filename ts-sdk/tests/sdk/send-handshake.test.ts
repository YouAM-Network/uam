/**
 * send() fires a handshake.request whenever the recipient is not already in
 * a confirmed (pinned/verified/trusted) or in-flight (handshake-sent) state,
 * and resolving the recipient's key never writes to the contact book.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";

import { sodiumReady, MessageType } from "../../src/protocol/index.js";
import type { Agent } from "../../src/sdk/agent.js";
import { FakeRelay, makeAgent, cleanupAgents } from "./harness.js";

let relay: FakeRelay;
const agents: Agent[] = [];

function agent(name: string, trustPolicy?: string): Agent {
  const a = makeAgent(relay, name, { trustPolicy });
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
  await cleanupAgents(agents);
});

describe("first-contact handshake on send()", () => {
  it("first send to an unknown contact fires a handshake.request", async () => {
    const alice = agent("alice");
    const bob = agent("bob");

    await alice.send(bob.address, "hello");

    expect(relay.sentTypes(alice.address)).toEqual([
      MessageType.HANDSHAKE_REQUEST,
      MessageType.MESSAGE,
    ]);
    expect(alice._contactBook.getTrustState(bob.address)).toBe(
      "handshake-sent"
    );
  });

  it("resolving a recipient's key does not write a provisional contact", async () => {
    const alice = agent("alice");
    const bob = agent("bob");

    const resolve = (
      alice as unknown as {
        _resolvePublicKey(a: string): Promise<Uint8Array>;
      }
    )._resolvePublicKey.bind(alice);
    await resolve(bob.address);

    expect(alice._contactBook.isKnown(bob.address)).toBe(false);
    expect(alice._contactBook.getTrustState(bob.address)).toBeNull();
  });

  it("send to a provisional contact fires a handshake.request", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    alice._contactBook.addContact(bob.address, bob.publicKey, {
      trustState: "provisional",
    });

    await alice.send(bob.address, "hello");

    expect(relay.sentTypes(alice.address)).toEqual([
      MessageType.HANDSHAKE_REQUEST,
      MessageType.MESSAGE,
    ]);
  });

  it("second send while a handshake is in flight does not re-fire it", async () => {
    const alice = agent("alice");
    const bob = agent("bob");

    await alice.send(bob.address, "one");
    await alice.send(bob.address, "two");

    expect(relay.sentTypes(alice.address)).toEqual([
      MessageType.HANDSHAKE_REQUEST,
      MessageType.MESSAGE,
      MessageType.MESSAGE,
    ]);
  });

  for (const state of ["pinned", "verified", "trusted"]) {
    it(`send to a ${state} contact does not fire a handshake`, async () => {
      const alice = agent("alice");
      const bob = agent("bob");
      alice._contactBook.addContact(bob.address, bob.publicKey, {
        trustState: state,
      });

      await alice.send(bob.address, "hello");

      expect(relay.sentTypes(alice.address)).toEqual([MessageType.MESSAGE]);
    });
  }

  it("full handshake: first send pins the recipient once the accept arrives", async () => {
    const alice = agent("alice");
    const bob = agent("bob");

    await alice.send(bob.address, "hello bob");
    expect(alice._contactBook.getTrustState(bob.address)).toBe(
      "handshake-sent"
    );

    const bobInbox = await bob.inbox();
    expect(bobInbox.map((m) => m.content)).toEqual(["hello bob"]);
    expect(bob._contactBook.getTrustState(alice.address)).toBe("provisional");

    await alice.inbox();
    expect(alice._contactBook.getTrustState(bob.address)).toBe("pinned");
    expect(alice._contactBook.getPublicKey(bob.address)).toBe(bob.publicKey);
  });
});
