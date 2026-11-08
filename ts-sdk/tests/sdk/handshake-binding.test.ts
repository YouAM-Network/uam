/**
 * Contact cards in handshake.request (and pending approvals) must be bound to
 * the envelope sender. Real agents, real crypto, real ContactBook; only the
 * relay is in memory (see harness.ts).
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";

import {
  sodiumReady,
  MessageType,
  InvalidEnvelopeError,
  fromWireDict,
} from "../../src/protocol/index.js";
import type { Agent } from "../../src/sdk/agent.js";
import {
  FakeRelay,
  makeAgent,
  cleanupAgents,
  cardJson,
  vkOf,
  addr,
  requestWithCard,
} from "./harness.js";

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

// ---------------------------------------------------------------------------
// T1.1 -- contact card must be bound to the envelope sender
// ---------------------------------------------------------------------------

describe("handshake.request card binding", () => {
  it("request card naming another address is rejected", async () => {
    const eve = agent("eve");
    const bob = agent("bob");
    // Eve signs a card claiming Alice's address with her own key, and sends
    // it from her own address.
    const forged = await cardJson(addr("alice"), eve);
    const wire = await requestWithCard(eve, bob, forged);

    await expect(
      bob._handshake.handleInbound(bob, fromWireDict(wire), vkOf(eve))
    ).rejects.toThrow(InvalidEnvelopeError);

    expect(bob._contactBook.isKnown(addr("alice"))).toBe(false);
    expect(bob._contactBook.isKnown(eve.address)).toBe(false);
    // No accept went back.
    expect(relay.sentTypes(bob.address)).toEqual([]);
  });

  it("request card carrying another agent's key is rejected", async () => {
    const eve = agent("eve");
    const bob = agent("bob");
    const carol = agent("carol");
    // Card names Eve's address but is self-signed by Carol's key, so
    // card.publicKey is Carol's key while the envelope is signed by Eve.
    const forged = await cardJson(eve.address, carol);
    const wire = await requestWithCard(eve, bob, forged);

    await expect(
      bob._handshake.handleInbound(bob, fromWireDict(wire), vkOf(eve))
    ).rejects.toThrow(InvalidEnvelopeError);

    expect(bob._contactBook.isKnown(eve.address)).toBe(false);
  });

  it("request card naming another address is not stored as pending (approval-required)", async () => {
    const eve = agent("eve");
    const bob = agent("bob", "approval-required");
    const forged = await cardJson(addr("alice"), eve);
    const wire = await requestWithCard(eve, bob, forged);

    await expect(
      bob._handshake.handleInbound(bob, fromWireDict(wire), vkOf(eve))
    ).rejects.toThrow(InvalidEnvelopeError);

    expect(bob._contactBook.getPending()).toEqual([]);
  });

  it("approve rejects a pending entry whose card was poisoned", async () => {
    const eve = agent("eve");
    const bob = agent("bob", "approval-required");
    // A pending row stored before the request-side binding existed: keyed by
    // Eve's address but carrying a card that claims Alice's address.
    const poisoned = await cardJson(addr("alice"), eve);
    bob._contactBook.addPending(eve.address, JSON.stringify(poisoned));

    await expect(bob.approve(eve.address)).rejects.toThrow(
      InvalidEnvelopeError
    );

    expect(bob._contactBook.isKnown(addr("alice"))).toBe(false);
    expect(bob._contactBook.isKnown(eve.address)).toBe(false);
    expect(relay.sentTypes(bob.address)).toEqual([]);
  });

  it("approve of a well-formed pending entry still works", async () => {
    const alice = agent("alice");
    const bob = agent("bob", "approval-required");
    bob._contactBook.addPending(
      alice.address,
      JSON.stringify(await cardJson(alice.address, alice))
    );

    await bob.approve(alice.address);

    expect(bob._contactBook.getTrustState(alice.address)).toBe("trusted");
    expect(bob._contactBook.getPublicKey(alice.address)).toBe(alice.publicKey);
    expect(relay.sentTypes(bob.address)).toEqual([
      MessageType.HANDSHAKE_ACCEPT,
    ]);
  });
});

