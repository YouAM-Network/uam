/**
 * One bad inbound item must not throw out of inbox() or lose the rest of
 * the batch.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";

import {
  sodiumReady,
  MessageType,
} from "../../src/protocol/index.js";
import type { Agent } from "../../src/sdk/agent.js";
import {
  FakeRelay,
  makeAgent,
  cleanupAgents,
  rawEnvelope,
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
// inbox() must survive one bad message
// ---------------------------------------------------------------------------

describe("inbox() robustness", () => {
  it("malformed request does not break inbox()", async () => {
    const eve = agent("eve");
    const alice = agent("alice");
    const bob = agent("bob");
    bob._contactBook.addContact(alice.address, alice.publicKey, {
      trustState: "trusted",
    });

    // A correctly signed handshake.request whose sealed payload is not a card.
    relay.deliver(
      await rawEnvelope(
        eve,
        bob.address,
        MessageType.HANDSHAKE_REQUEST,
        "this is not json",
        vkOf(bob)
      )
    );
    // A request with a forged card (binding failure).
    relay.deliver(
      await requestWithCard(eve, bob, await cardJson(addr("alice"), eve))
    );
    // Something that is not an envelope at all.
    relay.inject(bob.address, { uam_version: "0.1", garbage: true });
    // A normal message after the bad ones.
    relay.deliver(
      await rawEnvelope(
        alice,
        bob.address,
        MessageType.MESSAGE,
        "still delivered",
        vkOf(bob)
      )
    );

    const msgs = await bob.inbox();

    expect(msgs.map((m) => m.content)).toEqual(["still delivered"]);
    expect(bob._contactBook.isKnown(eve.address)).toBe(false);
  });
});
