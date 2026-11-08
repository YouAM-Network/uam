/**
 * receipt.read names the message it answers in reply_to (signed, visible
 * to the relay), so the relay can bind the receipt to a message it routed.
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";

import {
  sodiumReady,
  MessageType,
  fromWireDict,
  verifyEnvelope,
} from "../../src/protocol/index.js";
import type { Agent } from "../../src/sdk/agent.js";
import { FakeRelay, makeAgent, cleanupAgents, rawEnvelope, vkOf } from "./harness.js";

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
  await cleanupAgents(agents);
});

describe("receipt.read", () => {
  it("names the message read in reply_to", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    bob._contactBook.addContact(alice.address, alice.publicKey, {
      trustState: "trusted",
    });

    const wire = await rawEnvelope(alice, bob.address, MessageType.MESSAGE, "hi", vkOf(bob));
    relay.deliver(wire);

    await bob.inbox();

    const receipts = relay
      .sentBy(bob.address)
      .filter((w) => w["type"] === MessageType.RECEIPT_READ);
    expect(receipts).toHaveLength(1);
    expect(receipts[0]!["reply_to"]).toBe(wire["message_id"]);
    // reply_to is covered by the signature
    expect(() => verifyEnvelope(fromWireDict(receipts[0]!), vkOf(bob))).not.toThrow();
  });
});
