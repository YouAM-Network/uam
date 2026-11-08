/**
 * handshake.accept is honoured only after we sent a request, and only once
 * its payload decrypts and any embedded card is valid and bound to the
 * sender. Real agents, real crypto, real ContactBook (see harness.ts).
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";

import {
  sodiumReady,
} from "../../src/protocol/index.js";
import type { Agent } from "../../src/sdk/agent.js";
import {
  FakeRelay,
  makeAgent,
  cleanupAgents,
  cardJson,
  vkOf,
  addr,
  acceptWithPayload,
  markHandshakeSent,
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
// T1.2 -- handshake.accept only after we sent a request; decrypt + bind
// ---------------------------------------------------------------------------

describe("handshake.accept gating", () => {
  it("unsolicited handshake.accept does not pin the sender", async () => {
    const eve = agent("eve");
    const bob = agent("bob");
    // Bob never sent Eve a request.
    relay.deliver(
      await acceptWithPayload(eve, bob, {
        status: "accepted",
        contact_card: await cardJson(eve.address, eve),
      })
    );

    await bob.inbox();

    expect(bob._contactBook.getTrustState(eve.address)).toBeNull();
  });

  it("accept whose card names a different address is rejected", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    markHandshakeSent(alice, bob);
    relay.deliver(
      await acceptWithPayload(bob, alice, {
        status: "accepted",
        contact_card: await cardJson(addr("carol"), bob),
      })
    );

    await alice.inbox();

    expect(alice._contactBook.getTrustState(bob.address)).toBe(
      "handshake-sent"
    );
    expect(alice._contactBook.isKnown(addr("carol"))).toBe(false);
  });

  it("accept whose card carries a different key is rejected", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    const carol = agent("carol");
    markHandshakeSent(alice, bob);
    relay.deliver(
      await acceptWithPayload(bob, alice, {
        status: "accepted",
        contact_card: await cardJson(bob.address, carol),
      })
    );

    await alice.inbox();

    expect(alice._contactBook.getTrustState(bob.address)).toBe(
      "handshake-sent"
    );
  });

  it("accept whose card signature is invalid is rejected", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    markHandshakeSent(alice, bob);
    const card = await cardJson(bob.address, bob);
    card["display_name"] = "tampered after signing";
    relay.deliver(
      await acceptWithPayload(bob, alice, {
        status: "accepted",
        contact_card: card,
      })
    );

    await alice.inbox();

    expect(alice._contactBook.getTrustState(bob.address)).toBe(
      "handshake-sent"
    );
  });

  it("accept that cannot be decrypted does not pin the sender", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    const carol = agent("carol");
    markHandshakeSent(alice, bob);
    // Signed by Bob and addressed to Alice, but encrypted to Carol's key.
    relay.deliver(
      await acceptWithPayload(
        bob,
        alice,
        { status: "accepted", contact_card: await cardJson(bob.address, bob) },
        vkOf(carol)
      )
    );

    await alice.inbox();

    expect(alice._contactBook.getTrustState(bob.address)).toBe(
      "handshake-sent"
    );
  });

  it("solicited accept with a valid bound card pins the sender", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    markHandshakeSent(alice, bob);
    relay.deliver(
      await acceptWithPayload(bob, alice, {
        status: "accepted",
        contact_card: await cardJson(bob.address, bob),
      })
    );

    await alice.inbox();

    expect(alice._contactBook.getTrustState(bob.address)).toBe("pinned");
    expect(alice._contactBook.getPublicKey(bob.address)).toBe(bob.publicKey);
  });

  it("solicited accept without a card still pins (older peers)", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    markHandshakeSent(alice, bob);
    relay.deliver(await acceptWithPayload(bob, alice, { status: "accepted" }));

    await alice.inbox();

    expect(alice._contactBook.getTrustState(bob.address)).toBe("pinned");
  });

  it("accept never downgrades a trusted contact to pinned", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    alice._contactBook.addContact(bob.address, bob.publicKey, {
      trustState: "trusted",
      trustSource: "explicit-approval",
    });
    relay.deliver(
      await acceptWithPayload(bob, alice, {
        status: "accepted",
        contact_card: await cardJson(bob.address, bob),
      })
    );

    await alice.inbox();

    expect(alice._contactBook.getTrustState(bob.address)).toBe("trusted");
  });
});

