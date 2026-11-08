/**
 * Inbound envelope checks in Agent._processInbound, after signature
 * verification: recipient, freshness, expiry, then replay (recorded last).
 */

import { describe, it, expect, beforeAll, beforeEach, afterEach } from "vitest";

import {
  sodiumReady,
  MessageType,
  MAX_ENVELOPE_AGE,
} from "../../src/protocol/index.js";
import type { Agent } from "../../src/sdk/agent.js";
import {
  FakeRelay,
  makeAgent,
  cleanupAgents,
  rawEnvelope,
  vkOf,
  addr,
  cardJson,
  requestWithCard,
} from "./harness.js";

let relay: FakeRelay;
const agents: Agent[] = [];

function agent(name: string): Agent {
  const a = makeAgent(relay, name);
  agents.push(a);
  return a;
}

/** Shift `a`'s clock by `offsetMs` relative to real time. */
function skewClock(a: Agent, offsetMs: number): void {
  (a as unknown as { _clock: () => number })._clock = () =>
    Date.now() + offsetMs;
}

async function messageTo(
  from: Agent,
  to: Agent,
  text: string,
  options?: { toAddress?: string; expires?: string }
) {
  return rawEnvelope(
    from,
    options?.toAddress ?? to.address,
    MessageType.MESSAGE,
    text,
    vkOf(to),
    options?.expires !== undefined ? { expires: options.expires } : undefined
  );
}

async function contents(a: Agent): Promise<string[]> {
  return (await a.inbox()).map((m) => m.content);
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

describe("recipient check", () => {
  it("envelope addressed to someone else dropped", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    // Signed for Carol, but handed to Bob (e.g. a relay or a peer
    // forwarding a copy).
    relay.inject(
      bob.address,
      await messageTo(alice, bob, "for carol", { toAddress: addr("carol") })
    );

    expect(await contents(bob)).toEqual([]);
  });

  it("envelope addressed to us is delivered", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    relay.deliver(await messageTo(alice, bob, "for bob"));

    expect(await contents(bob)).toEqual(["for bob"]);
  });
});

describe("freshness check", () => {
  it("MAX_ENVELOPE_AGE is 300 seconds", () => {
    expect(MAX_ENVELOPE_AGE).toBe(300);
  });

  it("stale envelope dropped", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    relay.deliver(await messageTo(alice, bob, "old"));
    skewClock(bob, (MAX_ENVELOPE_AGE + 1) * 1000);

    expect(await contents(bob)).toEqual([]);
  });

  it("future-dated envelope dropped", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    relay.deliver(await messageTo(alice, bob, "from the future"));
    skewClock(bob, -(MAX_ENVELOPE_AGE + 1) * 1000);

    expect(await contents(bob)).toEqual([]);
  });

  it("envelope inside the window is delivered", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    relay.deliver(await messageTo(alice, bob, "recent"));
    skewClock(bob, (MAX_ENVELOPE_AGE - 5) * 1000);

    expect(await contents(bob)).toEqual(["recent"]);
  });
});

describe("expiry check", () => {
  it("expired envelope dropped", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    const expires = new Date(Date.now() - 1000).toISOString();
    relay.deliver(await messageTo(alice, bob, "expired", { expires }));

    expect(await contents(bob)).toEqual([]);
  });

  it("envelope with a malformed expires dropped", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    relay.deliver(
      await messageTo(alice, bob, "bad expiry", { expires: "not-a-date" })
    );

    expect(await contents(bob)).toEqual([]);
  });

  it("envelope that has not expired is delivered", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    const expires = new Date(Date.now() + 60_000).toISOString();
    relay.deliver(await messageTo(alice, bob, "still valid", { expires }));

    expect(await contents(bob)).toEqual(["still valid"]);
  });
});

describe("replay check", () => {
  it("replayed envelope delivered once (same batch)", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    const wire = await messageTo(alice, bob, "once");
    relay.deliver(wire);
    relay.deliver({ ...wire });

    expect(await contents(bob)).toEqual(["once"]);
  });

  it("replayed envelope delivered once (later inbox call)", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    const wire = await messageTo(alice, bob, "once");
    relay.deliver(wire);
    expect(await contents(bob)).toEqual(["once"]);

    relay.deliver({ ...wire });
    expect(await contents(bob)).toEqual([]);
  });

  it("replayed handshake.request is processed once", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    const wire = await requestWithCard(
      alice,
      bob,
      await cardJson(alice.address, alice)
    );
    relay.deliver(wire);
    relay.deliver({ ...wire });

    await bob.inbox();

    expect(relay.sentTypes(bob.address)).toEqual([
      MessageType.HANDSHAKE_ACCEPT,
    ]);
  });

  it("an envelope rejected as stale is not recorded as seen", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    const wire = await messageTo(alice, bob, "retry me");
    relay.deliver(wire);
    skewClock(bob, (MAX_ENVELOPE_AGE + 1) * 1000);
    expect(await contents(bob)).toEqual([]);

    skewClock(bob, 0);
    relay.deliver({ ...wire });
    expect(await contents(bob)).toEqual(["retry me"]);
  });

  it("an envelope with a bad signature does not burn the message id", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    const wire = await messageTo(alice, bob, "genuine");
    // Same message id, different (unsigned) content.
    relay.deliver({ ...wire, thread_id: "tampered" });
    relay.deliver(wire);

    expect(await contents(bob)).toEqual(["genuine"]);
  });

  it("an envelope addressed elsewhere does not burn the message id", async () => {
    const alice = agent("alice");
    const bob = agent("bob");
    const carolWire = await messageTo(alice, bob, "x", {
      toAddress: addr("carol"),
    });
    relay.inject(bob.address, carolWire);
    expect(await contents(bob)).toEqual([]);

    const replay = (
      bob as unknown as {
        _replayCache: {
          seenOrRecord(f: string, m: string, signedAt: number): Promise<boolean>;
        };
      }
    )._replayCache;
    expect(
      await replay.seenOrRecord(
        alice.address,
        carolWire["message_id"] as string,
        Date.now()
      )
    ).toBe(false);
  });
});

describe("replay cache capacity", () => {
  it("reads UAM_REPLAY_CACHE_CAPACITY", () => {
    process.env["UAM_REPLAY_CACHE_CAPACITY"] = "7";
    try {
      const a = agent("alice");
      const cache = (a as unknown as { _replayCache: { capacity: number } })
        ._replayCache;
      expect(cache.capacity).toBe(7);
    } finally {
      delete process.env["UAM_REPLAY_CACHE_CAPACITY"];
    }
  });

  it("defaults to 1000000", () => {
    const a = agent("alice");
    const cache = (a as unknown as { _replayCache: { capacity: number } })
      ._replayCache;
    expect(cache.capacity).toBe(1_000_000);
  });
});
