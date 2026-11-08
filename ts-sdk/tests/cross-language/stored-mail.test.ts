/**
 * Stored mail exactly as the Python relay delivers it: its relay_meta stamp
 * and its /api/v1/versions answer, a day after the message was signed.
 * Regenerate the fixture with generate-stored-mail-fixture.py.
 *
 * The relay's domain (test.local) differs from the hostname in the agent's
 * relay URL, as youam.network does from relay.youam.network.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { sodiumReady } from "../../src/protocol/index.js";
import type { Agent } from "../../src/sdk/agent.js";
import type { PersistentReplayCache } from "../../src/sdk/replay-cache.js";
import { FakeRelay, addr, cleanupAgents, makeAgent } from "../sdk/harness.js";

const fixture = JSON.parse(
  readFileSync(resolve(__dirname, "fixtures/python-stored-mail.json"), "utf-8")
) as {
  alice_address: string;
  alice_verify_key_b64: string;
  bob_address: string;
  bob_seed_b64: string;
  stored: Record<string, unknown>;
  versions: unknown;
};

const HOUR = 3_600_000;
const signedAt = Date.parse(fixture.stored["timestamp"] as string);
const agents: Agent[] = [];

function setClock(a: Agent, now: number): void {
  (a as unknown as { _clock: () => number })._clock = () => now;
}

async function bobOnTheRelay(relay: FakeRelay): Promise<Agent> {
  process.env["UAM_SIGNING_KEY"] = fixture.bob_seed_b64;
  try {
    const bob = makeAgent(relay, "bob");
    agents.push(bob);
    (bob as unknown as { _address: string })._address = fixture.bob_address;
    return bob;
  } finally {
    delete process.env["UAM_SIGNING_KEY"];
  }
}

beforeAll(async () => {
  await sodiumReady;
});

afterEach(async () => {
  vi.unstubAllGlobals();
  await cleanupAgents(agents);
});

describe("stored mail from the Python relay", () => {
  it("is delivered a day later, once", async () => {
    vi.stubGlobal(
      "fetch",
      async () => new Response(JSON.stringify(fixture.versions))
    );
    const relay = new FakeRelay();
    relay.keys.set(fixture.alice_address, fixture.alice_verify_key_b64);
    const bob = await bobOnTheRelay(relay);

    setClock(bob, signedAt - HOUR);
    await (
      bob as unknown as { _replayCache: PersistentReplayCache }
    )._replayCache.createdAt();
    setClock(bob, signedAt + 24 * HOUR);

    relay.inject(addr("bob"), fixture.stored);
    const received = await bob.inbox();
    expect(received.map((m) => m.content)).toEqual(["hello from yesterday"]);

    relay.inject(addr("bob"), fixture.stored);
    expect(await bob.inbox()).toEqual([]);
  });
});
