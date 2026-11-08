/**
 * Stored mail: signed while the recipient was away, delivered later.
 *
 * The signed timestamp alone can't tell such a message from an old one sent
 * again. The relay's stamp can, and the SDK believes it only when all of this
 * holds:
 *
 * - the relay is the recipient's own and says it writes these stamps;
 * - the stamp says the message was stored, and that the relay received it
 *   within MAX_ENVELOPE_AGE of the signed time;
 * - the message is at most a week old, and not older than the replay cache.
 */

import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import {
  MAX_ENVELOPE_AGE,
  MessageType,
  sodiumReady,
} from "../../src/protocol/index.js";
import { Agent } from "../../src/sdk/agent.js";
import {
  RELAY_META_FEATURE,
  STORED_MAIL_MAX_AGE,
  relayVouches,
} from "../../src/sdk/freshness.js";
import type { PersistentReplayCache } from "../../src/sdk/replay-cache.js";

import {
  DOMAIN,
  FakeRelay,
  RELAY_URL,
  addr,
  cleanupAgents,
  makeAgent,
  rawEnvelope,
  vkOf,
} from "./harness.js";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

type Wire = Record<string, unknown>;

let relay: FakeRelay;
const agents: Agent[] = [];
let alice: Agent;
let bob: Agent;
/** What GET /api/v1/versions answers; a function may throw or build a Response. */
let versions: () => Response;
let versionRequests: string[];
let monotonic: number;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status });
}

function agent(name: string): Agent {
  const a = makeAgent(relay, name);
  agents.push(a);
  return a;
}

function setClock(a: Agent, offsetMs: number): void {
  (a as unknown as { _clock: () => number })._clock = () =>
    Date.now() + offsetMs;
}

function replayCache(a: Agent): PersistentReplayCache {
  return (a as unknown as { _replayCache: PersistentReplayCache })._replayCache;
}

/** Move bob's monotonic clock on by `ms`. */
function passTime(ms: number): void {
  monotonic += ms;
}

/** Create bob's replay cache `ago` ms before now. */
async function cacheCreated(a: Agent, ago: number): Promise<void> {
  setClock(a, -ago);
  await replayCache(a).createdAt();
  setClock(a, 0);
}

function stamp(wire: Wire, changes?: Record<string, unknown>): Wire {
  return {
    ...wire,
    relay_meta: {
      v: 1,
      relay: DOMAIN,
      received_at: wire["timestamp"],
      stored: true,
      ...changes,
    },
  };
}

async function message(text = "hello", options?: { expires?: string }): Promise<Wire> {
  return rawEnvelope(alice, bob.address, MessageType.MESSAGE, text, vkOf(bob), options);
}

/** Hand bob `wire` as his relay would, `later` ms after it was signed. */
async function deliver(wire: Wire, later: number = DAY): Promise<string[]> {
  setClock(bob, later);
  relay.inject(addr("bob"), wire);
  return (await bob.inbox()).map((m) => m.content);
}

beforeAll(async () => {
  await sodiumReady;
});

beforeEach(async () => {
  relay = new FakeRelay();
  alice = agent("alice");
  bob = agent("bob");
  await cacheCreated(bob, 30 * DAY);
  monotonic = 1000;
  (bob as unknown as { _monotonic: () => number })._monotonic = () => monotonic;
  versions = () => json({ features: [RELAY_META_FEATURE] });
  versionRequests = [];
  vi.stubGlobal("fetch", async (input: string | URL) => {
    const url = String(input);
    if (url.endsWith("/api/v1/versions")) {
      versionRequests.push(url);
      return versions();
    }
    return json({ detail: "not found" }, 404);
  });
});

afterEach(async () => {
  vi.unstubAllGlobals();
  await cleanupAgents(agents);
});

describe("stored mail", () => {
  it("is accepted a day after it was signed", async () => {
    expect(await deliver(stamp(await message()))).toEqual(["hello"]);
  });

  it("is accepted only once", async () => {
    const wire = stamp(await message());
    expect(await deliver(wire)).toEqual(["hello"]);
    expect(await deliver(wire)).toEqual([]);
  });

  it("is still recognised after the agent restarts", async () => {
    const wire = stamp(await message());
    expect(await deliver(wire)).toEqual(["hello"]);

    await replayCache(bob).close();
    expect(await deliver(wire, 2 * DAY)).toEqual([]);
  });

  it("is recorded under the data dir, where the Python SDK looks", async () => {
    await deliver(stamp(await message()));
    expect(existsSync(join(bob._config.dataDir, "replay", "replay.db"))).toBe(true);
  });

  it("is refused without a stamp", async () => {
    expect(await deliver(await message())).toEqual([]);
  });

  it("is refused once its own expiry has passed", async () => {
    const expires = new Date(Date.now() + HOUR).toISOString();
    expect(await deliver(stamp(await message("hello", { expires })))).toEqual([]);
  });

  it("is refused when older than the replay cache", async () => {
    bob = agent("bob");
    await cacheCreated(bob, -HOUR); // created after the message is signed
    expect(await deliver(stamp(await message()))).toEqual([]);
  });

  it("does not ask the relay when the message is fresh", async () => {
    expect(await deliver(stamp(await message()), 0)).toEqual(["hello"]);
    expect(versionRequests).toEqual([]);
  });

  it("names the relay by the signed address, not the configured one", async () => {
    const own = "bob::youam.test";
    (bob as unknown as { _address: string })._address = own;
    const sign = () =>
      rawEnvelope(alice, own, MessageType.MESSAGE, "hello", vkOf(bob));

    expect(await deliver(stamp(await sign(), { relay: "youam.test" }))).toEqual([
      "hello",
    ]);
    expect(await deliver(stamp(await sign(), { relay: DOMAIN }))).toEqual([]);
  });
});

describe("a stamp the relay may not have written", () => {
  it("is not believed when the relay doesn't write stamps", async () => {
    versions = () => json({ features: [] });
    expect(await deliver(stamp(await message()))).toEqual([]);
  });

  it("is not believed when the relay can't be reached", async () => {
    versions = () => {
      throw new TypeError("fetch failed");
    };
    expect(await deliver(stamp(await message()))).toEqual([]);
  });

  it("is not believed when the relay answers with an error", async () => {
    versions = () => json({ features: [RELAY_META_FEATURE] }, 503);
    expect(await deliver(stamp(await message()))).toEqual([]);
  });

  it.each([
    ["a null list", { features: null }],
    ["a string", { features: RELAY_META_FEATURE }],
    ["no list", {}],
    ["a bare list", [RELAY_META_FEATURE]],
    ["null", null],
  ])("is not believed when features is %s", async (_name, body) => {
    versions = () => json(body);
    expect(await deliver(stamp(await message()))).toEqual([]);
  });

  it("is not believed when the answer isn't JSON", async () => {
    versions = () => new Response("<html>");
    expect(await deliver(stamp(await message()))).toEqual([]);
  });

  it("remembers a no for 60 seconds, then asks again", async () => {
    versions = () => json({ features: [] });
    for (const text of ["one", "two"]) {
      expect(await deliver(stamp(await message(text)))).toEqual([]);
    }
    passTime(59_999);
    expect(await deliver(stamp(await message("three")))).toEqual([]);
    expect(versionRequests).toHaveLength(1);

    versions = () => json({ features: [RELAY_META_FEATURE] });
    passTime(1);
    expect(await deliver(stamp(await message("four")))).toEqual(["four"]);
    expect(versionRequests).toHaveLength(2);
  });

  it("times the no by the monotonic clock, not the wall clock", async () => {
    versions = () => json({ features: [] });
    await deliver(stamp(await message("one")));
    await deliver(stamp(await message("two")), DAY + HOUR);
    expect(versionRequests).toHaveLength(1);
  });

  it.each([
    ["a null list", () => json({ features: null })],
    ["not JSON", () => new Response("<html>")],
  ])("remembers a malformed body (%s) as a no", async (_name, answer) => {
    versions = answer;
    await deliver(stamp(await message("one")));
    await deliver(stamp(await message("two")));
    expect(versionRequests).toHaveLength(1);
  });

  it.each([
    [
      "an unreachable relay",
      () => {
        throw new TypeError("fetch failed");
      },
    ],
    ["an error status", () => json({ detail: "busy" }, 503)],
    [
      "a connection lost in the body",
      () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.error(new TypeError("terminated"));
            },
          })
        ),
    ],
  ])("does not remember %s, so the next message asks", async (_name, answer) => {
    const wire = stamp(await message());
    versions = answer;
    expect(await deliver(wire)).toEqual([]);

    versions = () => json({ features: [RELAY_META_FEATURE] });
    expect(await deliver(wire)).toEqual(["hello"]);
    expect(versionRequests).toHaveLength(2);
  });

  it("asks only once a yes is known", async () => {
    for (const text of ["one", "two", "three"]) {
      await deliver(stamp(await message(text)));
    }
    expect(versionRequests).toHaveLength(1);
  });

  it("asks at the relay URL without its trailing slash", async () => {
    bob = makeAgent(relay, "bob", { relay: `${RELAY_URL}/` });
    agents.push(bob);
    await cacheCreated(bob, 30 * DAY);
    await deliver(stamp(await message()));
    expect(versionRequests).toEqual([`${RELAY_URL}/api/v1/versions`]);
  });

  it("does not ask the relay when the stamp fails on its own", async () => {
    expect(await deliver(stamp(await message(), { stored: false }))).toEqual([]);
    expect(versionRequests).toEqual([]);
  });
});

describe("a new agent's replay cache", () => {
  const relayDomain = "youam.test";
  let keyHome: string;
  let registered: boolean[];
  let previousHome: string | undefined;

  beforeEach(() => {
    keyHome = mkdtempSync(join(tmpdir(), "uam-new-agent-"));
    registered = [];
    previousHome = process.env["UAM_HOME"];
    process.env["UAM_HOME"] = keyHome;
  });

  afterEach(() => {
    process.env["UAM_HOME"] = previousHome;
    rmSync(keyHome, { recursive: true, force: true });
  });

  function newAgent(): Agent {
    return new Agent("carol", {
      relay: RELAY_URL,
      keyDir: join(keyHome, "keys"),
      transport: "http",
    });
  }

  function stubRelay(inboxMail: () => Wire[]): void {
    vi.stubGlobal("fetch", async (input: string | URL) => {
      const url = String(input);
      if (url.endsWith("/api/v1/register")) {
        registered.push(existsSync(join(keyHome, "replay", "replay.db")));
        return json({
          address: `carol::${relayDomain}`,
          token: "a-token",
          relay: "ws://relay.test/ws",
        });
      }
      if (url.endsWith("/api/v1/versions")) {
        return json({ features: [RELAY_META_FEATURE] });
      }
      if (url.includes("/api/v1/inbox/")) return json({ messages: inboxMail() });
      return json({ detail: "not found" }, 404);
    });
  }

  it("exists before the agent registers", async () => {
    stubRelay(() => []);
    const carol = newAgent();
    await carol.connect();
    await carol.close();
    expect(registered).toEqual([true]);
  });

  it("covers mail that waits for the agent's first inbox()", async () => {
    let waiting: Wire[] = [];
    stubRelay(() => waiting.splice(0));
    const carol = newAgent();
    await carol.connect();
    carol._contactBook.addContact(alice.address, alice.publicKey, {
      trustState: "trusted",
    });

    const wire = await rawEnvelope(
      alice,
      carol.address,
      MessageType.MESSAGE,
      "hello",
      vkOf(carol)
    );
    waiting = [stamp(wire, { relay: relayDomain })];
    setClock(carol, DAY);

    expect((await carol.inbox()).map((m) => m.content)).toEqual(["hello"]);
    await carol.close();
  });

  it("does not stop connect() when it can't be opened", async () => {
    stubRelay(() => []);
    writeFileSync(join(keyHome, "replay"), "a file where the folder goes");

    const carol = newAgent();
    await carol.connect();
    expect(carol.isConnected).toBe(true);
    await carol.close();
  });
});

describe("relayVouches", () => {
  const now = Date.parse("2026-11-06T12:00:00.000Z");
  const signed = now - DAY;
  const iso = (ms: number) => new Date(ms).toISOString();
  const meta = (changes?: Record<string, unknown>) => ({
    v: 1,
    relay: DOMAIN,
    received_at: iso(signed),
    stored: true,
    ...changes,
  });
  const vouches = (relayMeta: unknown, signedAt = signed) =>
    relayVouches({ relay_meta: relayMeta }, signedAt, now, DOMAIN);

  it("accepts a message a week old", () => {
    const week = now - STORED_MAIL_MAX_AGE * 1000;
    expect(vouches(meta({ received_at: iso(week) }), week)).toBe(true);
  });

  it("accepts a stamp within the window of the signed time", () => {
    const received = iso(signed + MAX_ENVELOPE_AGE * 1000);
    expect(vouches(meta({ received_at: received }))).toBe(true);
  });

  it.each([
    ["an offset", "2026-11-05T14:00:00+02:00"],
    ["microseconds", "2026-11-05T12:00:00.123456+00:00"],
  ])("reads a time with %s", (_name, received) => {
    expect(vouches(meta({ received_at: received }))).toBe(true);
  });

  it.each([
    ["another relay", { relay: "elsewhere.example" }],
    ["another version", { v: 2 }],
    ["a version that is only truthy", { v: true }],
    ["stored false", { stored: false }],
    ["stored merely truthy", { stored: 1 }],
    ["no time", { received_at: undefined }],
    ["a time that isn't a string", { received_at: 1_762_000_000 }],
    ["words for a time", { received_at: "yesterday" }],
    ["a time with no zone", { received_at: "2026-11-05T12:00:00" }],
    ["a date only", { received_at: "2026-11-05" }],
    ["a loose time format", { received_at: "Nov 5 2026 12:00:00 GMT" }],
  ])("refuses a stamp with %s", (_name, changes) => {
    expect(vouches(meta(changes))).toBe(false);
  });

  it.each([
    ["a string", "stored"],
    ["null", null],
    ["a list", [meta()]],
  ])("refuses relay_meta that is %s", (_name, value) => {
    expect(vouches(value)).toBe(false);
  });

  it("refuses when there is no relay_meta", () => {
    expect(relayVouches({}, signed, now, DOMAIN)).toBe(false);
  });

  it("refuses mail received long after signing", () => {
    const received = iso(signed + (MAX_ENVELOPE_AGE + 1) * 1000);
    expect(vouches(meta({ received_at: received }))).toBe(false);
  });

  it("refuses mail signed in the future", () => {
    const ahead = now + DAY;
    expect(vouches(meta({ received_at: iso(ahead) }), ahead)).toBe(false);
  });

  it("refuses mail over a week old", () => {
    const old = now - (STORED_MAIL_MAX_AGE + MAX_ENVELOPE_AGE + 1) * 1000;
    expect(vouches(meta({ received_at: iso(old) }), old)).toBe(false);
  });
});
