/**
 * Registering an address that already exists: the relay answers 409 until
 * the caller proves it holds the key, and the agent then signs a statement
 * of the address and the time.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  SignatureVerificationError,
  UAMError,
  deserializeVerifyKey,
  sodiumReady,
  verifySignature,
} from "../../src/protocol/index.js";
import { Agent } from "../../src/sdk/agent.js";
import { KeyManager } from "../../src/sdk/key-manager.js";

const RELAY = "http://relay.youam.test";
const ADDRESS = "bob::youam.test";

type Body = {
  agent_name: string;
  public_key: string;
  proof?: { timestamp: string; signature: string };
};

let dir: string;
let registrations: Body[];
let lookups: number;
let wellKnownStatus: number;
let claimedDomain: string;
/** The relay's answer to a registration that carries a proof. */
let answerToProof: number;

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function agent(domain?: string, relay: string = RELAY): Agent {
  return new Agent("bob", {
    relay,
    domain,
    keyDir: join(dir, "keys"),
    transport: "http",
  });
}

function signedBytes(address: string, timestamp: string): Uint8Array {
  return new TextEncoder().encode(`uam-register-v1\n${address}\n${timestamp}`);
}

beforeEach(async () => {
  await sodiumReady;
  dir = mkdtempSync(join(tmpdir(), "uam-register-"));
  registrations = [];
  lookups = 0;
  wellKnownStatus = 200;
  claimedDomain = "youam.test";
  answerToProof = 200;
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/api/v1/register")) {
      const body = JSON.parse(String(init?.body)) as Body;
      registrations.push(body);
      if (!body.proof) return json({ detail: "exists" }, 409);
      return answerToProof === 200
        ? json({ address: ADDRESS, token: "new-token", relay: "ws://relay.test/ws" })
        : json({ detail: "refused" }, answerToProof);
    }
    if (url.endsWith("/.well-known/uam-relay.json")) {
      lookups += 1;
      return wellKnownStatus === 200
        ? json({ relay_domain: claimedDomain })
        : json({ detail: "unavailable" }, wellKnownStatus);
    }
    return json({ detail: "not found" }, 404);
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  rmSync(dir, { recursive: true, force: true });
});

describe("recovering a lost token", () => {
  it("proves the key after a 409 and keeps the new token", async () => {
    const a = agent();
    await a.connect();
    expect(a.address).toBe(ADDRESS);
    await a.close();

    const km = new KeyManager(join(dir, "keys"));
    expect(km.loadToken("bob")).toBe("new-token");
    expect(km.loadAddress("bob", RELAY)).toBe(ADDRESS);
  });

  it("first asks without a proof, then repeats the body with one", async () => {
    const a = agent();
    await a.connect();
    await a.close();

    expect(registrations).toHaveLength(2);
    const [first, second] = registrations;
    expect(first).toEqual({ agent_name: "bob", public_key: a.publicKey });
    const { proof, ...rest } = second;
    expect(rest).toEqual(first);
    expect(Object.keys(proof!).sort()).toEqual(["signature", "timestamp"]);
  });

  it("signs exactly the agreed string with the agent's key", async () => {
    const a = agent();
    await a.connect();
    await a.close();

    const { timestamp, signature } = registrations[1].proof!;
    const verifyKey = deserializeVerifyKey(a.publicKey);

    expect(() =>
      verifySignature(signedBytes(ADDRESS, timestamp), signature, verifyKey)
    ).not.toThrow();

    for (const other of [
      signedBytes("bob::relay.test", timestamp),
      signedBytes(ADDRESS, "2020-01-01T00:00:00.000Z"),
      new TextEncoder().encode(`uam-register-v2\n${ADDRESS}\n${timestamp}`),
      new TextEncoder().encode(`uam-register-v1\n${ADDRESS}\n${timestamp}\n`),
    ]) {
      expect(() => verifySignature(other, signature, verifyKey)).toThrow(
        SignatureVerificationError
      );
    }
  });

  it("stamps the current UTC time, ending in Z", async () => {
    const before = Date.now();
    const a = agent();
    await a.connect();
    await a.close();

    const { timestamp } = registrations[1].proof!;
    expect(timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/);
    const stamped = Date.parse(timestamp);
    expect(stamped).toBeGreaterThanOrEqual(before - 1000);
    expect(stamped).toBeLessThanOrEqual(Date.now());
  });

  it("uses an explicit domain without asking the relay", async () => {
    const a = agent("chosen.test");
    await a.connect();
    await a.close();

    expect(lookups).toBe(0);
    const { timestamp, signature } = registrations[1].proof!;
    expect(() =>
      verifySignature(
        signedBytes("bob::chosen.test", timestamp),
        signature,
        deserializeVerifyKey(a.publicKey)
      )
    ).not.toThrow();
  });

  it("signs for the configured domain if the lookup fails", async () => {
    wellKnownStatus = 503;

    const a = agent();
    await a.connect();
    await a.close();

    const { timestamp, signature } = registrations[1].proof!;
    expect(() =>
      verifySignature(
        signedBytes("bob::relay.youam.test", timestamp),
        signature,
        deserializeVerifyKey(a.publicKey)
      )
    ).not.toThrow();
  });

  it.each([409, 403])("reports a refused proof (%i)", async (status) => {
    answerToProof = status;

    const failure = await agent().connect().catch((err: unknown) => err);
    expect(failure).toBeInstanceOf(UAMError);
    expect(String(failure)).toMatch(/already registered/);
    expect(String(failure)).toMatch(/prove/);
    expect(String(failure)).not.toMatch(/different key/);
    expect(registrations).toHaveLength(2);
  });

  it("reports any other failure of the second attempt as it is", async () => {
    answerToProof = 500;

    await expect(agent().connect()).rejects.toThrow(/Registration failed: 500/);
  });
});

describe("which domain a proof may name", () => {
  async function connectTo(relay: string): Promise<unknown> {
    const a = agent(undefined, relay);
    const failure = await a.connect().catch((err: unknown) => err);
    await a.close();
    return failure;
  }

  function signedFor(a: string, proof: NonNullable<Body["proof"]>, key: string) {
    return () =>
      verifySignature(
        signedBytes(a, proof.timestamp),
        proof.signature,
        deserializeVerifyKey(key)
      );
  }

  it.each([
    ["another relay's", "https://evil.example"],
    ["a lookalike's", "https://notyouam.test"],
    ["a name that only starts with it", "https://youam.test.evil.example"],
    ["a parent of the URL's host, reversed", "https://test"],
    ["a URL hiding its host behind userinfo", "https://youam.test@evil.example"],
    ["a name that only starts with an IP", "http://127.0.0.1.evil.example"],
    ["a name that only starts with localhost", "http://localhost.evil.example"],
  ])("refuses %s URL for that domain", async (_name, relay) => {
    const failure = await connectTo(relay);

    expect(failure).toBeInstanceOf(UAMError);
    expect(String(failure)).toMatch(/youam\.test/);
    expect(String(failure)).toMatch(/domain/);
    expect(registrations).toHaveLength(1);
    expect(registrations[0].proof).toBeUndefined();
  });

  it.each([
    ["a subdomain", "https://relay.youam.test", "youam.test"],
    ["the domain itself", "https://youam.test", "youam.test"],
    ["a deeper subdomain", "https://a.b.youam.test", "youam.test"],
    ["an upper-case host", "https://RELAY.youam.test", "youam.test"],
    ["a loopback IP", "http://127.0.0.1:8787", "swarmify.local"],
    ["the rest of 127/8", "http://127.5.6.7:8787", "swarmify.local"],
    ["localhost", "http://localhost:8787", "swarmify.local"],
    ["IPv6 loopback", "http://[::1]:8787", "swarmify.local"],
  ])("allows %s", async (_name, relay, claims) => {
    claimedDomain = claims;
    const a = agent(undefined, relay);
    await a.connect();
    await a.close();

    expect(
      signedFor(`bob::${claims}`, registrations[1].proof!, a.publicKey)
    ).not.toThrow();
  });

  it("takes an explicit domain from any relay, without asking", async () => {
    const a = agent("chosen.test", "https://evil.example");
    await a.connect();
    await a.close();

    expect(lookups).toBe(0);
    expect(
      signedFor("bob::chosen.test", registrations[1].proof!, a.publicKey)
    ).not.toThrow();
  });
});
