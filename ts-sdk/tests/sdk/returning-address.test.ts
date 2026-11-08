/**
 * An agent keeps its address across restarts. The relay chooses the domain,
 * and it need not match the relay's hostname: relay.youam.network hands out
 * name::youam.network.
 */

import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Agent } from "../../src/sdk/agent.js";
import { KeyManager } from "../../src/sdk/key-manager.js";

const RELAY = "http://relay.test";
const ADDRESS = "bob::youam.test";

let dir: string;
let relayKnowsItsDomain: boolean;
let wellKnownBody: unknown;
let requested: string[];
let authorizations: string[];

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function agent(options?: {
  relay?: string;
  domain?: string;
  autoRegister?: boolean;
}): Agent {
  return new Agent("bob", {
    relay: RELAY,
    keyDir: join(dir, "keys"),
    transport: "http",
    ...options,
  });
}

function savedPath(): string {
  return join(dir, "keys", "bob.address");
}

function saved(): unknown {
  return JSON.parse(readFileSync(savedPath(), "utf-8"));
}

function lookups(): string[] {
  return requested.filter((url) => url.includes("uam-relay.json"));
}

async function addressAfterConnect(a: Agent): Promise<string> {
  await a.connect();
  const address = a.address;
  await a.close();
  return address;
}

async function firstRun(): Promise<void> {
  const a = agent();
  await a.connect();
  expect(a.address).toBe(ADDRESS);
  await a.close();
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "uam-returning-"));
  relayKnowsItsDomain = true;
  wellKnownBody = { relay_domain: "youam.test" };
  requested = [];
  authorizations = [];
  vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    requested.push(url);
    const auth = new Headers(init?.headers).get("Authorization");
    if (auth !== null) authorizations.push(`${new URL(url).host} ${auth}`);
    if (url.endsWith("/api/v1/register")) {
      const token = url.startsWith(RELAY)
        ? "a-token"
        : `a-token-from-${new URL(url).host}`;
      return json({ address: ADDRESS, token, relay: "ws://relay.test/ws" });
    }
    if (url.endsWith("/.well-known/uam-relay.json")) {
      return relayKnowsItsDomain
        ? json(wellKnownBody)
        : json({ detail: "unavailable" }, 503);
    }
    if (url.includes("/api/v1/inbox/")) return json({ messages: [] });
    return json({ detail: "not found" }, 404);
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  delete process.env["UAM_RELAY_DOMAIN"];
  chmodSync(join(dir), 0o700);
  if (existsSync(join(dir, "keys"))) chmodSync(join(dir, "keys"), 0o700);
  rmSync(dir, { recursive: true, force: true });
});

describe("a saved token", () => {
  const ELSEWHERE = "http://elsewhere.test";

  it("is not offered to a different relay", async () => {
    await firstRun();

    const a = agent({ relay: ELSEWHERE, autoRegister: false });
    await expect(a.connect()).rejects.toThrow(/No stored token/);
    await a.close();
    expect(requested.filter((url) => url.startsWith(ELSEWHERE))).toEqual([]);
  });

  it("is not sent there when the agent registers instead", async () => {
    await firstRun();

    const a = agent({ relay: ELSEWHERE });
    await a.connect();
    await a.inbox();
    await a.close();

    expect(requested).toContain(`${ELSEWHERE}/api/v1/register`);
    expect(authorizations).toEqual([
      `elsewhere.test Bearer a-token-from-elsewhere.test`,
    ]);
  });

  it("is used as before with an old plain-text address file", async () => {
    await firstRun();
    writeFileSync(savedPath(), ADDRESS);

    const a = agent({ autoRegister: false });
    await a.connect();
    expect(a.isConnected).toBe(true);
    await a.close();
  });
});

describe("returning agent address", () => {
  it("keeps the address after a restart", async () => {
    await firstRun();

    const a = agent();
    await a.connect();
    expect(a.address).toBe(ADDRESS);
    await a.close();
    expect(lookups()).toEqual([]);
  });

  it("records which relay gave the address", async () => {
    await firstRun();
    expect(saved()).toEqual({ address: ADDRESS, relay_url: RELAY });
  });

  it("asks the relay when only a token was saved", async () => {
    await firstRun();
    unlinkSync(savedPath());

    const a = agent();
    await a.connect();
    expect(a.address).toBe(ADDRESS);
    await a.close();
    expect(saved()).toEqual({ address: ADDRESS, relay_url: RELAY });
  });

  it("leaves the configured domain when the relay cannot say", async () => {
    await firstRun();
    unlinkSync(savedPath());
    relayKnowsItsDomain = false;

    const a = agent();
    await a.connect();
    expect(a.address).toBe("bob::relay.test");
    await a.close();
    expect(existsSync(savedPath())).toBe(false);
  });

  it.each([
    ["empty", { relay_domain: "" }],
    ["blank", { relay_domain: "   " }],
    ["a number", { relay_domain: 42 }],
    ["null", { relay_domain: null }],
    ["missing", {}],
    ["not a domain", { relay_domain: "not a domain!" }],
    ["a bare value", null],
  ])("treats a relay_domain that is %s as no answer", async (_name, body) => {
    await firstRun();
    unlinkSync(savedPath());
    wellKnownBody = body;

    expect(await addressAfterConnect(agent())).toBe("bob::relay.test");
    expect(existsSync(savedPath())).toBe(false);
  });

  it("uses an explicit domain without asking or reading the file", async () => {
    await firstRun();

    expect(await addressAfterConnect(agent({ domain: "chosen.test" }))).toBe(
      "bob::chosen.test"
    );
    expect(lookups()).toEqual([]);
    expect(saved()).toEqual({ address: ADDRESS, relay_url: RELAY });
  });

  it("takes the explicit domain from UAM_RELAY_DOMAIN too", async () => {
    await firstRun();
    process.env["UAM_RELAY_DOMAIN"] = "fromenv.test";

    expect(await addressAfterConnect(agent())).toBe("bob::fromenv.test");
    expect(lookups()).toEqual([]);
  });

  it("does not reuse an address saved for another relay", async () => {
    await firstRun();
    writeFileSync(
      savedPath(),
      JSON.stringify({ address: "bob::old.test", relay_url: "http://old.test" })
    );

    expect(await addressAfterConnect(agent())).toBe(ADDRESS);
    expect(saved()).toEqual({ address: ADDRESS, relay_url: RELAY });
  });

  it.each([
    ["plain text", ADDRESS],
    ["broken JSON", '{"address": '],
    ["a malformed address", JSON.stringify({ address: "nope", relay_url: RELAY })],
  ])("asks the relay when the file holds %s", async (_name, content) => {
    await firstRun();
    writeFileSync(savedPath(), content);

    expect(await addressAfterConnect(agent())).toBe(ADDRESS);
    expect(lookups()).toHaveLength(1);
  });

  it("builds the lookup URL without a double slash", async () => {
    await firstRun();
    unlinkSync(savedPath());

    await addressAfterConnect(agent({ relay: `${RELAY}/` }));
    expect(lookups()).toEqual([`${RELAY}/.well-known/uam-relay.json`]);
  });

  it("registers at a URL without a double slash", async () => {
    await addressAfterConnect(agent({ relay: `${RELAY}/` }));
    expect(requested).toContain(`${RELAY}/api/v1/register`);
  });

  it("matches the saved relay whatever its trailing slashes", async () => {
    await firstRun();

    expect(await addressAfterConnect(agent({ relay: `${RELAY}//` }))).toBe(ADDRESS);
    expect(lookups()).toEqual([]);
  });

  it("connects when the address cannot be written", async () => {
    await firstRun();
    unlinkSync(savedPath());
    mkdirSync(savedPath());

    expect(await addressAfterConnect(agent())).toBe(ADDRESS);
  });

  it.skipIf(process.getuid?.() === 0)(
    "registers in a read-only key folder",
    async () => {
      const keys = join(dir, "keys");
      new KeyManager(keys).loadOrGenerate("bob");
      chmodSync(keys, 0o500);

      expect(await addressAfterConnect(agent())).toBe(ADDRESS);
      expect(existsSync(savedPath())).toBe(false);
    }
  );

  it.skipIf(process.getuid?.() === 0)(
    "connects in a read-only key folder with a saved token",
    async () => {
      await firstRun();
      unlinkSync(savedPath());
      chmodSync(join(dir, "keys"), 0o500);

      expect(await addressAfterConnect(agent())).toBe(ADDRESS);
    }
  );

  it("looks up contacts on the same relay there", async () => {
    await firstRun();

    const a = agent();
    await a.connect();
    const resolver = (a as unknown as { _resolver: { relayDomain: string } })._resolver;
    expect(resolver.relayDomain).toBe("youam.test");
    await a.close();
  });

  it("saves and loads an address", () => {
    const km = new KeyManager(join(dir, "keys"));
    expect(km.loadAddress("bob", RELAY)).toBeNull();
    km.saveAddress("bob", ADDRESS, RELAY);

    const reloaded = new KeyManager(join(dir, "keys"));
    expect(reloaded.loadAddress("bob", RELAY)).toBe(ADDRESS);
    expect(reloaded.loadAddress("bob", `${RELAY}/`)).toBe(ADDRESS);
    expect(reloaded.loadAddress("bob", "http://other.test")).toBeNull();
  });

  it("compares relays with the saved side's slashes removed too", () => {
    const km = new KeyManager(join(dir, "keys"));
    km.saveAddress("bob", ADDRESS, `${RELAY}/`);
    expect(km.loadAddress("bob", RELAY)).toBe(ADDRESS);
  });

  it.each([
    ["a JSON array", "[]"],
    ["a JSON null", "null"],
    ["no relay", JSON.stringify({ address: ADDRESS })],
    ["no address", JSON.stringify({ relay_url: RELAY })],
    ["a non-string address", JSON.stringify({ address: 1, relay_url: RELAY })],
  ])("loads nothing from a file with %s", (_name, content) => {
    const km = new KeyManager(join(dir, "keys"));
    km.saveAddress("bob", ADDRESS, RELAY);
    writeFileSync(savedPath(), content);
    expect(km.loadAddress("bob", RELAY)).toBeNull();
  });

  it("loads nothing from an unreadable file", () => {
    mkdirSync(savedPath(), { recursive: true });
    expect(new KeyManager(join(dir, "keys")).loadAddress("bob", RELAY)).toBeNull();
  });
});
