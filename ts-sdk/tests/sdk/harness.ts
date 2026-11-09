/**
 * Test harness: real Agents (real keys, real crypto, real SQLite ContactBook
 * in a temp dir) wired to an in-memory relay. Only the network is faked.
 */

import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import {
  UAMError,
  createEnvelope,
  createContactCard,
  contactCardToDict,
  toWireDict,
  deserializeVerifyKey,
  type MessageType,
} from "../../src/protocol/index.js";
import { Agent } from "../../src/sdk/agent.js";
import { AddressResolver } from "../../src/sdk/resolver.js";
import { TransportBase } from "../../src/sdk/transport/base.js";

export const RELAY_URL = "http://relay.test";
export const DOMAIN = "relay.test";

export function addr(name: string): string {
  return `${name}::${DOMAIN}`;
}

type Wire = Record<string, unknown>;

/** In-memory relay: a mailbox per address plus a public-key directory. */
export class FakeRelay {
  readonly mailboxes = new Map<string, Wire[]>();
  readonly keys = new Map<string, string>();
  /** Every envelope any agent sent, in order. */
  readonly sent: Wire[] = [];
  /** What the relay answers a send with (null: no answer in time). */
  answer: (wire: Wire) => Wire | null = (wire) => ({
    message_id: wire["message_id"], status: "stored", delivered: false,
  });

  deliver(wire: Wire): void {
    this.sent.push(wire);
    const to = wire["to"] as string;
    const box = this.mailboxes.get(to) ?? [];
    box.push(wire);
    this.mailboxes.set(to, box);
  }

  /** Put a raw (possibly malformed) item straight into a mailbox. */
  inject(to: string, raw: Wire): void {
    const box = this.mailboxes.get(to) ?? [];
    box.push(raw);
    this.mailboxes.set(to, box);
  }

  take(address: string, limit: number): Wire[] {
    const box = this.mailboxes.get(address) ?? [];
    const out = box.slice(0, limit);
    this.mailboxes.set(address, box.slice(limit));
    return out;
  }

  sentBy(from: string): Wire[] {
    return this.sent.filter((w) => w["from"] === from);
  }

  sentTypes(from: string): string[] {
    return this.sentBy(from).map((w) => w["type"] as string);
  }
}

export class FakeTransport extends TransportBase {
  constructor(
    private _relay: FakeRelay,
    private _address: string
  ) {
    super();
  }
  async connect(): Promise<void> {}
  async disconnect(): Promise<void> {}
  async send(envelope: Wire): Promise<Wire | null> {
    this._relay.deliver(envelope);
    return this._relay.answer(envelope);
  }
  async receive(limit: number = 50): Promise<Wire[]> {
    return this._relay.take(this._address, limit);
  }
  async listen(): Promise<void> {
    throw new Error("not supported");
  }
}

export class FakeResolver extends AddressResolver {
  calls: string[] = [];
  constructor(private _relay: FakeRelay) {
    super();
  }
  async resolvePublicKey(address: string): Promise<string> {
    this.calls.push(address);
    const key = this._relay.keys.get(address);
    if (key === undefined) throw new UAMError(`Agent not found: ${address}`);
    return key;
  }
}

const homes: string[] = [];

/** Remove every temp home created by makeAgent(). Call from afterEach. */
export async function cleanupAgents(agents: Agent[]): Promise<void> {
  for (const a of agents) {
    try {
      a._contactBook.close();
    } catch {
      // already closed
    }
    await a._replayCache.close();
  }
  agents.length = 0;
  while (homes.length > 0) {
    rmSync(homes.pop()!, { recursive: true, force: true });
  }
}

/**
 * Build a connected Agent named `name` on the fake relay, without any
 * network I/O. Its contact book lives in its own temp dir.
 */
export function makeAgent(
  relay: FakeRelay,
  name: string,
  options?: { trustPolicy?: string; relay?: string }
): Agent {
  const home = mkdtempSync(join(tmpdir(), `uam-${name}-`));
  homes.push(home);
  // SDKConfig derives dataDir from UAM_HOME at construction time.
  const prevHome = process.env["UAM_HOME"];
  process.env["UAM_HOME"] = home;
  let agent: Agent;
  try {
    agent = new Agent(name, {
      relay: options?.relay ?? RELAY_URL,
      keyDir: join(home, "keys"),
      autoRegister: false,
      transport: "http",
      trustPolicy: options?.trustPolicy ?? "auto-accept",
    });
  } finally {
    process.env["UAM_HOME"] = prevHome;
  }
  agent._keyManager.loadOrGenerate(name);
  const a = agent as unknown as Record<string, unknown>;
  a["_address"] = addr(name);
  a["_token"] = `token-${name}`;
  a["_transport"] = new FakeTransport(relay, addr(name));
  a["_resolver"] = new FakeResolver(relay);
  agent._contactBook.open();
  a["_connected"] = true;
  relay.keys.set(addr(name), agent.publicKey);
  return agent;
}

/** Sign + encrypt an arbitrary envelope from `from` (bypassing Agent.send). */
export async function rawEnvelope(
  from: Agent,
  toAddress: string,
  type: MessageType | string,
  plaintext: string,
  recipientVk: Uint8Array,
  options?: { expires?: string }
): Promise<Wire> {
  const env = await createEnvelope(
    from.address,
    toAddress,
    type,
    new TextEncoder().encode(plaintext),
    from._keyManager.signingKey,
    recipientVk,
    options
  );
  return toWireDict(env);
}

/** A self-signed contact card claiming `address`, signed by `signer`'s key. */
export async function cardJson(
  address: string,
  signer: Agent
): Promise<Record<string, unknown>> {
  const card = await createContactCard(
    address,
    address.split("::")[0],
    "ws://relay.test/ws",
    signer._keyManager.signingKey
  );
  return contactCardToDict(card);
}

export function vkOf(agent: Agent): Uint8Array {
  return deserializeVerifyKey(agent.publicKey);
}

/** handshake.request from `from` to `to` carrying an arbitrary card. */
export async function requestWithCard(
  from: Agent,
  to: Agent,
  card: Record<string, unknown>
): Promise<Wire> {
  return rawEnvelope(
    from,
    to.address,
    "handshake.request",
    JSON.stringify(card),
    vkOf(to)
  );
}

/** handshake.accept from `from` to `to` carrying an arbitrary payload. */
export async function acceptWithPayload(
  from: Agent,
  to: Agent,
  payload: Record<string, unknown>,
  encryptTo?: Uint8Array
): Promise<Wire> {
  return rawEnvelope(
    from,
    to.address,
    "handshake.accept",
    JSON.stringify(payload),
    encryptTo ?? vkOf(to)
  );
}

/** Make `a` look like it already sent a handshake.request to `b`. */
export function markHandshakeSent(a: Agent, b: Agent): void {
  a._contactBook.addContact(b.address, b.publicKey, {
    trustState: "handshake-sent",
  });
}
