/**
 * Signed owner objects: the profile, canonical form, hash and schemas (P2a).
 *
 * Reads the vectors the Python suite reads (tests/vectors/signed/ at the
 * repo root). Their expected canonical forms and hashes come from an
 * independent oracle, so both SDKs must agree with it.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  InvalidDidKeyError,
  decodeDidKey,
  encodeDidKey,
} from "../../src/protocol/didkey.js";
import {
  SignedObjectError,
  canonical,
  objectHash,
  parseBody,
  validate,
} from "../../src/protocol/signed.js";

const VECTORS = resolve(__dirname, "../../../tests/vectors/signed");

interface ProfileCase { name: string; text: string; ok: boolean; canonical?: string }
interface ObjectCase {
  name: string; body: Record<string, unknown>; ok: boolean; canonical?: string; hash?: string;
}
interface DidCase { name?: string; kind?: string; key?: string; did: string; ok: boolean }

function load<T>(name: string): T[] {
  return JSON.parse(readFileSync(resolve(VECTORS, name), "utf-8")) as T[];
}

const PROFILE = load<ProfileCase>("profile.json");
const OBJECTS = load<ObjectCase>("objects.json");
const DIDKEYS = load<DidCase>("didkey.json");

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

describe("the profile", () => {
  it.each(PROFILE.filter((c) => c.ok).map((c) => [c.name, c] as const))(
    "%s has one canonical form",
    (_name, c) => {
      expect(new TextDecoder().decode(canonical(parseBody(c.text)))).toBe(c.canonical);
    }
  );

  it.each(PROFILE.filter((c) => !c.ok).map((c) => [c.name, c] as const))(
    "%s is refused",
    (_name, c) => {
      expect(() => parseBody(c.text)).toThrow(SignedObjectError);
    }
  );

  it("refuses bytes that aren't UTF-8", () => {
    expect(parseBody(new TextEncoder().encode('{"a":1}'))).toEqual({ a: 1 });
    expect(() => parseBody(new Uint8Array([0x7b, 0x22, 0x61, 0x22, 0x3a, 0x22, 0xff, 0x22, 0x7d])))
      .toThrow(SignedObjectError);
  });

  it("canonical() refuses what parseBody() would refuse", () => {
    for (const bad of [{ a: 1.5 }, { a: null }, { a: "café" }, { a: 2 ** 53 }, { a: undefined }]) {
      expect(() => canonical(bad as Record<string, unknown>)).toThrow(SignedObjectError);
    }
  });
});

describe("objects", () => {
  it.each(OBJECTS.filter((c) => c.ok).map((c) => [c.name, c] as const))(
    "%s validates and hashes as the oracle does",
    (_name, c) => {
      const body = parseBody(JSON.stringify(c.body));
      validate(body);
      expect(new TextDecoder().decode(canonical(body))).toBe(c.canonical);
      expect(objectHash(body)).toBe(c.hash);
    }
  );

  it.each(OBJECTS.filter((c) => !c.ok).map((c) => [c.name, c] as const))(
    "%s is refused",
    (_name, c) => {
      expect(() => validate(c.body)).toThrow(SignedObjectError);
      expect(() => objectHash(c.body)).toThrow(SignedObjectError);
    }
  );
});

describe("did:key", () => {
  it.each(DIDKEYS.filter((c) => c.ok).map((c) => [c.did.slice(0, 24), c] as const))(
    "%s decodes and round-trips",
    (_name, c) => {
      const { kind, key } = decodeDidKey(c.did);
      expect([kind, hex(key)]).toEqual([c.kind, c.key]);
      expect(encodeDidKey(kind, key)).toBe(c.did);
    }
  );

  it.each(DIDKEYS.filter((c) => !c.ok).map((c) => [c.name!, c] as const))(
    "%s is refused",
    (_name, c) => {
      expect(() => decodeDidKey(c.did)).toThrow(InvalidDidKeyError);
    }
  );

  it.each([
    ["p256", new Uint8Array([4, ...new Uint8Array(32)])],
    ["p256", new Uint8Array([2, ...new Uint8Array(31)])],
    ["ed25519", new Uint8Array(31)],
    ["rsa", new Uint8Array(32)],
  ] as const)("only encodes well-formed keys (%s)", (kind, key) => {
    expect(() => encodeDidKey(kind as "p256", key)).toThrow(InvalidDidKeyError);
  });
});
