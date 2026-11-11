/**
 * Signed owner objects: profile, canonical form, hash and schemas.
 *
 * Mirrors uam.protocol.signed in the Python SDK; both are checked against
 * the same vectors (tests/vectors/signed/). Every owner object (key log
 * entries, links, invites, redemptions, grants) is a JSON body in a
 * restricted profile, hashed as
 *
 *     h = base64url(SHA-256("UAM-<type>-v1\n" || JCS(body)))   (no padding)
 *
 * The profile: printable ASCII strings, integers within +/-(2^53-1), no
 * floats, no nulls, no duplicate keys, and no members a type doesn't define
 * (new ones go under `ext`, with `crit` naming those a verifier must know).
 * A body that breaks any rule is refused, never repaired.
 */

import { createHash } from "node:crypto";

import { parseAddress } from "./address.js";
import { decodeDidKey, type DidKeyKind } from "./didkey.js";
import { UAMError } from "./errors.js";

export const MAX_INT = 2 ** 53 - 1;
export const GRANT_MAX_DAYS = 90;
export const INVITE_MAX_DAYS = 7;

export type Body = Record<string, unknown>;

/** A signed-object body outside the profile or its type's schema. */
export class SignedObjectError extends UAMError {
  constructor(message?: string) {
    super(message);
    this.name = "SignedObjectError";
  }
}

const has = (obj: object, key: string) => Object.prototype.hasOwnProperty.call(obj, key);

// --- parsing -------------------------------------------------------------------

/**
 * A strict JSON parser for signed bodies. JSON.parse can't be used: it keeps
 * the last of two duplicate keys without a word.
 */
class Parser {
  private i = 0;
  constructor(private readonly s: string) {}

  fail(why: string): never {
    throw new SignedObjectError(`not JSON or outside the profile at ${this.i}: ${why}`);
  }

  ws(): void {
    while (this.i < this.s.length && " \t\n\r".includes(this.s[this.i]!)) this.i += 1;
  }

  document(): Body {
    this.ws();
    if (this.s[this.i] !== "{") this.fail("a body must be a JSON object");
    const value = this.value() as Body;
    this.ws();
    if (this.i !== this.s.length) this.fail("trailing characters");
    return value;
  }

  value(): unknown {
    this.ws();
    const c = this.s[this.i];
    if (c === "{") return this.object();
    if (c === "[") return this.array();
    if (c === '"') return this.string();
    if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) return this.number();
    for (const [word, v] of [["true", true], ["false", false]] as const) {
      if (this.s.startsWith(word, this.i)) {
        this.i += word.length;
        return v;
      }
    }
    if (this.s.startsWith("null", this.i)) this.fail("null is not allowed");
    return this.fail("unexpected character");
  }

  object(): Body {
    this.i += 1;
    const out: Body = Object.create(null) as Body;
    this.ws();
    if (this.s[this.i] === "}") {
      this.i += 1;
      return out;
    }
    for (;;) {
      this.ws();
      if (this.s[this.i] !== '"') this.fail("expected a key");
      const key = this.string();
      if (has(out, key)) this.fail(`duplicate key: ${JSON.stringify(key)}`);
      this.ws();
      if (this.s[this.i] !== ":") this.fail("expected ':'");
      this.i += 1;
      Object.defineProperty(out, key, {
        value: this.value(), enumerable: true, writable: true, configurable: true,
      });
      this.ws();
      if (this.s[this.i] === ",") {
        this.i += 1;
        continue;
      }
      if (this.s[this.i] === "}") {
        this.i += 1;
        return out;
      }
      this.fail("expected ',' or '}'");
    }
  }

  array(): unknown[] {
    this.i += 1;
    const out: unknown[] = [];
    this.ws();
    if (this.s[this.i] === "]") {
      this.i += 1;
      return out;
    }
    for (;;) {
      out.push(this.value());
      this.ws();
      if (this.s[this.i] === ",") {
        this.i += 1;
        continue;
      }
      if (this.s[this.i] === "]") {
        this.i += 1;
        return out;
      }
      this.fail("expected ',' or ']'");
    }
  }

  string(): string {
    this.i += 1;
    let out = "";
    for (;;) {
      const c = this.s[this.i];
      if (c === undefined) this.fail("unterminated string");
      this.i += 1;
      if (c === '"') break;
      if (c === "\\") {
        const e = this.s[this.i];
        this.i += 1;
        const simple: Record<string, string> = {
          '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t",
        };
        if (e !== undefined && has(simple, e)) {
          out += simple[e];
        } else if (e === "u") {
          const hex = this.s.slice(this.i, this.i + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) this.fail("bad \\u escape");
          out += String.fromCharCode(parseInt(hex, 16));
          this.i += 4;
        } else {
          this.fail("bad escape");
        }
      } else {
        if (c < " ") this.fail("control character in string");
        out += c;
      }
    }
    checkString(out);
    return out;
  }

  number(): number {
    const m = /^-?(0|[1-9][0-9]*)([.][0-9]+)?([eE][+-]?[0-9]+)?/.exec(this.s.slice(this.i));
    if (!m) return this.fail("bad number");
    const text = m[0];
    if (m[2] !== undefined || m[3] !== undefined) this.fail(`floats are not allowed: ${text}`);
    if (text === "-0") this.fail("-0 is not allowed");
    const big = BigInt(text);
    if (big > BigInt(MAX_INT) || big < -BigInt(MAX_INT)) this.fail(`integer out of range: ${text}`);
    this.i += text.length;
    return Number(big);
  }
}

/** Parse a body, refusing anything outside the profile. */
export function parseBody(text: string | Uint8Array): Body {
  let s: string;
  if (typeof text === "string") {
    s = text;
  } else {
    try {
      s = new TextDecoder("utf-8", { fatal: true }).decode(text);
    } catch {
      throw new SignedObjectError("body is not UTF-8");
    }
  }
  return new Parser(s).document();
}

// --- profile and canonical form ------------------------------------------------

function checkString(value: string): void {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) {
      throw new SignedObjectError("strings must be printable ASCII");
    }
  }
}

function isPlainObject(value: unknown): value is Body {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return proto === null || proto === Object.prototype;
}

function encode(value: unknown): string {
  if (value === true) return "true";
  if (value === false) return "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new SignedObjectError(`not an integer in range: ${value}`);
    }
    return String(value);
  }
  if (typeof value === "string") {
    checkString(value);
    return '"' + value.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
  }
  if (Array.isArray(value)) return "[" + value.map(encode).join(",") + "]";
  if (isPlainObject(value)) {
    // ASCII keys, so sorting by UTF-16 code unit is RFC 8785's order.
    return "{" + Object.keys(value).sort().map((key) => {
      checkString(key);
      return encode(key) + ":" + encode(value[key]);
    }).join(",") + "}";
  }
  if (value === null) throw new SignedObjectError("null is not allowed");
  throw new SignedObjectError(`not allowed: ${typeof value}`);
}

/** RFC 8785 canonical form (inside the profile: sorted keys, no whitespace). */
export function canonical(body: Body): Uint8Array {
  if (!isPlainObject(body)) throw new SignedObjectError("a body must be a JSON object");
  return new TextEncoder().encode(encode(body));
}

function hashCanonical(body: Body): string {
  return createHash("sha256")
    .update(`UAM-${String(body["type"])}-v1\n`)
    .update(canonical(body))
    .digest("base64url");
}

/** The object's hash; the body is validated first. */
export function objectHash(body: Body): string {
  validate(body);
  return hashCanonical(body);
}

// --- schemas ---------------------------------------------------------------

type Check = (value: unknown, path: string) => void;

const TIME_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;
const HASH_RE = /^[A-Za-z0-9_-]{43}$/;
const OWNER_ID_RE = /^[A-Za-z0-9_-]{22}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{16,64}$/;
const SECRET_RE = /^[A-Za-z0-9_-]{22}$/;
const DOMAIN_RE =
  /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

function fail(path: string, why: string): never {
  throw new SignedObjectError(`${path}: ${why}`);
}

const string_: Check = (v, p) => {
  if (typeof v !== "string" || v.length === 0) fail(p, "must be a non-empty string");
};

const label: Check = (v, p) => {
  string_(v, p);
  if ((v as string).length > 64) fail(p, "at most 64 characters");
  // Labels are quoted in the text an owner signs, so a quote in one could
  // make that text say something the object doesn't.
  if ((v as string).includes('"')) fail(p, 'must not contain "');
};

const matching = (re: RegExp, what: string): Check => (v, p) => {
  if (typeof v !== "string" || !re.test(v)) fail(p, `must be ${what}`);
};

const hash = matching(HASH_RE, "a hash (43 base64url characters)");
const ownerId = matching(OWNER_ID_RE, "an owner id (22 base64url characters)");
const nonce = matching(NONCE_RE, "a nonce (16-64 base64url characters)");
const secret = matching(SECRET_RE, "a secret (22 base64url characters)");
const domain = matching(DOMAIN_RE, "a lowercase domain");

function parseTime(value: string): number | null {
  const m = TIME_RE.exec(value);
  if (!m) return null;
  const [y, mo, d, h, mi, s] = m.slice(1).map(Number) as [number, number, number, number, number, number];
  const t = Date.UTC(y, mo - 1, d, h, mi, s);
  const back = new Date(t);
  if (
    back.getUTCFullYear() !== y || back.getUTCMonth() !== mo - 1 || back.getUTCDate() !== d ||
    back.getUTCHours() !== h || back.getUTCMinutes() !== mi || back.getUTCSeconds() !== s
  ) {
    return null;
  }
  return t;
}

const time: Check = (v, p) => {
  if (typeof v !== "string" || !TIME_RE.test(v)) fail(p, "must be YYYY-MM-DDTHH:MM:SSZ");
  if (parseTime(v) === null) fail(p, "not a real time");
};

const bool: Check = (v, p) => {
  if (typeof v !== "boolean") fail(p, "must be true or false");
};

const constant = (expected: string | number): Check => (v, p) => {
  if (v !== expected) fail(p, `must be ${JSON.stringify(expected)}`);
};

const oneOf = (...options: string[]): Check => (v, p) => {
  if (typeof v !== "string" || !options.includes(v)) fail(p, `must be one of ${options.join(", ")}`);
};

const uint: Check = (v, p) => {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) {
    fail(p, "must be a non-negative integer");
  }
};

const address: Check = (v, p) => {
  if (typeof v !== "string") fail(p, "must be an address");
  let full: string;
  try {
    full = parseAddress(v).full;
  } catch {
    return fail(p, "must be an address");
  }
  if (full !== v) fail(p, "must be an address in canonical (lowercase) form");
};

const did = (kind: DidKeyKind): Check => (v, p) => {
  let found: DidKeyKind;
  try {
    found = decodeDidKey(v as string).kind;
  } catch (err) {
    return fail(p, err instanceof Error ? err.message : String(err));
  }
  if (found !== kind) fail(p, `must be a ${kind} did:key`);
};

const list = (item: Check, minLen = 1, maxLen = 64): Check => (v, p) => {
  if (!Array.isArray(v) || v.length < minLen || v.length > maxLen) {
    fail(p, `must be a list of ${minLen}-${maxLen} items`);
  }
  v.forEach((entry, i) => item(entry, `${p}[${i}]`));
};

const object = (required: Record<string, Check>, optional: Record<string, Check> = {}): Check =>
  (v, p) => {
    if (!isPlainObject(v)) fail(p, "must be an object");
    for (const key of Object.keys(v)) {
      if (!has(required, key) && !has(optional, key)) fail(`${p}.${key}`, "unknown member");
    }
    for (const [key, member] of Object.entries(required)) {
      if (!has(v, key)) fail(`${p}.${key}`, "missing");
      member(v[key], `${p}.${key}`);
    }
    for (const [key, member] of Object.entries(optional)) {
      if (has(v, key)) member(v[key], `${p}.${key}`);
    }
  };

const location: Check = (v, p) => {
  if (v !== "shared") address(v, p);
};

const access = object({ actions: list(oneOf("message"), 1, 1), locations: list(location) });
const ownerRef = object({ relay: domain, ownerId, keysHash: hash });
const ownerRefNoKeys = object({ relay: domain, ownerId });
const passkey = did("p256");
const agentKey = did("ed25519");
const keysOwner = object({ relay: domain }, { ownerId });

const EXT: Record<string, Check> = { ext: () => undefined, crit: () => undefined };

function checkExt(body: Body): void {
  if (has(body, "ext") && !isPlainObject(body["ext"])) fail("ext", "must be an object");
  if (has(body, "crit")) {
    const crit = body["crit"];
    if (!has(body, "ext")) fail("crit", "needs ext");
    if (!Array.isArray(crit) || !crit.every((k) => typeof k === "string")) {
      fail("crit", "must be a list of ext keys");
    }
    for (const key of crit as string[]) {
      if (!has(body["ext"] as Body, key)) fail(`crit.${key}`, "not in ext");
      fail(`crit.${key}`, "unknown critical extension");
    }
  }
}

function span(body: Body, from: string, to: string): number {
  return parseTime(body[to] as string)! - parseTime(body[from] as string)!;
}

const DAY = 24 * 60 * 60 * 1000;

const SCHEMAS: Record<string, (body: Body) => void> = {
  UamOwnerKeys(body) {
    object(
      {
        type: constant("UamOwnerKeys"), v: constant(1), owner: keysOwner, seq: uint,
        keys: list(object({ id: passkey, rpId: domain, backupEligible: bool, label }), 1, 16),
      },
      {
        prev: hash,
        removed: list(object({ id: passkey, reason: oneOf("removed", "compromised") }), 1, 64),
        recovery: bool,
        ...EXT,
      }
    )(body, "$");
    const owner = body["owner"] as Body;
    if (body["seq"] === 0) {
      // The owner id is the hash of entry 0, so entry 0 can't contain it.
      if (has(owner, "ownerId") || has(body, "prev")) fail("$", "entry 0 has no owner.ownerId and no prev");
    } else if (!has(owner, "ownerId") || !has(body, "prev")) {
      fail("$", "a later entry needs owner.ownerId and prev");
    }
  },

  UamOwnerLink(body) {
    object({
      type: constant("UamOwnerLink"), v: constant(1), owner: ownerRef, agent: address,
      agentKey, relay: domain, via: oneOf("setup", "link"), shared: bool,
      effectiveAt: time, validFrom: time, nonce,
    }, { ...EXT })(body, "$");
  },

  UamOwnerUnlink(body) {
    object({
      type: constant("UamOwnerUnlink"), v: constant(1), owner: ownerRef, agent: address,
      agentKey, reason: oneOf("owner", "admin", "relink", "authority", "lapsed"), validFrom: time, nonce,
    }, { ...EXT })(body, "$");
  },

  UamInvite(body) {
    object(
      {
        type: constant("UamInvite"), v: constant(1), inviter: ownerRef, offer: access,
        ask: access, secretHash: hash, mode: oneOf("preapproved", "confirm"),
        maxUses: constant(1), validFrom: time, redeemBy: time, nonce,
      },
      { emailHash: hash, ...EXT }
    )(body, "$");
    if (body["mode"] === "preapproved" && !has(body, "emailHash")) {
      fail("$.emailHash", "a pre-approved invite names the invitee's email");
    }
    const d = span(body, "validFrom", "redeemBy");
    if (!(d > 0 && d <= INVITE_MAX_DAYS * DAY)) {
      fail("$.redeemBy", `must be after validFrom, within ${INVITE_MAX_DAYS} days`);
    }
  },

  UamRedemption(body) {
    object({
      type: constant("UamRedemption"), v: constant(1), invite: hash, secret,
      invitee: ownerRef, issuer: passkey, createdAt: time, nonce,
    }, { ...EXT })(body, "$");
  },

  UamContactGrant(body) {
    object({
      type: constant("UamContactGrant"), v: constant(1), issuer: passkey,
      issuerOwner: ownerRefNoKeys, credentialSubject: subject,
      authorization_details: list(object({
        type: constant("uam_contact"), actions: list(oneOf("message"), 1, 1),
        locations: list(location),
      }), 1, 8),
      via: oneOf("intro_email", "intro_code", "intro_qr", "request", "carried_over"),
      enforcer: domain, validFrom: time, validUntil: time, nonce,
    }, { ...EXT })(body, "$");
    const d = span(body, "validFrom", "validUntil");
    if (!(d > 0 && d <= GRANT_MAX_DAYS * DAY)) {
      fail("$.validUntil", `must be after validFrom, within ${GRANT_MAX_DAYS} days`);
    }
  },
};

const SUBJECTS: Record<string, Check> = {
  owner: object({ kind: constant("owner"), owner: ownerRef }),
  invitee: object({ kind: constant("invitee"), invite: hash }),
  agent: object({ kind: constant("agent"), id: agentKey, address }),
};

function subject(value: unknown, path: string): void {
  const kind = isPlainObject(value) ? value["kind"] : undefined;
  if (typeof kind !== "string" || !has(SUBJECTS, kind)) {
    fail(`${path}.kind`, `must be one of ${Object.keys(SUBJECTS).join(", ")}`);
  }
  SUBJECTS[kind]!(value, path);
}

/** Refuse a body outside the profile or its type's schema. */
export function validate(body: unknown): asserts body is Body {
  if (!isPlainObject(body)) throw new SignedObjectError("a body must be a JSON object");
  encode(body); // the profile
  const type = body["type"];
  if (typeof type !== "string" || !has(SCHEMAS, type)) {
    throw new SignedObjectError(`unknown type: ${JSON.stringify(type)}`);
  }
  SCHEMAS[type]!(body);
  checkExt(body);
}
