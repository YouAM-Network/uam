/**
 * Passkeys (WebAuthn): registration, assertions and the approval challenge.
 *
 * Mirrors uam.protocol.webauthn in the Python SDK; both are checked against
 * the same vectors (tests/vectors/webauthn/).
 *
 * - registration: `webauthn.create`, attestation format `none` only, user
 *   present and verified, ES256 only;
 * - assertion: `webauthn.get`, the exact challenge, the owner origin exactly,
 *   no cross-origin frame, rpIdHash = SHA-256(RP ID), user present and
 *   verified, backup eligibility unchanged, an ES256 signature over
 *   `authenticatorData || SHA-256(clientDataJSON)` (high-S accepted), and,
 *   where the stored counter is known, a counter that went up whenever either
 *   count is non-zero (synced passkeys report 0 throughout; a count that
 *   drops to 0 may be a clone).
 *
 * ES256 only: a passkey's did:key must never look like an agent key.
 */

import { createHash } from "node:crypto";

import { p256 } from "@noble/curves/p256";

import { encodeDidKey } from "./didkey.js";
import { UAMError } from "./errors.js";
import { SignedObjectError, canonical } from "./signed.js";

export const ES256 = -7;

const UP = 0x01;
const UV = 0x04;
const BE = 0x08;
const AT = 0x40;
const ED = 0x80;

/** A registration or assertion that fails a check. */
export class WebAuthnError extends UAMError {
  constructor(message?: string) {
    super(message);
    this.name = "WebAuthnError";
  }
}

/** A registered passkey: its id, algorithm, compressed P-256 key and flags. */
export interface Credential {
  readonly id: Uint8Array;
  readonly alg: number;
  readonly publicKey: Uint8Array;
  readonly backupEligible: boolean;
  readonly signCount: number;
}

export function credentialDid(credential: Credential): string {
  return encodeDidKey("p256", credential.publicKey);
}

const sha256 = (...parts: Uint8Array[]): Uint8Array => {
  const h = createHash("sha256");
  for (const part of parts) h.update(part);
  return new Uint8Array(h.digest());
};

const equal = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((byte, i) => byte === b[i]);

// --- CBOR (the subset WebAuthn uses) ------------------------------------------

type CborValue = number | boolean | string | Uint8Array | CborValue[] | Map<number | string, CborValue>;

function cbor(data: Uint8Array, start: number): [CborValue, number] {
  let i = start;
  if (i >= data.length) throw new WebAuthnError("CBOR: truncated");
  const first = data[i]!;
  const major = first >> 5;
  const info = first & 0x1f;
  i += 1;
  if (major === 7) {
    if (info === 20) return [false, i];
    if (info === 21) return [true, i];
    throw new WebAuthnError("CBOR: unsupported simple value or float");
  }
  let n: number;
  if (info < 24) {
    n = info;
  } else if (info >= 24 && info <= 27) {
    const size = 1 << (info - 24);
    if (i + size > data.length) throw new WebAuthnError("CBOR: truncated");
    let big = 0n;
    for (let k = 0; k < size; k += 1) big = (big << 8n) | BigInt(data[i + k]!);
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new WebAuthnError("CBOR: number too large");
    n = Number(big);
    i += size;
  } else {
    throw new WebAuthnError("CBOR: indefinite lengths are not supported");
  }
  if (major === 0) return [n, i];
  if (major === 1) return [-1 - n, i];
  if (major === 2 || major === 3) {
    if (i + n > data.length) throw new WebAuthnError("CBOR: truncated");
    const raw = data.slice(i, i + n);
    i += n;
    if (major === 2) return [raw, i];
    try {
      return [new TextDecoder("utf-8", { fatal: true }).decode(raw), i];
    } catch {
      throw new WebAuthnError("CBOR: text is not UTF-8");
    }
  }
  if (major === 4) {
    const items: CborValue[] = [];
    for (let k = 0; k < n; k += 1) {
      const [item, next] = cbor(data, i);
      items.push(item);
      i = next;
    }
    return [items, i];
  }
  if (major === 5) {
    const out = new Map<number | string, CborValue>();
    for (let k = 0; k < n; k += 1) {
      const [key, afterKey] = cbor(data, i);
      if (typeof key !== "number" && typeof key !== "string") {
        throw new WebAuthnError("CBOR: map keys must be integers or text");
      }
      if (out.has(key)) throw new WebAuthnError("CBOR: duplicate map key");
      const [value, afterValue] = cbor(data, afterKey);
      out.set(key, value);
      i = afterValue;
    }
    return [out, i];
  }
  throw new WebAuthnError("CBOR: tags are not supported");
}

function cborWhole(data: Uint8Array): CborValue {
  const [value, end] = cbor(data, 0);
  if (end !== data.length) throw new WebAuthnError("CBOR: trailing bytes");
  return value;
}

// --- shared checks ------------------------------------------------------------

function checkClientData(raw: Uint8Array, kind: string, challenge: Uint8Array, origin: string): void {
  let data: unknown;
  try {
    data = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw));
  } catch {
    throw new WebAuthnError("clientDataJSON is not JSON");
  }
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new WebAuthnError("clientDataJSON is not an object");
  }
  const d = data as Record<string, unknown>;
  if (d["type"] !== kind) throw new WebAuthnError(`clientData.type must be ${kind}`);
  if (d["challenge"] !== Buffer.from(challenge).toString("base64url")) {
    throw new WebAuthnError("clientData.challenge doesn't match");
  }
  if (d["origin"] !== origin) throw new WebAuthnError("clientData.origin doesn't match");
  if ("crossOrigin" in d && d["crossOrigin"] !== false) {
    throw new WebAuthnError("cross-origin ceremonies are refused");
  }
  if ("topOrigin" in d) throw new WebAuthnError("ceremonies in a frame are refused");
}

function checkAuthData(data: Uint8Array, rpId: string): { flags: number; count: number } {
  if (data.length < 37) throw new WebAuthnError("authenticatorData too short");
  if (!equal(data.slice(0, 32), sha256(new TextEncoder().encode(rpId)))) {
    throw new WebAuthnError("rpIdHash doesn't match");
  }
  const flags = data[32]!;
  if (!(flags & UP)) throw new WebAuthnError("user not present");
  if (!(flags & UV)) throw new WebAuthnError("user not verified");
  const count = new DataView(data.buffer, data.byteOffset + 33, 4).getUint32(0, false);
  return { flags, count };
}

function point(bytes: Uint8Array) {
  try {
    return p256.ProjectivePoint.fromHex(bytes);
  } catch {
    throw new WebAuthnError("not a P-256 point");
  }
}

// --- registration ---------------------------------------------------------------

/** Check a `webauthn.create` response; the passkey it registers. */
export function verifyRegistration(args: {
  attestationObject: Uint8Array;
  clientDataJSON: Uint8Array;
  challenge: Uint8Array;
  origin: string;
  rpId: string;
}): Credential {
  checkClientData(args.clientDataJSON, "webauthn.create", args.challenge, args.origin);
  const att = cborWhole(args.attestationObject);
  if (
    !(att instanceof Map) || att.size !== 3 ||
    !att.has("fmt") || !att.has("attStmt") || !att.has("authData")
  ) {
    throw new WebAuthnError("attestationObject must have fmt, attStmt and authData");
  }
  const stmt = att.get("attStmt");
  if (att.get("fmt") !== "none" || !(stmt instanceof Map) || stmt.size !== 0) {
    throw new WebAuthnError("only attestation format 'none' is accepted");
  }
  const data = att.get("authData");
  if (!(data instanceof Uint8Array)) throw new WebAuthnError("authData must be bytes");
  const { flags, count } = checkAuthData(data, args.rpId);
  if (!(flags & AT)) throw new WebAuthnError("no attested credential data");
  if (data.length < 55) throw new WebAuthnError("attested credential data too short");
  const idLen = (data[53]! << 8) | data[54]!;
  const credentialId = data.slice(55, 55 + idLen);
  if (credentialId.length !== idLen) throw new WebAuthnError("credential id truncated");
  const [cose, end] = cbor(data, 55 + idLen);
  if (!(flags & ED) && end !== data.length) {
    throw new WebAuthnError("trailing bytes after the credential key");
  }
  // kty EC2, alg ES256, crv P-256; other COSE parameters are ignored.
  if (!(cose instanceof Map) || cose.get(1) !== 2 || cose.get(3) !== ES256 || cose.get(-1) !== 1) {
    throw new WebAuthnError("only ES256 (P-256) passkeys are accepted");
  }
  const x = cose.get(-2);
  const y = cose.get(-3);
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) {
    throw new WebAuthnError("bad P-256 coordinates");
  }
  const key = point(new Uint8Array([4, ...x, ...y]));
  return {
    id: credentialId,
    alg: ES256,
    publicKey: key.toRawBytes(true),
    backupEligible: Boolean(flags & BE),
    signCount: count,
  };
}

// --- assertions -----------------------------------------------------------------

/**
 * Check a `webauthn.get` response from `credential`; its new sign count.
 *
 * `checkCounter: false` is for a verifier without the stored counter (an
 * agent checking an approval offline); the relay always checks it.
 */
export function verifyAssertion(
  credential: Credential,
  args: {
    authenticatorData: Uint8Array;
    clientDataJSON: Uint8Array;
    signature: Uint8Array;
    challenge: Uint8Array;
    origin: string;
    rpId: string;
    checkCounter?: boolean;
  }
): number {
  if (credential.alg !== ES256) throw new WebAuthnError("only ES256 (P-256) passkeys are accepted");
  checkClientData(args.clientDataJSON, "webauthn.get", args.challenge, args.origin);
  const { flags, count } = checkAuthData(args.authenticatorData, args.rpId);
  if (Boolean(flags & BE) !== credential.backupEligible) {
    throw new WebAuthnError("backup eligibility changed since registration");
  }
  const key = point(credential.publicKey);
  const digest = sha256(args.authenticatorData, sha256(args.clientDataJSON));
  let ok = false;
  try {
    ok = p256.verify(args.signature, digest, key.toRawBytes(false), {
      format: "der", lowS: false, prehash: false,
    });
  } catch {
    ok = false;
  }
  if (!ok) throw new WebAuthnError("bad signature");
  const checkCounter = args.checkCounter ?? true;
  if (checkCounter && (count || credential.signCount) && count <= credential.signCount) {
    throw new WebAuthnError("sign count didn't go up: the passkey may have been cloned");
  }
  return count;
}

// --- approvals ------------------------------------------------------------------

/**
 * The challenge one Face ID signs to approve `items` (type, hash) as shown.
 *
 * `screen` is the exact text the page showed; the challenge commits to its
 * SHA-256, so the page can't show one thing and get another signed.
 */
export function approvalChallenge(items: Array<[string, string]>, screen: string): Uint8Array {
  if (items.length === 0) throw new WebAuthnError("an approval covers at least one object");
  const body = {
    set: items.map(([t, h]) => ({ t, h })),
    screen: createHash("sha256").update(screen, "utf8").digest("hex"),
  };
  let data: Uint8Array;
  try {
    data = canonical(body);
  } catch (err) {
    if (err instanceof SignedObjectError) throw new WebAuthnError(`bad approval set: ${err.message}`);
    throw err;
  }
  return sha256(new TextEncoder().encode("UAM-APPROVAL-v1\n"), data);
}
