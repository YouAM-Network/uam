/**
 * did:key for the two key types owner objects carry (as the Python SDK).
 *
 * Ed25519 (an agent's key, `did:key:z6Mk...`, multicodec 0xed) and P-256
 * (a passkey, `did:key:zDn...`, multicodec 0x1200, compressed point).
 */

import { UAMError } from "./errors.js";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export type DidKeyKind = "ed25519" | "p256";

const PREFIX: Record<DidKeyKind, Uint8Array> = {
  ed25519: new Uint8Array([0xed, 0x01]),
  p256: new Uint8Array([0x80, 0x24]),
};
const LENGTH: Record<DidKeyKind, number> = { ed25519: 32, p256: 33 };

/** A did:key string that isn't one of the two supported key types. */
export class InvalidDidKeyError extends UAMError {
  constructor(message?: string) {
    super(message);
    this.name = "InvalidDidKeyError";
  }
}

export function b58encode(data: Uint8Array): string {
  let n = 0n;
  for (const byte of data) n = (n << 8n) | BigInt(byte);
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  let zeros = 0;
  while (zeros < data.length && data[zeros] === 0) zeros += 1;
  return "1".repeat(zeros) + out;
}

export function b58decode(text: string): Uint8Array {
  let n = 0n;
  for (const c of text) {
    const i = B58.indexOf(c);
    if (i < 0) throw new InvalidDidKeyError(`not base58btc: ${JSON.stringify(c)}`);
    n = n * 58n + BigInt(i);
  }
  const body: number[] = [];
  while (n > 0n) {
    body.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  let zeros = 0;
  while (zeros < text.length && text[zeros] === "1") zeros += 1;
  return new Uint8Array([...new Array<number>(zeros).fill(0), ...body]);
}

function checkKey(kind: DidKeyKind, key: Uint8Array): void {
  if (key.length !== LENGTH[kind]) {
    throw new InvalidDidKeyError(`${kind} key must be ${LENGTH[kind]} bytes`);
  }
  if (kind === "p256" && key[0] !== 2 && key[0] !== 3) {
    throw new InvalidDidKeyError("P-256 key must be a compressed point");
  }
}

/** `did:key:z...` for an Ed25519 key (32 bytes) or a compressed P-256 point (33 bytes). */
export function encodeDidKey(kind: DidKeyKind, publicKey: Uint8Array): string {
  if (!(kind in PREFIX)) throw new InvalidDidKeyError(`unsupported key type: ${kind}`);
  checkKey(kind, publicKey);
  return "did:key:z" + b58encode(new Uint8Array([...PREFIX[kind], ...publicKey]));
}

/** The key type and raw public key in a did:key string. */
export function decodeDidKey(did: string): { kind: DidKeyKind; key: Uint8Array } {
  if (typeof did !== "string" || !did.startsWith("did:key:z")) {
    throw new InvalidDidKeyError("not a did:key with base58btc multibase");
  }
  const raw = b58decode(did.slice("did:key:z".length));
  for (const kind of Object.keys(PREFIX) as DidKeyKind[]) {
    const prefix = PREFIX[kind];
    if (raw.length >= prefix.length && prefix.every((b, i) => raw[i] === b)) {
      const key = raw.slice(prefix.length);
      checkKey(kind, key);
      return { kind, key };
    }
  }
  throw new InvalidDidKeyError("unsupported key type");
}
