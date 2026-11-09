/**
 * Passkeys: registration, assertions and the approval challenge (P2b).
 *
 * Reads the vectors the Python suite reads (tests/vectors/webauthn/ at the
 * repo root), made by a software authenticator. Each rejection case changes
 * exactly one thing from a valid one.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { decodeDidKey } from "../../src/protocol/didkey.js";
import {
  type Credential,
  WebAuthnError,
  approvalChallenge,
  credentialDid,
  verifyAssertion,
  verifyRegistration,
} from "../../src/protocol/webauthn.js";

interface Response { [key: string]: string }
interface CredentialData {
  id?: string; alg: number; publicKey: string; backupEligible: boolean; signCount: number;
}
interface Case {
  name: string; ok: boolean; response: Response; challenge?: string;
  credential?: CredentialData; signCount?: number;
}
interface Vectors {
  rpId: string; origin: string; getChallenge: string;
  registrations: Case[]; assertions: Case[];
  approval: { set: Array<{ t: string; h: string }>; screen: string; challenge: string };
}

const V = JSON.parse(
  readFileSync(resolve(__dirname, "../../../tests/vectors/webauthn/vectors.json"), "utf-8")
) as Vectors;

const b = (text: string) => new Uint8Array(Buffer.from(text, "base64url"));
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");

function register(c: Case): Credential {
  return verifyRegistration({
    attestationObject: b(c.response["attestationObject"]!),
    clientDataJSON: b(c.response["clientDataJSON"]!),
    challenge: b(c.challenge!),
    origin: V.origin,
    rpId: V.rpId,
  });
}

function credential(data: CredentialData): Credential {
  return {
    id: new Uint8Array([1]),
    alg: data.alg,
    publicKey: new Uint8Array(Buffer.from(data.publicKey, "hex")),
    backupEligible: data.backupEligible,
    signCount: data.signCount,
  };
}

function assertion(c: Case, checkCounter = true): number {
  return verifyAssertion(credential(c.credential!), {
    authenticatorData: b(c.response["authenticatorData"]!),
    clientDataJSON: b(c.response["clientDataJSON"]!),
    signature: b(c.response["signature"]!),
    challenge: b(V.getChallenge),
    origin: V.origin,
    rpId: V.rpId,
    checkCounter,
  });
}

const cases = (list: Case[], ok: boolean) =>
  list.filter((c) => c.ok === ok).map((c) => [c.name, c] as const);

describe("registration", () => {
  it.each(cases(V.registrations, true))("%s gives the credential", (_name, c) => {
    const cred = register(c);
    const expected = c.credential!;
    expect(Buffer.from(cred.id).toString("base64url")).toBe(expected.id);
    expect(cred.alg).toBe(expected.alg);
    expect(hex(cred.publicKey)).toBe(expected.publicKey);
    expect(cred.backupEligible).toBe(expected.backupEligible);
    expect(cred.signCount).toBe(expected.signCount);
    const did = decodeDidKey(credentialDid(cred));
    expect([did.kind, hex(did.key)]).toEqual(["p256", expected.publicKey]);
  });

  it.each(cases(V.registrations, false))("%s is refused", (_name, c) => {
    expect(() => register(c)).toThrow(WebAuthnError);
  });
});

describe("assertions", () => {
  it.each(cases(V.assertions, true))("%s gives the new sign count", (_name, c) => {
    expect(assertion(c)).toBe(c.signCount);
  });

  it.each(cases(V.assertions, false))("%s is refused", (_name, c) => {
    expect(() => assertion(c)).toThrow(WebAuthnError);
  });

  it("lets a verifier without the stored counter skip the counter check", () => {
    const c = V.assertions.find((x) => x.name === "counter_went_back")!;
    expect(assertion(c, false)).toBe(7);
  });
});

describe("the approval challenge", () => {
  const items = V.approval.set.map((e) => [e.t, e.h] as [string, string]);

  it("covers every object and the screen", () => {
    const challenge = approvalChallenge(items, V.approval.screen);
    expect(Buffer.from(challenge).toString("base64url")).toBe(V.approval.challenge);
    expect(hex(approvalChallenge(items.slice(0, 1), V.approval.screen))).not.toBe(hex(challenge));
    expect(hex(approvalChallenge(items, V.approval.screen + " "))).not.toBe(hex(challenge));
  });

  it("needs at least one object", () => {
    expect(() => approvalChallenge([], "nothing")).toThrow(WebAuthnError);
  });
});
