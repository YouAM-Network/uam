/**
 * Tests for DNS verifier utilities.
 */

import { describe, it, expect } from "vitest";
import {
  parseUamTxt,
  extractPublicKey,
  generateTxtRecord,
} from "../../src/sdk/dns-verifier.js";

describe("parseUamTxt", () => {
  it("parses a valid UAM TXT record", () => {
    const tags = parseUamTxt(
      "v=uam1; key=ed25519:AAAA; relay=https://relay.example.com"
    );
    expect(tags).toEqual({
      v: "uam1",
      key: "ed25519:AAAA",
      relay: "https://relay.example.com",
    });
  });

  it("lowercases tag names", () => {
    const tags = parseUamTxt("V=uam1; KEY=ed25519:BBBB");
    expect(tags["v"]).toBe("uam1");
    expect(tags["key"]).toBe("ed25519:BBBB");
  });

  it("preserves value casing", () => {
    const tags = parseUamTxt("key=ed25519:AbCdEf");
    expect(tags["key"]).toBe("ed25519:AbCdEf");
  });

  it("handles empty input", () => {
    expect(parseUamTxt("")).toEqual({});
  });

  it("handles extra semicolons and whitespace", () => {
    const tags = parseUamTxt("  v=uam1 ;; key=ed25519:XX ; ");
    expect(tags["v"]).toBe("uam1");
    expect(tags["key"]).toBe("ed25519:XX");
  });

  it("preserves unknown tags (forward compatibility)", () => {
    const tags = parseUamTxt("v=uam1; key=ed25519:XX; custom=hello");
    expect(tags["custom"]).toBe("hello");
  });
});

describe("extractPublicKey", () => {
  it("strips ed25519: prefix", () => {
    const key = extractPublicKey({ key: "ed25519:AAAA" });
    expect(key).toBe("AAAA");
  });

  it("returns null if no key tag", () => {
    expect(extractPublicKey({ v: "uam1" })).toBeNull();
  });

  it("returns null if key does not have ed25519: prefix", () => {
    expect(extractPublicKey({ key: "rsa:BBBB" })).toBeNull();
  });

  it("returns null for empty key value", () => {
    expect(extractPublicKey({ key: "" })).toBeNull();
  });

  it("handles base64 key with special characters", () => {
    const key = extractPublicKey({
      key: "ed25519:AbC+dEf/123=",
    });
    expect(key).toBe("AbC+dEf/123=");
  });
});

describe("generateTxtRecord", () => {
  it("produces correct TXT record format", () => {
    const txt = generateTxtRecord("AAAA", "https://relay.example.com");
    expect(txt).toBe(
      "v=uam1; key=ed25519:AAAA; relay=https://relay.example.com"
    );
  });

  it("round-trips through parseUamTxt + extractPublicKey", () => {
    const publicKey = "AbCdEfGh123456==";
    const relayUrl = "https://relay.youam.network";
    const txt = generateTxtRecord(publicKey, relayUrl);
    const tags = parseUamTxt(txt);
    expect(tags["v"]).toBe("uam1");
    expect(extractPublicKey(tags)).toBe(publicKey);
    expect(tags["relay"]).toBe(relayUrl);
  });
});
