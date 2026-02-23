/**
 * Tests for Tier2Resolver DNS resolution.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock viem to prevent heavy dependency -- must be before imports
const { mockCreatePublicClient } = vi.hoisted(() => {
  const mockCreatePublicClient = vi.fn(() => ({
    readContract: vi.fn(),
  }));
  return { mockCreatePublicClient };
});

vi.mock("viem", () => ({
  createPublicClient: mockCreatePublicClient,
  http: vi.fn((url: string) => ({ url, type: "http" })),
  defineChain: vi.fn((def: Record<string, unknown>) => def),
}));

// Mock dns-verifier module before importing resolver
vi.mock("../../src/sdk/dns-verifier.js", () => ({
  queryUamTxt: vi.fn(),
  parseUamTxt: vi.fn(),
  extractPublicKey: vi.fn(),
  resolveKeyViaHttps: vi.fn(),
  generateTxtRecord: vi.fn(),
}));

// Import tier3 FIRST to break the circular dependency resolution issue.
// tier3.ts imports AddressResolver from resolver.ts; by importing tier3 first
// the module graph resolves correctly.
import "../../src/sdk/tier3.js";

import { Tier2Resolver } from "../../src/sdk/resolver.js";
import {
  queryUamTxt,
  parseUamTxt,
  extractPublicKey,
  resolveKeyViaHttps,
} from "../../src/sdk/dns-verifier.js";

const mockQueryUamTxt = vi.mocked(queryUamTxt);
const mockParseUamTxt = vi.mocked(parseUamTxt);
const mockExtractPublicKey = vi.mocked(extractPublicKey);
const mockResolveKeyViaHttps = vi.mocked(resolveKeyViaHttps);

describe("Tier2Resolver", () => {
  let resolver: Tier2Resolver;

  beforeEach(() => {
    vi.clearAllMocks();
    resolver = new Tier2Resolver();
  });

  it("resolves via DNS TXT records", async () => {
    mockQueryUamTxt.mockResolvedValue([
      "v=uam1; key=ed25519:AAAA; relay=https://relay.example.com",
    ]);
    mockParseUamTxt.mockReturnValue({
      v: "uam1",
      key: "ed25519:AAAA",
      relay: "https://relay.example.com",
    });
    mockExtractPublicKey.mockReturnValue("AAAA");

    const key = await resolver.resolvePublicKey(
      "alice::example.com",
      "token",
      "https://relay.example.com"
    );

    expect(key).toBe("AAAA");
    expect(mockQueryUamTxt).toHaveBeenCalledWith("example.com");
    expect(mockResolveKeyViaHttps).not.toHaveBeenCalled();
  });

  it("falls back to HTTPS when DNS returns no records", async () => {
    mockQueryUamTxt.mockResolvedValue([]);
    mockResolveKeyViaHttps.mockResolvedValue("BBBB");

    const key = await resolver.resolvePublicKey(
      "bob::example.com",
      "token",
      "https://relay.example.com"
    );

    expect(key).toBe("BBBB");
    expect(mockResolveKeyViaHttps).toHaveBeenCalledWith("bob", "example.com");
  });

  it("falls back to HTTPS when DNS TXT has no valid key", async () => {
    mockQueryUamTxt.mockResolvedValue([
      "v=uam1; relay=https://relay.example.com",
    ]);
    mockParseUamTxt.mockReturnValue({
      v: "uam1",
      relay: "https://relay.example.com",
    });
    mockExtractPublicKey.mockReturnValue(null);
    mockResolveKeyViaHttps.mockResolvedValue("CCCC");

    const key = await resolver.resolvePublicKey(
      "charlie::example.com",
      "token",
      "https://relay.example.com"
    );

    expect(key).toBe("CCCC");
  });

  it("throws UAMError when both DNS and HTTPS fail", async () => {
    mockQueryUamTxt.mockResolvedValue([]);
    mockResolveKeyViaHttps.mockResolvedValue(null);

    await expect(
      resolver.resolvePublicKey(
        "dave::example.com",
        "token",
        "https://relay.example.com"
      )
    ).rejects.toThrow(
      "Could not resolve public key for dave::example.com via DNS or HTTPS"
    );
  });

  it("skips non-uam1 TXT records", async () => {
    mockQueryUamTxt.mockResolvedValue([
      "v=uam1; key=ed25519:DDDD; relay=https://relay.example.com",
    ]);
    // Simulate a record where v is not uam1 (edge case)
    mockParseUamTxt.mockReturnValue({
      v: "uam2",
      key: "ed25519:DDDD",
    });
    mockExtractPublicKey.mockReturnValue("DDDD");
    mockResolveKeyViaHttps.mockResolvedValue("EEEE");

    const key = await resolver.resolvePublicKey(
      "eve::example.com",
      "token",
      "https://relay.example.com"
    );

    // Should fall back to HTTPS since v != uam1
    expect(key).toBe("EEEE");
  });
});
