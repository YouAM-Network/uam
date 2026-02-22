/**
 * Tests for Tier3Resolver (on-chain namespace lookup via UAMNameRegistry).
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Use vi.hoisted() so mock variables are available when vi.mock factory runs
const { mockReadContract, mockCreatePublicClient } = vi.hoisted(() => {
  const mockReadContract = vi.fn();
  const mockCreatePublicClient = vi.fn(() => ({
    readContract: mockReadContract,
  }));
  return { mockReadContract, mockCreatePublicClient };
});

vi.mock("viem", () => ({
  createPublicClient: mockCreatePublicClient,
  http: vi.fn((url: string) => ({ url, type: "http" })),
  defineChain: vi.fn((def: Record<string, unknown>) => def),
}));

import { Tier3Resolver, type Tier3Config } from "../../src/sdk/tier3.js";
import { SmartResolver } from "../../src/sdk/resolver.js";
import { UAMError } from "../../src/protocol/index.js";

const TEST_CONFIG: Tier3Config = {
  contractAddress: "0x1234567890abcdef1234567890abcdef12345678",
  rpcUrl: "https://test-rpc.example.com",
  cacheTtlMs: 3600_000,
};

function mockResolveResult(publicKey = "ed25519:TESTKEY123") {
  return [
    "0x0000000000000000000000000000000000000001", // owner
    publicKey, // publicKey
    "https://relay.example.com", // relayUrl
    BigInt(9999999999), // expiry
  ] as const;
}

describe("Tier3Resolver", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("resolvePublicKey returns public key from contract", async () => {
    mockReadContract.mockResolvedValueOnce(mockResolveResult());

    const resolver = new Tier3Resolver(TEST_CONFIG);
    const key = await resolver.resolvePublicKey(
      "scout::acme",
      "tok",
      "http://relay"
    );

    expect(key).toBe("ed25519:TESTKEY123");
    expect(mockReadContract).toHaveBeenCalledOnce();
    expect(mockReadContract).toHaveBeenCalledWith(
      expect.objectContaining({
        functionName: "resolve",
        args: ["acme"],
      })
    );
  });

  it("cache hit skips RPC call", async () => {
    mockReadContract.mockResolvedValue(mockResolveResult());

    const resolver = new Tier3Resolver(TEST_CONFIG);

    const key1 = await resolver.resolvePublicKey(
      "scout::acme",
      "tok",
      "http://relay"
    );
    const key2 = await resolver.resolvePublicKey(
      "scout::acme",
      "tok",
      "http://relay"
    );

    expect(key1).toBe("ed25519:TESTKEY123");
    expect(key2).toBe("ed25519:TESTKEY123");
    // Only one RPC call -- second was served from cache
    expect(mockReadContract).toHaveBeenCalledOnce();
  });

  it("expired cache triggers fresh RPC", async () => {
    mockReadContract.mockResolvedValue(mockResolveResult());

    const resolver = new Tier3Resolver({
      ...TEST_CONFIG,
      cacheTtlMs: 1, // 1ms TTL -- expires almost immediately
    });

    await resolver.resolvePublicKey("scout::acme", "tok", "http://relay");

    // Wait for cache to expire
    await new Promise((r) => setTimeout(r, 10));

    await resolver.resolvePublicKey("scout::acme", "tok", "http://relay");

    expect(mockReadContract).toHaveBeenCalledTimes(2);
  });

  it("NameNotFound revert throws UAMError", async () => {
    mockReadContract.mockRejectedValue(
      new Error("execution reverted: NameNotFound")
    );

    const resolver = new Tier3Resolver(TEST_CONFIG);

    await expect(
      resolver.resolvePublicKey("scout::unknown", "tok", "http://relay")
    ).rejects.toThrow(UAMError);

    const resolver2 = new Tier3Resolver(TEST_CONFIG);
    await expect(
      resolver2.resolvePublicKey("scout::unknown", "tok", "http://relay")
    ).rejects.toThrow(/Tier 3 name not found on-chain/);
  });

  it("RPC connection error throws UAMError", async () => {
    mockReadContract.mockRejectedValue(
      new Error("Failed to connect to RPC endpoint")
    );

    const resolver = new Tier3Resolver(TEST_CONFIG);

    await expect(
      resolver.resolvePublicKey("scout::acme", "tok", "http://relay")
    ).rejects.toThrow(UAMError);

    const resolver2 = new Tier3Resolver(TEST_CONFIG);
    await expect(
      resolver2.resolvePublicKey("scout::acme", "tok", "http://relay")
    ).rejects.toThrow(/Tier 3 resolution failed/);
  });

  it("empty public key throws UAMError", async () => {
    mockReadContract.mockResolvedValueOnce(mockResolveResult(""));

    const resolver = new Tier3Resolver(TEST_CONFIG);

    await expect(
      resolver.resolvePublicKey("scout::acme", "tok", "http://relay")
    ).rejects.toThrow(/has no public key registered/);
  });

  it("isAvailable returns true for unregistered name", async () => {
    mockReadContract.mockResolvedValueOnce(true);

    const resolver = new Tier3Resolver(TEST_CONFIG);
    const available = await resolver.isAvailable("newname");

    expect(available).toBe(true);
    expect(mockReadContract).toHaveBeenCalledWith(
      expect.objectContaining({
        functionName: "available",
        args: ["newname"],
      })
    );
  });

  it("isAvailable returns false on error", async () => {
    mockReadContract.mockRejectedValueOnce(new Error("RPC error"));

    const resolver = new Tier3Resolver(TEST_CONFIG);
    const available = await resolver.isAvailable("somename");

    expect(available).toBe(false);
  });

  it("invalidateCache clears specific name", async () => {
    mockReadContract.mockResolvedValue(mockResolveResult());

    const resolver = new Tier3Resolver(TEST_CONFIG);

    // Populate cache
    await resolver.resolvePublicKey("scout::acme", "tok", "http://relay");
    expect(mockReadContract).toHaveBeenCalledTimes(1);

    // Invalidate
    resolver.invalidateCache("acme");

    // Next call should hit RPC again
    await resolver.resolvePublicKey("scout::acme", "tok", "http://relay");
    expect(mockReadContract).toHaveBeenCalledTimes(2);
  });

  it("invalidateCache with no args clears all", async () => {
    mockReadContract.mockResolvedValue(mockResolveResult());

    const resolver = new Tier3Resolver(TEST_CONFIG);

    // Populate cache with two entries
    await resolver.resolvePublicKey("alice::alpha", "tok", "http://relay");
    await resolver.resolvePublicKey("bob::bravo", "tok", "http://relay");
    expect(mockReadContract).toHaveBeenCalledTimes(2);

    // Clear all
    resolver.invalidateCache();

    // Both should hit RPC again
    await resolver.resolvePublicKey("alice::alpha", "tok", "http://relay");
    await resolver.resolvePublicKey("bob::bravo", "tok", "http://relay");
    expect(mockReadContract).toHaveBeenCalledTimes(4);
  });
});

describe("SmartResolver Tier3 routing", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("routes dot-free domain to Tier3Resolver", async () => {
    mockReadContract.mockResolvedValueOnce(mockResolveResult("ONCHAINKEY"));

    const resolver = new SmartResolver("youam.network", TEST_CONFIG);

    const key = await resolver.resolvePublicKey(
      "scout::acme",
      "tok",
      "http://relay"
    );

    expect(key).toBe("ONCHAINKEY");
    expect(mockReadContract).toHaveBeenCalledOnce();
  });

  it("throws if no tier3Config for dot-free domain", async () => {
    const resolver = new SmartResolver("youam.network");

    await expect(
      resolver.resolvePublicKey("scout::acme", "tok", "http://relay")
    ).rejects.toThrow(/Tier 3 resolution requires contract config/);
  });
});
