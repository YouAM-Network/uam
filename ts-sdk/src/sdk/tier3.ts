/**
 * Tier 3 resolver: on-chain namespace lookup via UAMNameRegistry (TSSDK-09).
 *
 * Uses viem for contract reads on Base Sepolia/Base L2.
 */

import { createPublicClient, http, type Address, defineChain } from "viem";
import { UAMError } from "../protocol/index.js";
import { parseAddress } from "../protocol/address.js";
import { AddressResolver } from "./resolver.js";

// Default config
const DEFAULT_RPC_URL = "https://sepolia.base.org";
const DEFAULT_CHAIN_ID = 84532; // Base Sepolia

// Cache TTL: 1 hour in milliseconds
const CACHE_TTL_MS = 3600 * 1000;

// Minimal ABI for resolve() and available() -- inline to avoid file I/O
const REGISTRY_ABI = [
  {
    name: "resolve",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "name", type: "string" }],
    outputs: [
      { name: "owner", type: "address" },
      { name: "publicKey", type: "string" },
      { name: "relayUrl", type: "string" },
      { name: "expiry", type: "uint256" },
    ],
  },
  {
    name: "available",
    type: "function",
    stateMutability: "view",
    inputs: [{ name: "name", type: "string" }],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

interface CacheEntry {
  publicKey: string;
  expiresAt: number; // Date.now() + TTL
}

export interface Tier3Config {
  contractAddress: string;
  rpcUrl?: string;
  chainId?: number;
  cacheTtlMs?: number;
}

/**
 * Build a minimal chain definition for viem.
 * Using defineChain avoids importing chain-specific types from viem/chains
 * which cause TypeScript compatibility issues with generic PublicClient.
 */
function buildChain(chainId: number, rpcUrl: string) {
  return defineChain({
    id: chainId,
    name: `chain-${chainId}`,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: {
      default: { http: [rpcUrl] },
    },
  });
}

/**
 * Resolve agent addresses via on-chain UAMNameRegistry contract.
 *
 * Uses viem PublicClient to call resolve() on the contract.
 * Caches results for 1 hour to minimize RPC calls.
 */
export class Tier3Resolver extends AddressResolver {
  private _contractAddress: Address;
  private _client: ReturnType<typeof createPublicClient>;
  private _cacheTtlMs: number;
  private _cache: Map<string, CacheEntry> = new Map();

  constructor(config: Tier3Config) {
    super();
    this._contractAddress = config.contractAddress as Address;
    this._cacheTtlMs = config.cacheTtlMs ?? CACHE_TTL_MS;
    const rpcUrl = config.rpcUrl ?? DEFAULT_RPC_URL;
    const chainId = config.chainId ?? DEFAULT_CHAIN_ID;
    this._client = createPublicClient({
      chain: buildChain(chainId, rpcUrl),
      transport: http(rpcUrl),
    });
  }

  async resolvePublicKey(
    address: string,
    _token: string,
    _relayUrl: string
  ): Promise<string> {
    const parsed = parseAddress(address);
    const name = parsed.domain; // For Tier 3, domain IS the namespace

    // Check cache
    const cached = this._cache.get(name);
    if (cached && cached.expiresAt > Date.now()) {
      return cached.publicKey;
    }

    // Call contract
    try {
      const result = await this._client.readContract({
        address: this._contractAddress,
        abi: REGISTRY_ABI,
        functionName: "resolve",
        args: [name],
      });

      const [_owner, publicKey, _relayUrl2, _expiry] = result;

      if (!publicKey) {
        throw new UAMError(
          `Tier 3 name '${name}' has no public key registered`
        );
      }

      // Cache result
      this._cache.set(name, {
        publicKey,
        expiresAt: Date.now() + this._cacheTtlMs,
      });

      return publicKey;
    } catch (err) {
      if (err instanceof UAMError) throw err;
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("NameNotFound") || msg.includes("revert")) {
        throw new UAMError(`Tier 3 name not found on-chain: ${name}`);
      }
      throw new UAMError(`Tier 3 resolution failed for ${name}: ${msg}`);
    }
  }

  /**
   * Check if a name is available for registration.
   */
  async isAvailable(name: string): Promise<boolean> {
    try {
      const result = await this._client.readContract({
        address: this._contractAddress,
        abi: REGISTRY_ABI,
        functionName: "available",
        args: [name],
      });
      return result;
    } catch {
      return false;
    }
  }

  /**
   * Clear cache for a specific name or all names.
   */
  invalidateCache(name?: string): void {
    if (name) {
      this._cache.delete(name);
    } else {
      this._cache.clear();
    }
  }
}
