/**
 * Unit tests for the in-memory inbound replay cache (LRU + TTL).
 */

import { describe, it, expect } from "vitest";

import { EnvelopeReplayCache } from "../../src/sdk/replay-cache.js";

function clock(start = 1_000_000) {
  let t = start;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

describe("EnvelopeReplayCache", () => {
  it("first sighting is recorded, second is a replay", () => {
    const cache = new EnvelopeReplayCache();
    expect(cache.seenOrRecord("alice::x.test", "m1")).toBe(false);
    expect(cache.seenOrRecord("alice::x.test", "m1")).toBe(true);
  });

  it("is keyed by sender and message id together", () => {
    const cache = new EnvelopeReplayCache();
    expect(cache.seenOrRecord("alice::x.test", "m1")).toBe(false);
    expect(cache.seenOrRecord("bob::x.test", "m1")).toBe(false);
    expect(cache.seenOrRecord("alice::x.test", "m2")).toBe(false);
  });

  it("does not confuse keys that only differ in where the split falls", () => {
    const cache = new EnvelopeReplayCache();
    expect(cache.seenOrRecord("a", "bc")).toBe(false);
    expect(cache.seenOrRecord("ab", "c")).toBe(false);
  });

  it("entries older than the TTL are treated as new", () => {
    const c = clock();
    const cache = new EnvelopeReplayCache({ ttlMs: 300_000, now: c.now });
    cache.seenOrRecord("alice::x.test", "m1");
    c.advance(299_999);
    expect(cache.seenOrRecord("alice::x.test", "m1")).toBe(true);
    c.advance(300_000);
    expect(cache.seenOrRecord("alice::x.test", "m1")).toBe(false);
  });

  it("evicts the least recently used entry at capacity", () => {
    const cache = new EnvelopeReplayCache({ capacity: 2 });
    cache.seenOrRecord("a", "1");
    cache.seenOrRecord("a", "2");
    // Touch "1" so "2" becomes the least recently used.
    expect(cache.seenOrRecord("a", "1")).toBe(true);
    cache.seenOrRecord("a", "3");

    expect(cache.size).toBe(2);
    expect(cache.seenOrRecord("a", "1")).toBe(true);
    expect(cache.seenOrRecord("a", "2")).toBe(false); // was evicted
  });

  it("rejects a non-positive capacity", () => {
    expect(() => new EnvelopeReplayCache({ capacity: 0 })).toThrow();
  });
});
