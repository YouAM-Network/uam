/**
 * resolver.ts must be importable on its own, as the first module in a fresh
 * module graph. A resolver.ts <-> tier3.ts import cycle used to leave
 * AddressResolver undefined when tier3.ts evaluated, so anything importing
 * resolver.ts (or agent.ts) first crashed with
 * "Class extends value undefined is not a constructor or null".
 */

import { describe, it, expect } from "vitest";

describe("resolver module import order", () => {
  it("importing resolver.ts first yields usable resolver classes", async () => {
    const mod = await import("../../src/sdk/resolver.js");
    const smart = new mod.SmartResolver("relay.test");
    expect(smart).toBeInstanceOf(mod.AddressResolver);
    expect(typeof mod.Tier3Resolver).toBe("function");
    expect(Object.getPrototypeOf(mod.Tier3Resolver)).toBe(mod.AddressResolver);
  });
});
