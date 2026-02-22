import { describe, it, expect } from "vitest";
import { parseAddress, Address } from "../../src/protocol/address.js";
import { InvalidAddressError } from "../../src/protocol/errors.js";

describe("parseAddress", () => {
  it("parses a standard address", () => {
    const addr = parseAddress("alice::example.com");
    expect(addr.agent).toBe("alice");
    expect(addr.domain).toBe("example.com");
    expect(addr.full).toBe("alice::example.com");
  });

  it("parses minimal address (single char agent)", () => {
    const addr = parseAddress("a::b");
    expect(addr.agent).toBe("a");
    expect(addr.domain).toBe("b");
    expect(addr.full).toBe("a::b");
  });

  it("parses address with hyphens and subdomains", () => {
    const addr = parseAddress("my-agent::test.domain.com");
    expect(addr.agent).toBe("my-agent");
    expect(addr.domain).toBe("test.domain.com");
  });

  it("normalizes to lowercase", () => {
    const addr = parseAddress("ALICE::EXAMPLE.COM");
    expect(addr.agent).toBe("alice");
    expect(addr.domain).toBe("example.com");
    expect(addr.full).toBe("alice::example.com");
  });

  it("strips whitespace", () => {
    const addr = parseAddress("  alice::example.com  ");
    expect(addr.full).toBe("alice::example.com");
  });

  it("rejects empty string", () => {
    expect(() => parseAddress("")).toThrow(InvalidAddressError);
  });

  it("rejects string without delimiter", () => {
    expect(() => parseAddress("nodelimiter")).toThrow(InvalidAddressError);
  });

  it("rejects empty agent", () => {
    expect(() => parseAddress("::empty")).toThrow(InvalidAddressError);
  });

  it("rejects agent starting with hyphen", () => {
    expect(() => parseAddress("-bad::example.com")).toThrow(
      InvalidAddressError
    );
  });

  it("rejects agent ending with hyphen", () => {
    expect(() => parseAddress("bad-::example.com")).toThrow(
      InvalidAddressError
    );
  });

  it("accepts agent with underscore", () => {
    const addr = parseAddress("my_agent::example.com");
    expect(addr.agent).toBe("my_agent");
  });

  it("rejects address exceeding 128 chars total", () => {
    const longAgent = "a".repeat(60);
    const longDomain = "b".repeat(70) + ".com";
    // total: 60 + 2 + 74 = 136 > 128
    expect(() => parseAddress(`${longAgent}::${longDomain}`)).toThrow(
      InvalidAddressError
    );
  });

  it("accepts agent at exactly 64 chars", () => {
    // 64 char agent (starts and ends with alnum)
    const agent = "a" + "b".repeat(62) + "c";
    expect(agent.length).toBe(64);
    const addr = parseAddress(`${agent}::x`);
    expect(addr.agent).toBe(agent);
  });

  it("rejects agent exceeding 64 chars", () => {
    // The regex itself limits to 64 chars (0-62 middle + 2 ends = max 64)
    // But 65 chars should fail regex match
    const agent = "a" + "b".repeat(63) + "c";
    expect(agent.length).toBe(65);
    expect(() => parseAddress(`${agent}::x`)).toThrow(InvalidAddressError);
  });

  it("parses single-char agent names", () => {
    const addr = parseAddress("x::example.com");
    expect(addr.agent).toBe("x");
  });

  it("rejects special characters in agent", () => {
    expect(() => parseAddress("al!ce::example.com")).toThrow(
      InvalidAddressError
    );
    expect(() => parseAddress("al ice::example.com")).toThrow(
      InvalidAddressError
    );
    expect(() => parseAddress("al@ce::example.com")).toThrow(
      InvalidAddressError
    );
  });
});
