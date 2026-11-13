/**
 * The version the SDK and CLI report must be the package's version.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { SDK_VERSION } from "../../src/version.js";
import { Agent } from "../../src/sdk/agent.js";

const pkg = JSON.parse(
  readFileSync(resolve(__dirname, "../../package.json"), "utf-8")
) as { version: string };

describe("SDK version", () => {
  it("package version is 0.4.0", () => {
    expect(pkg.version).toBe("0.4.0");
  });

  it("SDK_VERSION matches package.json", () => {
    expect(SDK_VERSION).toBe(pkg.version);
  });

  it("Agent.version reports the package version", () => {
    const agent = new Agent("versiontest", { transport: "http" });
    expect(agent.version).toBe(pkg.version);
  });

  it("CLI --version reports the package version", () => {
    const cliSource = readFileSync(
      resolve(__dirname, "../../src/cli/index.ts"),
      "utf-8"
    );
    expect(cliSource).toMatch(/\.version\(SDK_VERSION\)/);
  });
});
