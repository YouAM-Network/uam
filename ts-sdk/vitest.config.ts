import { defineConfig } from "vitest/config";
import { resolve } from "node:path";
import { readFileSync } from "node:fs";

const { version } = JSON.parse(
  readFileSync(resolve(__dirname, "package.json"), "utf-8")
) as { version: string };

export default defineConfig({
  // Same build-time constant tsup injects (see src/version.ts).
  define: { __UAM_SDK_VERSION__: JSON.stringify(version) },
  test: {
    environment: "node",
    globals: true,
    testTimeout: 30000, // 30s timeout for crypto init
    include: ["tests/**/*.test.ts"],
    setupFiles: ["tests/setup-env.ts"],
  },
  resolve: {
    alias: {
      // Force CJS resolution for libsodium-wrappers (ESM build is broken)
      "libsodium-wrappers": resolve(
        __dirname,
        "node_modules/libsodium-wrappers/dist/modules/libsodium-wrappers.js"
      ),
    },
  },
});
