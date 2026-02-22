import { defineConfig } from "vitest/config";
import { resolve } from "node:path";

export default defineConfig({
  test: {
    environment: "node",
    globals: true,
    testTimeout: 30000, // 30s timeout for crypto init
    include: ["tests/**/*.test.ts"],
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
