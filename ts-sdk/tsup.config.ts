import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: ["src/index.ts"],
    format: ["esm", "cjs"],
    dts: true,
    splitting: false,
    sourcemap: true,
    clean: true,
    outDir: "dist",
    external: ["better-sqlite3", "ws", "libsodium-wrappers"],
    target: "node18",
  },
  {
    entry: ["src/cli/index.ts"],
    format: ["cjs"],
    outDir: "dist/cli",
    banner: { js: "#!/usr/bin/env node" },
    external: ["better-sqlite3", "ws", "libsodium-wrappers"],
    target: "node18",
  },
]);
