import { readFileSync } from "node:fs";
import { defineConfig } from "tsup";

const { version } = JSON.parse(readFileSync("./package.json", "utf-8")) as {
  version: string;
};
const define = { __UAM_SDK_VERSION__: JSON.stringify(version) };

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
    define,
  },
  {
    entry: ["src/cli/index.ts"],
    format: ["cjs"],
    outDir: "dist/cli",
    banner: { js: "#!/usr/bin/env node" },
    external: ["better-sqlite3", "ws", "libsodium-wrappers"],
    target: "node18",
    define,
  },
]);
