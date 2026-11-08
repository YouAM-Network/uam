#!/usr/bin/env node
/**
 * Install the packed tarball into a clean project and use it from ESM and
 * CommonJS, the way a consumer would. Run `npm run build` first.
 */

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Runs against the installed package. `sdk` is its root export. */
const checks = `
  const { protocol } = sdk;
  await protocol.sodiumReady;
  const keypair = protocol.generateKeypair();
  const signature = protocol.signMessage(new Uint8Array([1, 2, 3]), keypair.signingKey);
  protocol.verifySignature(new Uint8Array([1, 2, 3]), signature, keypair.verifyKey);
  if (typeof sdk.Agent !== "function") throw new Error("Agent is not exported");

  const book = new sdk.ContactBook(process.argv[2]);
  book.open();
  book.addContact("alice::youam.test", "a-key", { trustState: "trusted" });
  if (!book.isKnown("alice::youam.test")) throw new Error("ContactBook lost a contact");
  book.close();

  const secret = "a-secret";
  const body = Buffer.from("payload");
  const hmac = crypto.createHmac("sha256", secret).update(body).digest("hex");
  if (!sdk.verifyWebhookSignature(body, "sha256=" + hmac, secret)) {
    throw new Error("verifyWebhookSignature rejected a good signature");
  }
`;

const esm = `
import crypto from "node:crypto";
import * as sdk from "@youam/sdk";
${checks}
console.log("ESM ok");
`;

const cjs = `
const crypto = require("node:crypto");
const sdk = require("@youam/sdk");
(async () => {
${checks}
  console.log("CJS ok");
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
`;

function run(command, args, cwd) {
  return execFileSync(command, args, {
    cwd,
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "inherit"],
  });
}

if (!existsSync(join(packageDir, "dist", "index.js"))) {
  console.error("No build found: run `npm run build` first.");
  process.exit(1);
}

const work = mkdtempSync(join(tmpdir(), "uam-smoke-"));
try {
  const [packed] = JSON.parse(
    run("npm", ["pack", "--json", "--pack-destination", work], packageDir)
  );
  for (const required of ["LICENSE", "README.md", "dist/index.js", "dist/index.cjs"]) {
    if (!packed.files.some((file) => file.path === required)) {
      throw new Error(`${required} is not in the tarball`);
    }
  }

  const project = join(work, "project");
  mkdirSync(project);
  writeFileSync(join(project, "package.json"), '{"name":"smoke","private":true}\n');
  run("npm", ["install", "--no-audit", "--no-fund", join(work, packed.filename)], project);

  writeFileSync(join(project, "smoke.mjs"), esm);
  writeFileSync(join(project, "smoke.cjs"), cjs);
  for (const [script, dataDir] of [
    ["smoke.mjs", "data-esm"],
    ["smoke.cjs", "data-cjs"],
  ]) {
    mkdirSync(join(project, dataDir));
    process.stdout.write(run(process.execPath, [script, dataDir], project));
  }
} finally {
  rmSync(work, { recursive: true, force: true });
}
