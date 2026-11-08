/**
 * Isolate every test file from the developer's UAM environment.
 *
 * SDKConfig reads UAM_RELAY_URL / UAM_RELAY_DOMAIN / UAM_TRUST_POLICY /
 * UAM_HOME, so a shell that has them set (e.g. a local relay) changes test
 * outcomes, and an unset UAM_HOME lets tests write into the real ~/.uam.
 * Tests that exercise these variables set them explicitly.
 */

import { mkdtempSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

for (const name of Object.keys(process.env)) {
  if (name.startsWith("UAM_") && name !== "UAM_WRITE_FIXTURES") {
    delete process.env[name];
  }
}
process.env["UAM_HOME"] = mkdtempSync(join(tmpdir(), "uam-test-home-"));
