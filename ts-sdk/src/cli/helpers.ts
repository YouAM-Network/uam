/**
 * CLI helper utilities shared across commands.
 */

import { readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

/**
 * Scan key directory for a .key file and return the agent name.
 *
 * If exactly one .key file exists, return the name (filename without .key).
 * If multiple exist, return the first alphabetically.
 * If none exist, return null.
 */
export function findAgentName(keyDir?: string): string | null {
  const dir = keyDir ?? join(process.env["UAM_HOME"] ?? join(homedir(), ".uam"), "keys");

  if (!existsSync(dir)) {
    return null;
  }

  const keyFiles = readdirSync(dir)
    .filter((f) => f.endsWith(".key"))
    .sort();

  if (keyFiles.length === 0) {
    return null;
  }

  return keyFiles[0].replace(/\.key$/, "");
}

/**
 * Print an error message to stderr and exit with code 1.
 */
export function cliError(msg: string): never {
  process.stderr.write(msg + "\n");
  process.exit(1);
}
