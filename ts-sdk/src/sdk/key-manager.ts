/**
 * Ed25519 key generation, storage, loading, and token persistence.
 *
 * Matches Python key_manager.py: stores 32-byte seed (not 64-byte secret key),
 * uses same file format so keys are cross-language compatible.
 */

import {
  chmodSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";
import { platform } from "node:os";

import {
  type Keypair,
  type SigningKey,
  type VerifyKey,
  type Seed,
  generateKeypair,
  serializeSigningKey,
  deserializeSigningKey,
  serializeVerifyKey,
} from "../protocol/index.js";

const DEFAULT_KEY_DIR = join(homedir(), ".uam", "keys");

export class KeyManager {
  private _keyDir: string;
  private _keypair: Keypair | null = null;

  constructor(keyDir?: string | null) {
    this._keyDir = keyDir ?? DEFAULT_KEY_DIR;
  }

  /** The 64-byte Ed25519 signing key. Throws if not loaded. */
  get signingKey(): SigningKey {
    if (this._keypair === null) {
      throw new Error("No keypair loaded. Call loadOrGenerate() first.");
    }
    return this._keypair.signingKey;
  }

  /** The 32-byte Ed25519 verify (public) key. Throws if not loaded. */
  get verifyKey(): VerifyKey {
    if (this._keypair === null) {
      throw new Error("No keypair loaded. Call loadOrGenerate() first.");
    }
    return this._keypair.verifyKey;
  }

  /** The 32-byte seed. Throws if not loaded. */
  get seed(): Seed {
    if (this._keypair === null) {
      throw new Error("No keypair loaded. Call loadOrGenerate() first.");
    }
    return this._keypair.seed;
  }

  /**
   * Load existing keypair or generate a new one.
   *
   * First-run: generates keypair, writes {name}.key and {name}.pub,
   * sets 0o600 permissions on the private key.
   *
   * Returning user: loads from disk, warns if permissions too permissive.
   */
  loadOrGenerate(name: string): void {
    mkdirSync(this._keyDir, { recursive: true });
    const keyPath = join(this._keyDir, `${name}.key`);
    const pubPath = join(this._keyDir, `${name}.pub`);

    if (existsSync(keyPath)) {
      // Returning user: load existing keys
      this._checkPermissions(keyPath);
      const seedB64 = readFileSync(keyPath, "utf-8").trim();
      this._keypair = deserializeSigningKey(seedB64);
    } else {
      // First-run: generate new keypair
      this._keypair = generateKeypair();
      writeFileSync(keyPath, serializeSigningKey(this._keypair.seed));
      writeFileSync(pubPath, serializeVerifyKey(this._keypair.verifyKey));
      this._setPermissions(keyPath);
    }
  }

  /**
   * Store the relay token alongside the keypair.
   */
  saveToken(name: string, token: string): void {
    const tokenPath = join(this._keyDir, `${name}.token`);
    writeFileSync(tokenPath, token);
    this._setPermissions(tokenPath);
  }

  /**
   * Load a previously saved token, or return null.
   *
   * Also checks for legacy .api_key files for backward compatibility.
   */
  loadToken(name: string): string | null {
    const tokenPath = join(this._keyDir, `${name}.token`);
    if (existsSync(tokenPath)) {
      return readFileSync(tokenPath, "utf-8").trim();
    }
    // Backward compatibility: check for legacy .api_key file
    const legacyPath = join(this._keyDir, `${name}.api_key`);
    if (existsSync(legacyPath)) {
      return readFileSync(legacyPath, "utf-8").trim();
    }
    return null;
  }

  /** Set file permissions to 0o600 (owner read/write only). */
  private _setPermissions(path: string): void {
    if (platform() !== "win32") {
      chmodSync(path, 0o600);
    }
  }

  /** Warn if key file permissions are too permissive. */
  private _checkPermissions(path: string): void {
    if (platform() === "win32") {
      return; // Cannot reliably check on Windows
    }
    try {
      const mode = statSync(path).mode & 0o777;
      if (mode !== 0o600) {
        console.warn(
          `Key file ${path} has permissions ${mode.toString(8)} (expected 600). ` +
            `Run: chmod 600 ${path}`
        );
      }
    } catch {
      // Ignore stat errors
    }
  }
}
