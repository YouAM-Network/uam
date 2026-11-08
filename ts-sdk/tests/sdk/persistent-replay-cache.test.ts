/**
 * PersistentReplayCache: inbound (sender, message id) pairs kept on disk.
 *
 * Stored mail can reach an agent days after it was sent, so the replay cache
 * has to outlive the process and hold ids for the whole window an envelope
 * can be accepted in. The file is the same one the Python SDK uses.
 */

import { execFile } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";

import Database from "better-sqlite3";
import { buildSync } from "esbuild";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { MAX_ENVELOPE_AGE } from "../../src/protocol/index.js";
import {
  PersistentReplayCache,
  RETENTION_SECONDS,
} from "../../src/sdk/replay-cache.js";

const ALICE = "alice::test.local";
const START = 1_000_000_000;

let dir: string;
let path: string;
let t: number;
const open: PersistentReplayCache[] = [];

function cache(capacity?: number): PersistentReplayCache {
  const c = new PersistentReplayCache(path, { capacity, now: () => t });
  open.push(c);
  return c;
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "uam-replay-"));
  path = join(dir, "replay", "replay.db");
  t = START;
});

afterEach(async () => {
  await Promise.all(open.splice(0).map((c) => c.close()));
  rmSync(dir, { recursive: true, force: true });
});

describe("PersistentReplayCache", () => {
  it("first sighting is new, second is a replay", async () => {
    const c = cache();
    expect(await c.seenOrRecord(ALICE, "m1", t)).toBe(false);
    expect(await c.seenOrRecord(ALICE, "m1", t)).toBe(true);
    expect(await c.seenOrRecord("carol::test.local", "m1", t)).toBe(false);
  });

  it("remembers across instances", async () => {
    const first = cache();
    await first.seenOrRecord(ALICE, "m1", t);
    await first.close();

    expect(await cache().seenOrRecord(ALICE, "m1", t)).toBe(true);
  });

  it("keeps ids for the whole retention window", async () => {
    const c = cache();
    await c.seenOrRecord(ALICE, "m1", t);
    t += (RETENTION_SECONDS - 1) * 1000;
    expect(await c.seenOrRecord(ALICE, "m1", t)).toBe(true);
  });

  it("purges ids past retention", async () => {
    const c = cache();
    await c.seenOrRecord(ALICE, "old", t);
    t += (RETENTION_SECONDS + 1) * 1000;
    await c.seenOrRecord(ALICE, "new", t);
    expect(await c.count()).toBe(1);
  });

  it("retains seven days plus the window on both sides", () => {
    expect(RETENTION_SECONDS).toBe(7 * 86400 + 2 * MAX_ENVELOPE_AGE);
  });

  it("when full, evicts nothing and accepts only fresh envelopes", async () => {
    const c = cache(2);
    await c.seenOrRecord(ALICE, "m1", t);
    await c.seenOrRecord(ALICE, "m2", t);

    const old = t - (MAX_ENVELOPE_AGE + 60) * 1000;
    expect(await c.seenOrRecord(ALICE, "m3", old)).toBe(true);
    expect(await c.seenOrRecord(ALICE, "m1", t)).toBe(true);

    expect(await c.seenOrRecord(ALICE, "m4", t)).toBe(false);
    expect(await c.seenOrRecord(ALICE, "m4", t)).toBe(true);
    expect(await c.count()).toBe(2);
  });

  it("catches an envelope accepted while full after room opens up", async () => {
    const c = cache(2);
    await c.seenOrRecord(ALICE, "m1", t);
    t += (RETENTION_SECONDS - 30) * 1000;
    await c.seenOrRecord(ALICE, "m2", t);

    expect(await c.seenOrRecord(ALICE, "m3", t)).toBe(false);

    t += 60_000; // m1 expires at the next purge, so the file has room again
    expect(await c.seenOrRecord(ALICE, "m3", t)).toBe(true);
  });

  it("while full, catches a repeat for as long as it could be accepted", async () => {
    const c = cache(1);
    await c.seenOrRecord(ALICE, "m1", t);

    // Signed ahead of our clock: fresh until MAX_ENVELOPE_AGE after that.
    const signed = t + MAX_ENVELOPE_AGE * 1000;
    expect(await c.seenOrRecord(ALICE, "m2", signed)).toBe(false);

    t += (2 * MAX_ENVELOPE_AGE - 1) * 1000;
    expect(await c.seenOrRecord(ALICE, "m2", signed)).toBe(true);
  });

  it("writes created_at once", async () => {
    const first = cache();
    expect(await first.createdAt()).toBe(START);
    await first.close();

    t += 3_600_000;
    const second = cache();
    expect(await second.createdAt()).toBe(START);
    expect(await second.signedBeforeCache(START - 1000)).toBe(true);
    expect(await second.signedBeforeCache(START + 1000)).toBe(false);
  });

  it("opens on first use and creates its directory", async () => {
    const c = cache();
    expect(existsSync(path)).toBe(false);
    await c.seenOrRecord(ALICE, "m1", t);
    expect(existsSync(path)).toBe(true);
  });

  it("can be closed twice, and reopens when used again", async () => {
    const c = cache();
    await c.close();
    await c.seenOrRecord(ALICE, "m1", t);
    await c.close();
    await c.close();
    expect(await c.seenOrRecord(ALICE, "m1", t)).toBe(true);
  });

  it("opens once when first used by concurrent callers", async () => {
    const c = cache();
    const results = await Promise.all([
      c.seenOrRecord(ALICE, "m1", t),
      c.seenOrRecord(ALICE, "m1", t),
      c.createdAt(),
    ]);
    expect(results.slice(0, 2).sort()).toEqual([false, true]);
  });

  it.each([0, -1, 1.5])("refuses capacity %d", (capacity) => {
    expect(() => new PersistentReplayCache(path, { capacity })).toThrow(RangeError);
  });

  it("can open again after a failed open", async () => {
    mkdirSync(path, { recursive: true }); // a directory where the file goes
    const c = cache();
    await expect(c.seenOrRecord(ALICE, "m1", t)).rejects.toThrow();

    rmSync(path, { recursive: true });
    expect(await c.seenOrRecord(ALICE, "m1", t)).toBe(false);
  });

  it("waits out a lock on the switch to WAL", async () => {
    mkdirSync(dirname(path), { recursive: true });
    const other = new Database(path);
    other.exec("CREATE TABLE held (x)");
    other.exec("BEGIN EXCLUSIVE");
    setTimeout(() => {
      other.exec("COMMIT");
      other.close();
    }, 250);

    expect(await cache().seenOrRecord(ALICE, "m1", t)).toBe(false);
  });
});

describe("the file", () => {
  it("has the Python SDK's schema, in seconds", async () => {
    const c = cache();
    await c.seenOrRecord(ALICE, "m1", t);
    await c.close();

    const db = new Database(path, { readonly: true });
    try {
      expect(db.pragma("journal_mode", { simple: true })).toBe("wal");
      expect(db.prepare("SELECT * FROM seen_envelopes").all()).toEqual([
        { from_address: ALICE, message_id: "m1", seen_at: START / 1000 },
      ]);
      const meta = db.prepare("SELECT key, value FROM replay_meta").all() as Array<{
        key: string;
        value: string;
      }>;
      expect(meta).toHaveLength(1);
      expect(meta[0].key).toBe("created_at");
      expect(Number(meta[0].value)).toBe(START / 1000);
    } finally {
      db.close();
    }
  });

  it("reads a file the Python SDK wrote", async () => {
    mkdirSync(dirname(path), { recursive: true });
    const db = new Database(path);
    db.pragma("journal_mode = WAL");
    db.exec(`
      CREATE TABLE seen_envelopes (
        from_address TEXT NOT NULL,
        message_id   TEXT NOT NULL,
        seen_at      REAL NOT NULL,
        PRIMARY KEY (from_address, message_id)
      ) WITHOUT ROWID;
      CREATE INDEX seen_envelopes_seen_at ON seen_envelopes (seen_at);
      CREATE TABLE replay_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      INSERT INTO replay_meta VALUES ('created_at', '999999.5');
      INSERT INTO seen_envelopes VALUES ('${ALICE}', 'm1', 999999.75);
    `);
    db.close();

    const c = cache();
    expect(await c.createdAt()).toBe(999_999_500);
    expect(await c.seenOrRecord(ALICE, "m1", t)).toBe(true);
  });
});

describe("two processes", () => {
  const execute = promisify(execFile);

  it("agree on one new and the rest replays, on a brand-new file", async () => {
    // Bundled beside node_modules so the child can resolve better-sqlite3.
    const here = resolve(__dirname, "../..");
    const build = mkdtempSync(join(here, "node_modules", ".uam-replay-test-"));
    try {
      buildSync({
        entryPoints: [join(here, "src/sdk/replay-cache.ts")],
        outfile: join(build, "replay-cache.mjs"),
        bundle: true,
        platform: "node",
        format: "esm",
        packages: "external",
      });
      const child = join(build, "child.mjs");
      writeFileSync(
        child,
        `import { PersistentReplayCache } from "./replay-cache.mjs";
         const [path, startAt] = process.argv.slice(2);
         await new Promise((r) => setTimeout(r, Number(startAt) - Date.now()));
         const cache = new PersistentReplayCache(path);
         console.log(await cache.seenOrRecord("${ALICE}", "m1", Date.now()));
         await cache.close();`
      );

      const startAt = String(Date.now() + 1000);
      const runs = await Promise.all(
        Array.from({ length: 6 }, () =>
          execute(process.execPath, [child, path, startAt])
        )
      );
      const answers = runs.map((r) => r.stdout.trim()).sort();
      expect(answers).toEqual(["false", "true", "true", "true", "true", "true"]);
    } finally {
      rmSync(build, { recursive: true, force: true });
    }
  });
});
