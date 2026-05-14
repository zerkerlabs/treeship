import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, existsSync, readFileSync, writeFileSync, symlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ship } from "../src/index.js";

// =============================================================================
// Round-trip integration test
//
// Exercises the SDK end-to-end against the real `treeship` CLI binary built
// from this workspace. Anything that mocks the CLI defeats the point of this
// test -- we want to catch SDK <-> CLI integration drift (flag changes, JSON
// schema changes, exit-code semantics) the moment it lands.
//
// Strategy:
//   1. Locate the workspace root by walking up from __dirname until we find
//      `Cargo.toml` with a [workspace] table. Use that to resolve the release
//      binary path: <workspace>/target/release/treeship.
//   2. If the binary is missing OR is from a different workspace version,
//      build it once with `cargo build --release -p treeship-cli`. If `cargo`
//      itself is unavailable, skip the suite.
//   3. The SDK shells out to whatever `treeship` it finds on PATH. To pin it
//      to our just-built binary we create a per-suite shim directory with a
//      symlink named `treeship` -> our binary, and prepend that directory to
//      `process.env.PATH`. The SDK's `execFile` calls inherit this PATH.
//   4. Point `TREESHIP_CONFIG` at a tempdir so we don't touch the developer's
//      real ~/.treeship/ keystore.
// =============================================================================

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

function findWorkspaceRoot(start: string): string {
  let dir = start;
  for (let i = 0; i < 10; i++) {
    const cargo = join(dir, "Cargo.toml");
    if (existsSync(cargo)) {
      const contents = readFileSync(cargo, "utf8");
      if (contents.includes("[workspace]")) return dir;
    }
    const parent = resolve(dir, "..");
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error(`could not find workspace Cargo.toml walking up from ${start}`);
}

function cargoAvailable(): boolean {
  const r = spawnSync("cargo", ["--version"], { stdio: "ignore" });
  return r.status === 0;
}

/**
 * Read the canonical CLI version from packages/cli/Cargo.toml.
 *
 * We use the CLI's Cargo.toml as the source of truth (it's what
 * `treeship version` reports via `env!("CARGO_PKG_VERSION")`). If the
 * file is missing or unparseable we return null and skip the version
 * pin -- better than erroring out an otherwise functional suite.
 */
function readCliCargoVersion(workspaceRoot: string): string | null {
  const cargoToml = join(workspaceRoot, "packages", "cli", "Cargo.toml");
  if (!existsSync(cargoToml)) return null;
  const contents = readFileSync(cargoToml, "utf8");
  // Match the [package].version line, not workspace deps' version fields.
  // We look for `version = "X.Y.Z"` within the first ~30 lines (before
  // [features] / [dependencies]).
  const head = contents.split("\n").slice(0, 30).join("\n");
  const m = head.match(/^version\s*=\s*"([^"]+)"/m);
  return m ? m[1] : null;
}

/**
 * Ask the binary for its version string. `treeship version` prints
 *   "treeship <version> (rust)"
 * Return null if the binary errors out or the format changes.
 */
function readBinaryVersion(binaryPath: string): string | null {
  const r = spawnSync(binaryPath, ["version"], { encoding: "utf8" });
  if (r.status !== 0) return null;
  const m = (r.stdout || "").match(/treeship\s+(\S+)/);
  return m ? m[1] : null;
}

function buildBinary(workspaceRoot: string, binaryPath: string): void {
  // Build the CLI in release mode. This is slow on a cold cache (minutes)
  // but cached afterwards. Tests will time out at the vitest level if cargo
  // is wedged -- that's the correct signal.
  const r = spawnSync(
    "cargo",
    ["build", "--release", "-p", "treeship-cli"],
    { cwd: workspaceRoot, stdio: "inherit" },
  );
  if (r.status !== 0) {
    throw new Error(`cargo build failed with exit code ${r.status}`);
  }
  if (!existsSync(binaryPath)) {
    throw new Error(`cargo build succeeded but binary still missing at ${binaryPath}`);
  }
}

/**
 * Ensure the binary exists AND matches the workspace's declared CLI
 * version. A stale binary from a previous commit would otherwise sail
 * through every assertion -- the whole point of this suite is to catch
 * SDK <-> CLI drift, so a mismatched binary defeats the test.
 *
 * Mismatch policy: rebuild, then continue. Do NOT fail the test --
 * rebuilding is the correct recovery, and forcing a fail would block
 * `vitest --watch` workflows where the developer has just edited Rust
 * code and expects the suite to pick it up.
 */
function ensureBinary(workspaceRoot: string, binaryPath: string): void {
  const expected = readCliCargoVersion(workspaceRoot);

  if (existsSync(binaryPath)) {
    const actual = readBinaryVersion(binaryPath);
    if (expected && actual && actual === expected) {
      return; // up-to-date
    }
    // Mismatch (or couldn't read either side). Force a rebuild rather
    // than silently passing the suite with stale bits.
  }

  buildBinary(workspaceRoot, binaryPath);
}

const WORKSPACE_ROOT = findWorkspaceRoot(__dirname);
const BINARY_PATH    = join(WORKSPACE_ROOT, "target", "release", "treeship");

// Skip the whole suite cleanly if cargo isn't installed. The smoke-test
// suite (sdk.test.ts) still runs in that environment; we just can't drive
// the binary.
const cargoOk = cargoAvailable();
const describeOrSkip = cargoOk ? describe : describe.skip;

describeOrSkip("@treeship/sdk round-trip vs real CLI", () => {
  let sessionDir:  string;
  let shimDir:     string;
  let configPath:  string;
  let storageDir:  string;
  let originalPath: string | undefined;
  let originalTreeshipConfig: string | undefined;
  let setupSucceeded = false;

  beforeAll(() => {
    // Capture env state up-front so the rollback path (if any step below
    // throws) can restore it deterministically. Without this, a partial
    // setup-then-throw leaves PATH and TREESHIP_CONFIG mutated for the
    // rest of the vitest process, which is fine in CI (fresh process)
    // but corrupts subsequent runs under `vitest --watch`.
    originalPath           = process.env.PATH;
    originalTreeshipConfig = process.env.TREESHIP_CONFIG;

    try {
      ensureBinary(WORKSPACE_ROOT, BINARY_PATH);

      // Per-suite scratch dir: holds both the PATH shim and the .treeship/
      // config + keystore.
      sessionDir = mkdtempSync(join(tmpdir(), "treeship-sdk-roundtrip-"));
      shimDir    = join(sessionDir, "bin");
      mkdirSync(shimDir, { recursive: true });
      symlinkSync(BINARY_PATH, join(shimDir, "treeship"));

      configPath = join(sessionDir, ".treeship", "config.json");
      storageDir = join(sessionDir, ".treeship", "artifacts");

      process.env.PATH            = `${shimDir}:${process.env.PATH ?? ""}`;
      process.env.TREESHIP_CONFIG = configPath;

      // Initialize a fresh ship. The SDK doesn't expose `init` -- it's a
      // one-time setup step the operator runs via the CLI -- so we invoke
      // the binary directly. --force is safe here because the path is in
      // a tempdir; the global-keystore guard only trips on the user's
      // resolved ~/.treeship.
      execFileSync(BINARY_PATH, ["init", "--config", configPath, "--force"], {
        stdio: "pipe",
        env:   { ...process.env },
      });

      setupSucceeded = true;
    } catch (err) {
      // Roll back any partial mutations so afterAll's cleanup is a no-op
      // and the rest of the test file (or other suites in the same proc)
      // see clean state.
      if (originalPath === undefined) delete process.env.PATH;
      else process.env.PATH = originalPath;
      if (originalTreeshipConfig === undefined) delete process.env.TREESHIP_CONFIG;
      else process.env.TREESHIP_CONFIG = originalTreeshipConfig;
      if (sessionDir && existsSync(sessionDir)) {
        rmSync(sessionDir, { recursive: true, force: true });
      }
      throw err;
    }
  }, 300_000);  // 5 min: cold cargo build dominates on first run

  afterAll(() => {
    // Always restore env, even if beforeAll partially set things up and
    // then threw -- in that case `setupSucceeded` stays false and the
    // catch block above already rolled back, but a second restore is
    // cheap and idempotent.
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
    if (originalTreeshipConfig === undefined) delete process.env.TREESHIP_CONFIG;
    else process.env.TREESHIP_CONFIG = originalTreeshipConfig;

    if (setupSucceeded && sessionDir && existsSync(sessionDir)) {
      rmSync(sessionDir, { recursive: true, force: true });
    }
  });

  it("CLI binary version is reachable from the SDK's PATH lookup", async () => {
    // checkCli does `treeship version`; the shim must resolve it.
    const v = await (await import("../src/index.js")).Ship.checkCli();
    expect(v).toMatch(/\S+/);  // non-empty version string
  });

  it("attest.action -> verify.verify round-trips with outcome=pass", async () => {
    const s = ship();
    const result = await s.attest.action({
      actor:  "agent:test-runner",
      action: "sdk.roundtrip.write",
      meta:   { source: "roundtrip.test.ts" },
    });

    expect(result.artifactId).toMatch(/^art_/);

    const verified = await s.verify.verify(result.artifactId);
    expect(verified.outcome).toBe("pass");
    expect(verified.target).toBe(result.artifactId);
    expect(verified.chain).toBeGreaterThanOrEqual(1);
  });

  it("tampering with the signature causes verify.verify to fail", async () => {
    const s = ship();

    // Create a fresh receipt to tamper with so we don't interfere with the
    // pass-path test above.
    const { artifactId } = await s.attest.action({
      actor:  "agent:test-runner",
      action: "sdk.roundtrip.tamper",
    });

    // Baseline: it verifies clean.
    const before = await s.verify.verify(artifactId);
    expect(before.outcome).toBe("pass");

    // Tamper: flip one bit in the Ed25519 signature. We mutate the on-disk
    // record at <storage_dir>/<id>.json. The envelope is a DSSE-shaped
    // {payload, payloadType, signatures: [{keyid, sig}]} where `sig` is
    // base64url-encoded raw 64-byte signature bytes.
    const artifactPath = join(storageDir, `${artifactId}.json`);
    expect(existsSync(artifactPath)).toBe(true);

    const record   = JSON.parse(readFileSync(artifactPath, "utf8"));
    const sigB64u  = record.envelope.signatures[0].sig as string;
    expect(typeof sigB64u).toBe("string");
    expect(sigB64u.length).toBeGreaterThan(0);

    // Decode base64url (padded with the right number of '=' for Buffer),
    // flip the low bit of byte 0, re-encode. A single-bit flip in an
    // Ed25519 signature with overwhelming probability produces an invalid
    // signature -- and ed25519-dalek's strict verifier definitely rejects it.
    const padded = sigB64u.replace(/-/g, "+").replace(/_/g, "/")
      + "=".repeat((4 - (sigB64u.length % 4)) % 4);
    const raw = Buffer.from(padded, "base64");
    raw[0]   = raw[0] ^ 0x01;
    const tampered = raw
      .toString("base64")
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    record.envelope.signatures[0].sig = tampered;
    writeFileSync(artifactPath, JSON.stringify(record, null, 2));

    // Confirm verification now fails. The CLI exits non-zero on a bad
    // signature but still emits structured JSON to stdout, which the SDK
    // parses and surfaces as outcome=fail. If this assertion ever flips
    // to pass, something is very wrong with the wiring.
    //
    // Also assert that at least one check actually *failed* in the
    // chain. The SDK exposes the failed count via `chain` on a fail
    // outcome (see verify.ts), so a non-zero value here proves we got
    // here via a genuine signature-verification failure -- not via
    // some other fail mode (empty chain, missing artifact, JSON parse
    // error, etc).
    const after = await s.verify.verify(artifactId);
    expect(after.outcome).toBe("fail");
    expect(after.chain).toBeGreaterThanOrEqual(1);
  });

  it("tampering with the envelope payload causes verify.verify to fail", async () => {
    // Sister test to the sig-tamper case above. Proves that the
    // signature is bound to the *payload bytes* and not just the keyid
    // -- mutate a field inside the base64-encoded payload, leave the
    // original signature untouched, and verify must reject.
    //
    // This catches a class of regression where (hypothetically) verify
    // only validated the signature against the keyid table, or against
    // a re-canonicalized form of the statement, and skipped the actual
    // DSSE pre-authenticated-encoding check that binds sig -> payload
    // bytes.
    const s = ship();
    const { artifactId } = await s.attest.action({
      actor:  "agent:test-runner",
      action: "sdk.roundtrip.payload-tamper",
    });

    const artifactPath = join(storageDir, `${artifactId}.json`);
    expect(existsSync(artifactPath)).toBe(true);

    const record = JSON.parse(readFileSync(artifactPath, "utf8"));

    // DSSE payload is base64-encoded JSON of the statement.
    // Decode -> mutate the `actor` field -> re-encode. Length may change,
    // but DSSE's PAE prefixes lengths, so any change breaks the sig.
    const payloadB64 = record.envelope.payload as string;
    expect(typeof payloadB64).toBe("string");
    expect(payloadB64.length).toBeGreaterThan(0);

    // DSSE uses standard base64 (not base64url) for the payload field.
    const payloadJsonBytes = Buffer.from(payloadB64, "base64");
    const payloadObj = JSON.parse(payloadJsonBytes.toString("utf8"));

    // Mutate a field that the statement actually contains. The action
    // statement carries `actor`, so we change it. If a future schema
    // change renames `actor`, the fallback branch still ensures the
    // bytes diverge.
    if (typeof payloadObj.actor === "string") {
      payloadObj.actor = payloadObj.actor + "-tampered";
    } else {
      payloadObj.__tampered = true;
    }

    record.envelope.payload = Buffer
      .from(JSON.stringify(payloadObj), "utf8")
      .toString("base64");

    writeFileSync(artifactPath, JSON.stringify(record, null, 2));

    const after = await s.verify.verify(artifactId);
    expect(after.outcome).toBe("fail");
    expect(after.chain).toBeGreaterThanOrEqual(1);
  });

  it("hub.status reports disconnected when no hub is configured AND the CLI actually answered", async () => {
    // A fresh init has no hub_connections + no active_hub. With the CLI
    // fix in place (`treeship hub status --format json` emits a real
    // JSON envelope instead of empty stdout), the SDK successfully
    // parses the response and returns `{ connected: false }` via the
    // *happy path* -- NOT via the swallowed-exception fallback in
    // hub.ts's catch block.
    //
    // Before the fix this test was a tautology: the CLI emitted nothing,
    // exec.ts's JSON.parse("") threw, hub.ts swallowed it and returned
    // `{ connected: false }` from its catch arm -- so the test passed
    // regardless of what the CLI actually did.
    //
    // To prove the CLI fix is in effect, we drive the binary directly
    // here and assert the stdout is non-empty parseable JSON with the
    // expected shape. If a future regression breaks the CLI's JSON
    // emission, this assertion fails *and* the SDK call below either
    // throws or returns via the catch arm -- both detectable.

    // 1. Direct CLI assertion: the binary must emit a non-empty JSON
    //    envelope to stdout.
    const cli = spawnSync(
      BINARY_PATH,
      ["hub", "status", "--config", configPath, "--format", "json"],
      { encoding: "utf8" },
    );
    expect(cli.status).toBe(0);
    expect(cli.stdout.trim().length).toBeGreaterThan(0);
    const parsed = JSON.parse(cli.stdout) as Record<string, unknown>;
    expect(parsed.status).toBe("detached");
    expect(parsed.connected).toBe(false);

    // 2. SDK assertion: the high-level API must reach the same answer
    //    via the happy path. We can tell happy-vs-catch apart by the
    //    presence of the `endpoint` key on the returned object --
    //    hub.ts's try-arm includes it (even when undefined), the
    //    catch-arm returns a bare { connected: false } with no
    //    endpoint key at all.
    const s = ship();
    const status = await s.hub.status();
    expect(status.connected).toBe(false);
    expect("endpoint" in status).toBe(true);
  });
});
