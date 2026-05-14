import { describe, it, expect, beforeAll } from "vitest";
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
//   2. If the binary is missing, build it once with `cargo build --release -p
//      treeship-cli`. If `cargo` itself is unavailable, skip the suite.
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

function ensureBinary(workspaceRoot: string, binaryPath: string): void {
  if (existsSync(binaryPath)) return;
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

  beforeAll(() => {
    ensureBinary(WORKSPACE_ROOT, BINARY_PATH);

    // Per-suite scratch dir: holds both the PATH shim and the .treeship/
    // config + keystore.
    sessionDir = mkdtempSync(join(tmpdir(), "treeship-sdk-roundtrip-"));
    shimDir    = join(sessionDir, "bin");
    mkdirSync(shimDir, { recursive: true });
    symlinkSync(BINARY_PATH, join(shimDir, "treeship"));

    configPath = join(sessionDir, ".treeship", "config.json");
    storageDir = join(sessionDir, ".treeship", "artifacts");

    originalPath = process.env.PATH;
    process.env.PATH         = `${shimDir}:${process.env.PATH ?? ""}`;
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
  }, 300_000);  // 5 min: cold cargo build dominates on first run

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
    // flip the high bit of byte 0, re-encode. A single-bit flip in an
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
    const after = await s.verify.verify(artifactId);
    expect(after.outcome).toBe("fail");
  });

  it("hub.status reports disconnected when no hub is configured", async () => {
    // A fresh init has no hub_connections + no active_hub. The SDK's
    // status() catches the CLI's error path and reports { connected: false }
    // rather than throwing -- giving callers a polled-status idiom that
    // works whether or not a hub is reachable.
    const s = ship();
    const status = await s.hub.status();
    expect(status.connected).toBe(false);
  });

  // Cleanup: restore PATH and remove the tempdir. We do this in an
  // afterAll-equivalent inline rather than registering an afterAll hook,
  // to keep the suite a single straight read. Vitest doesn't strictly
  // need it (tempdir + reverted PATH don't leak between processes) but
  // it's polite for repeated `vitest --watch` runs.
  it("cleans up the per-suite scratch dir and PATH override", () => {
    process.env.PATH = originalPath ?? "";
    delete process.env.TREESHIP_CONFIG;
    rmSync(sessionDir, { recursive: true, force: true });
    expect(existsSync(sessionDir)).toBe(false);
  });
});
