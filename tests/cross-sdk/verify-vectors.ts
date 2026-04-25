// TypeScript runner for the cross-SDK contract suite.
//
// Loads tests/cross-sdk/corpus.json (written by gen-vectors.sh), points
// the @treeship/sdk at the corpus's scratch keystore via TREESHIP_CONFIG,
// then verifies every vector through ship().verify.verify(id) -- the
// actual SDK public surface, NOT a private CLI bypass. Emits one JSON
// line per vector to stdout.
//
// Output format (one per line, JSON, no embedded newlines):
//   {"runner":"ts","name":"<vector-name>","outcome":"pass","chain":1}
//   {"runner":"ts","name":"<vector-name>","outcome":"fail","chain":0}
//   {"runner":"ts","name":"<vector-name>","outcome":"error","error":"<message>"}
//
// Exits 0 if every observed outcome matches the corpus's expected_outcome;
// non-zero if any vector failed expectations or threw.

import { readFileSync, existsSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const corpusPath = join(here, "corpus.json");

type Vector = {
  name: string;
  artifact_id: string;
  category: "valid" | "broken-chain" | "revoked";
  expected_outcome: "pass" | "fail";
  expected_chain?: number;
};

type Corpus = {
  config_path: string;
  vectors: Vector[];
};

const corpus: Corpus = JSON.parse(readFileSync(corpusPath, "utf8"));

// Locate the treeship binary the same way gen-vectors.sh does and put its
// directory on PATH so the SDK finds it when it spawns `treeship`.
function findBinaryDir(): string {
  // Prefer debug over release: the orchestrator rebuilds debug each run,
  // so a stale release binary from a prior `cargo build --release` won't
  // silently shadow it. TREESHIP_BIN still wins for explicit callers.
  const candidates = [
    process.env.TREESHIP_BIN,
    join(repoRoot, "target", "debug", "treeship"),
    join(repoRoot, "target", "release", "treeship"),
  ].filter((x): x is string => Boolean(x));
  const binary = candidates.find((p) => {
    try {
      return existsSync(p) && (statSync(p).mode & 0o111) !== 0;
    } catch {
      return false;
    }
  });
  if (!binary) throw new Error("no treeship binary found; build with cargo first");
  return dirname(binary);
}

const binaryDir = findBinaryDir();
process.env.PATH = `${binaryDir}:${process.env.PATH ?? ""}`;
process.env.TREESHIP_CONFIG = corpus.config_path;

// Import the SDK from its built output. The source uses .js suffixes in
// its imports (TS module resolution hint), which Node's strip-types
// loader doesn't resolve back to .ts -- so we point at packages/sdk-ts/dist,
// which is real .js. The orchestrator (run.sh) is responsible for ensuring
// the build is fresh before invoking this runner.
const sdkIndex = join(repoRoot, "packages", "sdk-ts", "dist", "index.js");
if (!existsSync(sdkIndex)) {
  throw new Error(
    `SDK build not found at ${sdkIndex} -- run 'npm run build' in packages/sdk-ts first`,
  );
}
const { ship } = (await import(sdkIndex)) as {
  ship: () => { verify: { verify: (id: string) => Promise<{ outcome: string; chain: number; target: string }> } };
};

let mismatches = 0;
const s = ship();
for (const v of corpus.vectors) {
  let line: Record<string, unknown>;
  try {
    const result = await s.verify.verify(v.artifact_id);
    line = {
      runner: "ts",
      name: v.name,
      outcome: result.outcome,
      chain: result.chain,
    };
    const errors: string[] = [];
    if (result.outcome !== v.expected_outcome) {
      errors.push(`expected outcome=${v.expected_outcome}, got ${result.outcome}`);
    }
    // expected_chain is optional in the corpus -- if it's set, both SDKs
    // must agree on it too. Without this assertion both SDKs could
    // silently regress to the same wrong chain count and the suite
    // would still exit 0 (Codex finding #4 in the v0.9.5 review).
    if (v.expected_chain !== undefined && result.chain !== v.expected_chain) {
      errors.push(`expected chain=${v.expected_chain}, got ${result.chain}`);
    }
    if (errors.length > 0) {
      mismatches++;
      line.expected_outcome = v.expected_outcome;
      if (v.expected_chain !== undefined) line.expected_chain = v.expected_chain;
      line.error = errors.join("; ");
    }
  } catch (err) {
    mismatches++;
    line = {
      runner: "ts",
      name: v.name,
      outcome: "error",
      error: err instanceof Error ? err.message : String(err),
    };
  }
  process.stdout.write(JSON.stringify(line) + "\n");
}

process.exit(mismatches === 0 ? 0 : 1);
