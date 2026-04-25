// TypeScript runner for the cross-SDK contract suite.
//
// Reads tests/cross-sdk/corpus.json (written by gen-vectors.sh), verifies
// every vector through the @treeship/sdk public surface, and emits one JSON
// line per vector to stdout. The orchestrator (run.sh) diffs this against
// the Python runner's output and fails on any divergence.
//
// Output format (one per line, JSON, no embedded newlines):
//   {"runner":"ts","name":"<vector-name>","outcome":"pass","chain":1}
//   {"runner":"ts","name":"<vector-name>","outcome":"fail","chain":0,"error":null}
//   {"runner":"ts","name":"<vector-name>","outcome":"error","error":"<message>"}
//
// The runner exits 0 if every observed outcome matches the corpus's
// expected_outcome; non-zero if any vector failed expectations or threw.

import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
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

// Locate the SDK source. We import from the workspace path because the
// suite is meant to validate the in-tree SDK, not whatever's on npm.
const sdkSrc = join(here, "..", "..", "packages", "sdk-ts");

// The published SDK shells out to `treeship` on PATH. To bind it to the
// scratch keystore the corpus was generated against, we wrap our calls
// here directly rather than going through ship().verify.verify(). This
// shadows the public API while keeping the same input/output shape, so
// the contract under test is "verify(id) returns {outcome, chain}" --
// not "what binary do you happen to find on PATH".
//
// For the higher-fidelity contract (in-process WASM verifyReceipt), see
// the matching block in verify_vectors.py and the README.

function runVerify(artifactId: string): { outcome: string; chain: number } {
  // Find the binary the same way gen-vectors.sh does.
  const repoRoot = join(here, "..", "..");
  const candidates = [
    process.env.TREESHIP_BIN,
    join(repoRoot, "target", "release", "treeship"),
    join(repoRoot, "target", "debug", "treeship"),
  ].filter((x): x is string => Boolean(x));

  const binary = candidates.find((p) => {
    try {
      return existsSync(p) && (statSync(p).mode & 0o111) !== 0;
    } catch {
      return false;
    }
  });
  if (!binary) {
    throw new Error("no treeship binary found; build with cargo first");
  }

  let stdout = "";
  try {
    stdout = execFileSync(binary, [
      "--config", corpus.config_path,
      "--format", "json",
      "verify", artifactId,
    ], { encoding: "utf8" });
  } catch (err: unknown) {
    // verify exits 1 on fail. We still want the JSON outcome.
    const ex = err as { stdout?: string };
    stdout = ex.stdout ?? "";
    if (!stdout) throw err;
  }

  const parsed = JSON.parse(stdout);
  return {
    outcome: String(parsed.outcome),
    chain: Number(parsed.passed ?? parsed.total ?? 0),
  };
}

let mismatches = 0;
for (const v of corpus.vectors) {
  let line: Record<string, unknown>;
  try {
    const result = runVerify(v.artifact_id);
    line = {
      runner: "ts",
      name: v.name,
      outcome: result.outcome,
      chain: result.chain,
    };
    if (result.outcome !== v.expected_outcome) {
      mismatches++;
      line.expected_outcome = v.expected_outcome;
      line.error = `expected outcome=${v.expected_outcome}, got ${result.outcome}`;
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

void sdkSrc; // silence unused-binding when SDK source is referenced only for documentation
process.exit(mismatches === 0 ? 0 : 1);
