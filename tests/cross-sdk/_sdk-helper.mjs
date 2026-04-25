// Tiny dispatcher used by the cross-SDK roundtrip script (run from
// tests/cross-sdk/roundtrip.sh). Imports the in-tree TypeScript SDK
// from its built dist/ and exposes two operations on stdin/stdout:
//
//   node _sdk-helper.mjs attest-action <actor> <action>
//     -> stdout: artifact id (no newline, no JSON)
//
//   node _sdk-helper.mjs verify <artifact_id>
//     -> stdout: outcome string ("pass" | "fail" | "error")
//
// Exits non-zero on any unexpected error.

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const { ship } = await import(join(repoRoot, "packages", "sdk-ts", "dist", "index.js"));

const [, , op, ...args] = process.argv;
const s = ship();

if (op === "attest-action") {
  const [actor, action] = args;
  if (!actor || !action) {
    console.error("usage: _sdk-helper.mjs attest-action <actor> <action>");
    process.exit(2);
  }
  const r = await s.attest.action({ actor, action });
  process.stdout.write(r.artifactId);
} else if (op === "verify") {
  const [id] = args;
  if (!id) {
    console.error("usage: _sdk-helper.mjs verify <artifact_id>");
    process.exit(2);
  }
  const r = await s.verify.verify(id);
  process.stdout.write(r.outcome);
} else {
  console.error(`unknown op: ${op}`);
  process.exit(2);
}
