// Runs the shared redaction vectors against the plugin's TypeScript redactor.
//
// The Rust CLI runs the same file (packages/cli/tests/redaction_vectors.rs).
// Two implementations of a security control drift, and drift here is silent:
// the plugin keeps producing receipts, they just stop being safe. A shared
// vector file makes the divergence a test failure instead of an incident.
//
//   node --test test/redaction.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(here, "..", "..", "..", "tests", "vectors", "redaction.json");

const { redactCommand } = await import("../dist/index.js");
const vectors = JSON.parse(readFileSync(VECTORS, "utf8"));

test("every audit-known leak is redacted", async (t) => {
  for (const v of vectors.leaks) {
    await t.test(v.name, () => {
      const got = redactCommand(v.input);
      for (const secret of v.must_not_contain) {
        assert.ok(
          !got.includes(secret),
          `secret survived redaction\n  input:  ${v.input}\n  output: ${got}\n  leaked: ${secret}`,
        );
      }
      // Redacting the entire line would satisfy the assertion above while
      // destroying the receipt's evidence value. Check what must survive.
      for (const keep of v.preserved ?? []) {
        assert.ok(
          got.includes(keep),
          `over-redacted, lost context\n  input:  ${v.input}\n  output: ${got}\n  missing: ${keep}`,
        );
      }
    });
  }
});

test("benign commands are returned unchanged", async (t) => {
  for (const v of vectors.benign) {
    await t.test(v.name, () => {
      assert.equal(
        redactCommand(v.input),
        v.input,
        `over-redacted a command with nothing sensitive in it`,
      );
    });
  }
});
