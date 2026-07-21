// Validates the example fixtures against their schema.
//
// Convention: under examples/, a file named "*.valid.json" must validate
// against the matching schema, and a file named "*.invalid.*.json" must fail.
// The invalid fixtures encode the boundary format's discipline (for example,
// a smuggled top-level self-report field is rejected by additionalProperties).
//
// Run: cd schemas && npm install && npm test

import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const here = dirname(fileURLToPath(import.meta.url));
const schemaPath = join(here, "treeship.boundary.v1.json");
const examplesDir = join(here, "examples");

const ajv = new Ajv({ allErrors: true, strict: true });
addFormats(ajv);

const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
const validate = ajv.compile(schema);

let failures = 0;

for (const file of readdirSync(examplesDir).sort()) {
  if (!file.endsWith(".json")) continue;
  const expectValid = file.endsWith(".valid.json");
  const expectInvalid = file.includes(".invalid.");
  if (!expectValid && !expectInvalid) {
    console.error(`SKIP  ${file} (name must end .valid.json or contain .invalid.)`);
    failures++;
    continue;
  }

  const data = JSON.parse(readFileSync(join(examplesDir, file), "utf8"));
  const ok = validate(data);

  if (expectValid && ok) {
    console.log(`PASS  ${file} (valid as expected)`);
  } else if (expectInvalid && !ok) {
    const why = (validate.errors || []).map((e) => `${e.instancePath || "/"} ${e.message}`).join("; ");
    console.log(`PASS  ${file} (rejected as expected: ${why})`);
  } else if (expectValid && !ok) {
    console.error(`FAIL  ${file} (expected valid, got errors)`);
    console.error("        " + JSON.stringify(validate.errors, null, 2).replaceAll("\n", "\n        "));
    failures++;
  } else {
    console.error(`FAIL  ${file} (expected invalid, but it validated)`);
    failures++;
  }
}

console.log(`\nResult: ${failures === 0 ? "all fixtures behaved as expected" : failures + " failed"}`);
process.exit(failures === 0 ? 0 : 1);
