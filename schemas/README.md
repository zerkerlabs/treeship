# Treeship schemas

Machine-readable JSON Schemas for Treeship payload profiles, with a fixture validator.

## `treeship.boundary.v1.json`

The boundary-proof payload: a provider-neutral record of an actor-checker evaluation boundary (what a checker was allowed to see, what policy denied, and the decision it reached). It is carried as the `payload` of a Treeship receipt artifact.

The concept and the proven/asserted discipline are documented at
[`docs/content/docs/concepts/actor-checker-boundaries.mdx`](../docs/content/docs/concepts/actor-checker-boundaries.mdx).

The schema mechanically enforces parts of that discipline:

- `additionalProperties: false` at the top level rejects smuggled self-reports such as `verifier_excluded_inputs`. Exclusion is derived from the signed `policy` plus the committed `diet`, never claimed directly. Any human-readable echo belongs inside `asserted`.
- `committed_at` is required, so a payload cannot omit the proof that the diet was frozen before the decision.
- `decision` is constrained to `allow | deny | partial | abstain`.
- digests must be `sha256:<64 hex>`.

## Fixtures

Under `examples/`:

- `*.valid.json` must validate against the schema.
- `*.invalid.*.json` must fail. These encode the discipline; for example, `boundary.v1.invalid.self-report.json` smuggles a top-level `verifier_excluded_inputs` field and is rejected.

## Run the validator

```bash
cd schemas
npm install
npm test
```
