# Treeship graph proof invariants

Read this file on every `treeship-graph-loop` invocation.

## Product boundary

Treeship is the proof layer for graphs, not an orchestrator.

A graph database may be a disposable query index, never the authority. Signed artifacts, independently checkable receipts, verifier-selected trust roots, Merkle inclusion proofs, and consistency proofs remain authoritative.

## Graph model

Keep three graphs separate:

1. **Declared graph:** what a signed workflow authorizes.
2. **Observed graph:** attempts and transitions reconstructed from execution evidence.
3. **Evidence graph:** signed and captured artifacts supporting those observations.

Agent parentage remains hierarchical. Retries and loops create repeated `{node_id, attempt, iteration}` observations. They do not create cyclic parent relationships.

## Trust rules

- Prefer independently checkable evidence over self-reported `edge.taken` claims.
- Preserve provenance as `checked | captured | asserted`.
- Keep `deviation`, `gap`, authority outcomes, loop outcomes, and commitment outcomes separate.
- A content hash or signed timestamp does not prove pre-existence.
- Pre-existence requires trusted checkpoint inclusion, leaf ordering, consistency, and one log identity.
- V1 uses the checkpoint signing public key as log identity. Explicit key rotation requires a future continuity design.
- Run binding comes from the signed `session.start` action.
- Manifest and receipt workflow references are discovery copies. Compare them with the verified signed root before signing derived claims.
- Validate every workflow reference before writing active-session state.
- External workflow authorities require a dedicated trust-root kind. Do not reuse checkpoint, certificate, room-host, or ship trust.

## Loop rules

- `max_iterations` counts verified traversals of the declared back edge.
- `budget.max_actions` counts unique verified signed-action references attributed to retry attempts after the first back-edge traversal.
- Tool labels are authority observations, not action counts.
- Duplicate or unbound action references fail closed.

## Implementation order

Take the first unfinished slice unless the user names another focus:

1. Automatically publish and compose declaration and first-run checkpoints.
2. Compose declaration inclusion, first-run inclusion, consistency, signature, trust-root, log-identity, and run-binding checks into one fail-closed verifier path.
3. Add the CLI workflow conformance verifier.
4. Replace placeholder proof identifiers with end-to-end cryptographic fixtures where applicable.
5. Dogfood a Claude Code plus gstack QA repair loop.
6. Add external adapters only after the local proof chain is complete.

Defer graph databases, optimization, automatic graph rewriting, generalized effects, and orchestration.

## Current core surfaces

- Normative spec: `docs/specs/workflow-declarations.md`
- Reducer and proof helpers: `packages/core/src/verify/workflow_conformance.rs`
- Golden tests: `packages/core/tests/workflow_conformance_golden.rs`
- Golden fixtures: `packages/core/tests/fixtures/workflow-conformance/`
- CLI binding: `packages/cli/src/commands/session.rs`
- CLI workflow tests: `packages/cli/tests/workflow_cli.rs`
- Predicate schema: `packages/core/src/predicates/schemas/workflow.v1.json`
- Parent-cycle handling: `packages/core/src/session/graph.rs`

## Required proof chain

A complete checked result needs:

1. Workflow artifact included in a checkpoint tree of size `N`.
2. Signed first-run `session.start` binds the exact workflow artifact.
3. First-run artifact has zero-based leaf index `>= N`.
4. A valid consistency proof shows the later checkpoint extends the declaration checkpoint.
5. Both checkpoints belong to the same log identity and satisfy verifier-selected checkpoint trust.
6. The observed run is reconstructed from graded evidence and reduced deterministically against the declaration.
