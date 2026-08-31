---
name: treeship-graph-loop
description: Run bounded, spec-first implementation cycles for Treeship's workflow and graph proof layer. Use when continuing workflow declarations, checkpoint composition, run binding, evidence-derived paths, bounded loops, or conformance verification.
compatibility: Requires the Treeship Rust workspace and the global gstack install.
---

# Treeship Graph Engineering Loop

Run a bounded engineering loop for Treeship's graph proof layer. This is not an orchestrator and must not turn Treeship into one.

## Invocation inputs

Accept these inputs from the user or calling prompt:

- **Cycle budget:** default `1`, hard maximum `3` per invocation.
- **Focus:** default to the first unfinished item in the implementation order in `references/invariants.md`.

A cycle is one reviewable protocol slice, not one file or one tool call.

## Start gate

Before every invocation:

1. Locate the Treeship repository. Use the current git root when it contains `packages/core`; otherwise use `./treeship` when that directory is a git repository. Treat the resulting path as `REPO_ROOT`, run shell commands from it, and resolve all project paths below against it. Stop if neither location is valid.
2. Verify gstack exists:
   ```bash
   test -d ~/.claude/skills/gstack/bin && echo GSTACK_OK || echo GSTACK_MISSING
   ```
   Stop on `GSTACK_MISSING` and print the repository-required installation instructions.
3. Read, in order:
   - `AGENTS.md`
   - `docs/quality/ai-assisted-development.md`
   - `docs/specs/workflow-declarations.md`
   - `references/invariants.md` relative to this skill
4. Inspect `git status --short`, the current branch, and the diff against `origin/main`.
5. Preserve unrelated work. Never reset, restore, stash, stage, commit, or rewrite files outside the selected slice unless the user explicitly asks.
6. Confirm there is a concrete objective and a falsifiable acceptance test. Stop and ask when the next step requires a new trust power, wire-format decision, or compatibility decision not settled by the spec.

## Cycle

For each permitted cycle, perform every phase below.

### 1. Select one slice

Choose the smallest end-to-end slice that advances the declared focus. State:

- protocol claim being added or changed,
- authoritative signed or cryptographic evidence,
- attacker-controlled inputs,
- expected machine-verifiable outcome,
- explicit non-goals.

Do not select optimization, graph databases, automatic graph rewriting, or orchestration behavior.

### 2. Spec before code

Update the normative spec before implementation when semantics change. Keep the declared graph, observed graph, and evidence graph distinct.

Refuse a design that can pass because of:

- empty evidence,
- self-reported edge selection,
- an unsigned mutable mirror,
- a signed timestamp without trusted ordering,
- trust-root reuse across different powers,
- a database lookup treated as authority.

### 3. Write the adversarial test first

Add the smallest regression test or golden fixture that fails before the implementation. Include at least one mutation or substitution case.

A useful test must prove a named invariant. `is_ok()` alone is not an assertion of trust correctness.

When a bug or surprising failure is found, convert it into a permanent regression test before continuing. This growing counterexample corpus is the loop's durable improvement mechanism. Do not call model-generated notes authoritative.

### 4. Implement the minimum complete proof path

Implement only what the new test and spec require. Fail closed before writing state or signing derived claims.

Keep cryptographic authority in signed artifacts, Merkle proofs, consistency proofs, and verifier-selected trust. A graph database may only be a disposable query index.

### 5. Verify in layers

Run targeted tests first, then the relevant gates:

```bash
cargo fmt --all -- --check
cargo test -p treeship-core --lib
cargo test -p treeship-core --test workflow_conformance_golden
cargo test -p treeship-cli --test workflow_cli
cargo clippy -p treeship-core -p treeship-cli --all-targets -- -D warnings
git diff --check
```

Also run when applicable:

- `cargo test -p treeship-cli --test session_cli` for session close or binding changes.
- `cargo test -p treeship-cli --test room_cli` for room changes.
- `./tests/cross-sdk/run.sh` for wire-format or cross-language changes.
- `cd docs && npm run build` plus repository documentation checks for public behavior changes.
- `cargo package -p treeship-core --allow-dirty --no-verify` for new core files or schemas.

Do not work around the known unpublished `treeship-zk-circom` CLI packaging blocker. Report its exact error if that preflight is attempted.

### 6. Adversarial review

Before calling the cycle complete, try to break the new claim with:

- artifact substitution,
- signer substitution,
- payload mutation,
- missing or duplicated evidence,
- empty observation sets,
- out-of-order or cross-log checkpoints,
- mutable manifest changes,
- unknown fields and omitted required fields,
- cycle, deep-chain, and budget boundary cases.

Check that provenance remains `checked | captured | asserted` and that path deviations, gaps, authority deviations, commitment outcomes, and loop limits remain separate axes.

### 7. Close the cycle

Update documentation, changelog, inventory, generated matrices, and capability maps only when the public contract changed.

Report:

- files changed,
- invariant now enforced,
- tests and gates run,
- remaining risks,
- exact next slice.

Do not commit or push unless the user explicitly asks.

If a non-obvious project lesson would save future work, record it with gstack learnings. Never store secrets, mutable verdicts, or unverified claims as learning entries.

## Continue or stop

Continue to another cycle only when all are true:

- the previous cycle is fully green,
- the next slice is already specified,
- no user decision is required,
- the invocation's cycle budget remains.

Stop immediately when:

- a security-sensitive choice is ambiguous,
- the diff contains unexplained unrelated changes,
- a verifier can pass vacuously,
- a required trust root or evidence artifact does not exist,
- the same failure survives three attempts,
- the cycle budget is exhausted.

There is no background execution. A new user message or `/graph-loop` invocation is required after the active invocation ends.
