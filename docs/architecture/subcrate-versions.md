# Subcrate version policy

> Authoritative, in-repo description of which packages in this monorepo
> ride the main Treeship release train and which ones run on their own
> cadence. Written as a v0.10.4 follow-up to a v0.10.3 audit P2 that
> flagged version skew between `packages/core` (0.10.3) and several
> sibling packages.

---

## TL;DR

Most packages under `packages/` are pinned to a single monorepo version
that ticks each release. Three are deliberately not:

| Package | Current | Tracks monorepo? | Reason |
|---|---|---|---|
| `packages/vi` (`treeship-vi`) | 0.6.0 | No | Sibling experiment, independent cadence, `publish = false` |
| `packages/zk-circom` (`treeship-zk-circom`) | 0.5.0 | No | Early-stage proof prototype, `publish = false` |
| `packages/zk-risc0` (`treeship-zk-risc0`) | 0.5.0 | No | Early-stage proof prototype, `publish = false` |
| `packages/zk-circom/package.json` (npm side) | 1.0.0 | No | Scaffolding-default from `npm init`, never published, never consumed |

The version-consistency preflight
(`scripts/check-release-versions.py`) **intentionally does not walk
any of these.** Adding them today would either force the main release
to wait on prototype work that isn't ready to ship, or force the
prototypes to bump on every monorepo release for no semantic reason.
Both are bad outcomes; the preflight is correct to skip them.

---

## What rides the main release train

Every package in this table moves together. When `scripts/release.sh
prepare <version>` runs, every site in this list bumps in lock-step,
and `scripts/check-release-versions.py <version>` verifies it.

| Package | Manifest | Site label in preflight |
|---|---|---|
| `treeship-core` | `packages/core/Cargo.toml` | `rust crate treeship-core` |
| `treeship-cli` | `packages/cli/Cargo.toml` | `rust crate treeship-cli` |
| `treeship-core-wasm` | `packages/core-wasm/Cargo.toml` | `rust crate treeship-core-wasm` |
| `@treeship/sdk` | `packages/sdk-ts/package.json` | `npm @treeship/sdk` |
| `@treeship/verify` | `packages/verify-js/package.json` | `npm @treeship/verify` |
| `@treeship/mcp` | `bridges/mcp/package.json` | `npm @treeship/mcp` |
| `@treeship/a2a` | `bridges/a2a/package.json` | `npm @treeship/a2a` |
| `treeship` (npm wrapper) | `npm/treeship/package.json` | `npm treeship (wrapper)` |
| `@treeship/cli-linux-x64` | `npm/@treeship/cli-linux-x64/package.json` | platform CLI binary |
| `@treeship/cli-darwin-arm64` | `npm/@treeship/cli-darwin-arm64/package.json` | platform CLI binary |
| `@treeship/cli-darwin-x64` | `npm/@treeship/cli-darwin-x64/package.json` | platform CLI binary |
| `treeship-sdk` (PyPI) | `packages/sdk-python/pyproject.toml` | `pypi treeship-sdk (pyproject)` |
| `treeship` Claude Code plugin | `.claude-plugin/marketplace.json` | metadata.version + plugins[treeship].version |

Plus three internal-pin cross-checks the preflight enforces:

- `packages/cli/Cargo.toml` → `treeship-core` (must match `[package].version`)
- Every npm package above → `@treeship/core-wasm` (must match core-wasm `[package].version`)
- `npm/treeship/package.json` `optionalDependencies` → each platform CLI package (must match)

Drift in any of these blocks the release in CI before tag or publish.

---

## What runs on its own cadence

### `packages/vi` — Verifiable Intent (`treeship-vi`)

Current version: **0.6.0**. Latest workspace commits show the v0.6.x
line is its own track that grew out of the "Verifiable Intent
foundation" sprint (commits `e408df8`, `f9e229e`, `c304720`,
`16c6878`). It implements the L1 → L2 → L3 credential chain (issuer
bank credentials, user mandates, agent credentials) used for binding
agent actions to off-chain authorizations such as payment intents.

- **`publish = false`** in `Cargo.toml` — it does not go to crates.io.
- **Not a dependency of the CLI release path** — `treeship-cli` does
  not link `treeship-vi`. The keystore in `treeship-core` exposes
  legacy public symbols (`aes_gcm_encrypt` / `aes_gcm_decrypt`) so
  the `treeship-vi` keystore can stay byte-stable on its own
  cadence; see the v0.10.3 CHANGELOG entry under
  TS-2026-001 and `packages/core/src/keys/mod.rs:978`.
- **Why the version is decoupled:** the VI work is a separable
  product with its own design churn. Forcing it to step from
  0.6.0 → 0.10.4 today would lie about its maturity. Its semver
  resets when the VI surface stabilizes and we decide whether to
  publish it as a sibling crate or merge it into `treeship-core`.

### `packages/zk-circom` — Circom circuits (`treeship-zk-circom`)

Current version: **0.5.0**. Implements three Groth16 circuits
(`policy-checker`, `input-output-binding`, `prompt-template`) plus
trusted-setup artifacts in `zkeys/`.

- **`publish = false`** in `Cargo.toml` (and the comment in the
  manifest says so explicitly: `# Not published to crates.io yet`).
- **Behind a `--features zk` feature gate.** Not built by default.
- **Why the version is decoupled:** the proving surface still has
  open architectural questions — see the commented-out
  `ark-circom`/`ark-bn254` dependencies in `packages/zk-circom/Cargo.toml`
  with the `TODO: Enable once ark version alignment is resolved`
  marker. Bumping it on every Treeship release would imply API
  stability the crate does not yet have.
- **The npm-side `packages/zk-circom/package.json` at version 1.0.0**
  is `npm init` boilerplate. It carries one runtime dep (`circomlib`)
  used by the Circom toolchain locally. The package is never
  published and nothing in the monorepo imports it via npm. The
  `1.0.0` is the default scaffolding string — it has no semantic
  meaning. Renaming or deleting this file is tracked as cleanup, not
  as a version-skew bug.

### `packages/zk-risc0` — RISC Zero guest (`treeship-zk-risc0`)

Current version: **0.5.0**. RISC Zero zkVM guest program for
chain-level proofs of attestation chains; sibling to `zk-circom`.

- **`publish = false`** in `Cargo.toml`.
- **Requires the `rzup` toolchain and Rust nightly** (see
  `packages/zk-risc0/README.md`) — not a build the average
  contributor runs.
- **Why the version is decoupled:** same reasoning as `zk-circom`.
  The guest program's interface to `treeship-cli` (`treeship prove
  --engine risc0 --chain ./chain.json`) is exploratory, and its
  proof format is not yet promoted to a verifier-stable shape.
  Its semver tracks the proving surface, not the receipt surface.

---

## Release cadence policy

### Main release train

- **Trigger:** any change to receipt composition, approval
  semantics, replay/journal behavior, package verification, hub
  checkpoint verification, MCP/A2A bridges, tool authorization,
  agent identity, harness coverage, public sharing, or
  installer/bootstrap security. Also: bump-only and CHANGELOG
  releases.
- **Who bumps:** `scripts/release.sh prepare <version>` rewrites
  every site listed under "What rides the main release train"
  above. `check-release-versions.py <version>` is the preflight
  assertion.
- **Tagging cadence:** roughly weekly during active development.

### Sibling subcrates (`vi`, `zk-circom`, `zk-risc0`)

- **Trigger:** semantic change inside the subcrate itself —
  new credential type for `vi`, new circuit or proving backend
  for `zk-circom`/`zk-risc0`, breaking change to the subcrate's
  own public API.
- **Who bumps:** the contributor making the change, by hand,
  in the subcrate's own `Cargo.toml`. Not touched by
  `scripts/release.sh`.
- **Does not block the main release.** Subcrate versions are
  invisible to crates.io and to consumers; they're internal
  semver markers for the contributors working on those crates.

### Promotion criteria

A sibling subcrate joins the main release train when:

1. It is ready to publish (`publish = false` is removed).
2. Its public API is stable enough that a monorepo bump on every
   release is a true claim, not a lie.
3. A consumer in the main release train (`treeship-cli`, an SDK,
   or a bridge) takes a hard dependency on it.

When that happens, add it to `collect_sites()` in
`scripts/check-release-versions.py` and to the "main release
train" table above in the same PR.

---

## Confirming the preflight is correct, not buggy

The v0.10.3 audit raised version skew between `packages/core`
(0.10.3) and the three subcrates above as a P2: "Document the
intentional decoupling, or align." This document is the
documentation half of that choice. The alignment half is
deliberately not done — the skew is intentional and the
preflight's silence on these crates is correct, for the reasons
in the per-package sections above.

If a future audit re-flags this skew, the response is to update
this doc rather than to expand the preflight or bump the
subcrates without semantic cause.

---

## Genuine drift found during this audit

None. Every skew is intentional. The npm-side `packages/zk-circom/package.json`
at 1.0.0 is the only ambiguous case, and it is `npm init` scaffolding
rather than drift — a stale default that has no semantic meaning and
is never published or consumed. It can be cleaned up (renamed, deleted,
or pinned at `0.0.0-private`) in a separate trivial PR; it is not
worth blocking this audit close on.
