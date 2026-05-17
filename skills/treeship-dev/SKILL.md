---
name: treeship-dev
description: Work on the Treeship source repository safely. Use when Codex or another coding agent is asked to modify, review, document, or test the zerkerlabs/treeship repo, especially packages/core, packages/cli, packages/hub, docs, SDKs, MCP bridge, DSSE artifacts, approvals, handoffs, Hub/Dock/DPoP, or cryptographic verification behavior. This skill provides repo scope, required read order, crypto invariants, CLI UX rules, and validation commands for contributors.
---

# Treeship Dev

## Start Here

Use the local `zerkerlabs/treeship` checkout as the workspace root. Stay scoped to that repo unless the user explicitly asks to inspect sibling repos.

Read these files before code changes:

1. `AGENTS.md`
2. `ONBOARDING.md`

Treat `AGENTS.md` as the source of truth. If these skill instructions conflict with `AGENTS.md`, follow `AGENTS.md`.

## What Treeship Is

Treeship is a portable trust layer for AI agent workflows. Actions, approvals, handoffs, receipts, bundles, and related records are signed artifacts that must verify without trusting hosted infrastructure.

The core loop is:

```bash
treeship wrap -- your-command
treeship hub push <artifact-id>
```

## Non-Negotiable Invariants

Preserve these exactly:

- DSSE PAE format: `"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload`
- Artifact ID derivation: `artifact_id = "art_" + hex(sha256(PAE_bytes)[..16])`
- Statement structs do not contain an `id` field. IDs live on records/sign results.
- Envelope JSON uses DSSE camelCase: `payload`, `payloadType`, `signatures`.
- Approval nonce binding is enforced: `action.approvalNonce == approval.nonce`.
- Hub/Dock auth uses DPoP with a separate dock keypair. Do not add session tokens.
- Rekor anchoring is best-effort and must not make artifact push fail when Rekor is down.
- TypeScript SDK verification must use the WASM verifier path, not a `treeship` subprocess.

## Repo Map

- `packages/core`: Rust core library, attestation, statements, keys, storage, verifier, Merkle.
- `packages/cli`: Rust CLI, command tree, wrap/status/verify/hub/ui/otel commands.
- `packages/hub`: Go Hub server and SQLite-backed API.
- `packages/core-wasm`: Browser verifier.
- `packages/sdk-ts`: TypeScript SDK.
- `packages/sdk-python`: Python SDK.
- `bridges/mcp`: MCP bridge.
- `docs`: Fumadocs documentation.
- `skills`: portable agent skills.
- `plugins`: Codex plugin candidates.

## Preferred Read Order

For core protocol or CLI work, read:

1. `packages/core/src/attestation/pae.rs`
2. `packages/core/src/attestation/sign.rs`
3. `packages/core/src/attestation/verify.rs`
4. `packages/core/src/statements/mod.rs`
5. `packages/cli/src/main.rs`
6. `packages/cli/src/commands/wrap.rs`

For Hub work, read `packages/hub/main.go` and the relevant package under `packages/hub/internal`.

For docs-only work, still read `AGENTS.md`, then edit only the relevant pages under `docs`.

## CLI UX Rules

When changing CLI behavior:

- Keep commands noninteractive.
- Provide `--format json` where command output needs stable machine-readable output.
- Return useful exit codes: `0` ok, `1` error, `3` not initialized, `4` usage.
- Include a concrete fix in errors.
- Print a dim next-step hint on success.
- Respect `NO_COLOR` and `--no-color`.
- `treeship wrap` must propagate the subprocess exit code.

## Validation

Choose focused checks for the files changed:

```bash
cargo test -p treeship-core
cargo test -p treeship-cli
cargo test
```

For Hub:

```bash
cd packages/hub
go test ./...
go build ./...
```

For TypeScript or MCP packages, inspect package scripts first, then run the relevant npm test/build command from that package directory.

## Working Style

Keep edits narrow. Do not refactor unrelated crypto, storage, or schema code while solving a task. Avoid changing generated IDs, signed payload shape, schema field casing, or verification semantics unless the user explicitly asks and the change is reconciled with `AGENTS.md`.

Use direct, concise writing. Avoid corporate phrasing.
