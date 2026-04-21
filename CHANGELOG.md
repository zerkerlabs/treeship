# Changelog

## 0.9.3 (2026-04-20)

Trust onboarding for AI agents. The motivating problem: developers attempting to install Treeship would land on `treeship.dev/setup` (404, missing rewrite) and, even after installing, Claude Code would refuse to attach the MCP server because it had no in-context explanation of what `@treeship/mcp` captures or where data goes. v0.9.3 fixes both halves.

### Added

- `treeship add` (any framework) now drops a single `./TREESHIP.md` into the project root if one isn't already there. The file is framework-agnostic and answers the trust question for Claude Code, Cursor, Cline, Hermes, OpenClaw, and any future MCP-aware agent in one place: what gets captured (tool name, arguments, exit code, duration), what does NOT get captured (file contents, env values, secrets), when data leaves the machine (only on explicit `treeship session report` / `hub push` / `auto_push: true`), and how to use the wrap/session lifecycle.
- The TREESHIP.md template ships embedded in the CLI binary via `include_str!` so the drop works offline and never fetches over the network.

### Changed

- `treeship add` no longer touches framework-specific files (CLAUDE.md, .cursorrules, skill files) for trust purposes. Those stay focused on framework-specific instructions; the trust block lives in TREESHIP.md instead. One file, one source of truth, any agent.
- `integrations/claude-code/CLAUDE.md` template gains the trust block (what's captured, what isn't, when data leaves) above the existing wrapping rules — so users who copy the template manually also get the trust context, not only those who go through `treeship add`.
- `bridges/mcp/README.md` reframed: the inspect-before-trust path now leads with `treeship package verify` (offline, WASM, no hub required), with a clear pointer to the bridge source. Removed the previous "Verify our own development" section pending the flagship release receipt.

### Notes

- Same safety guards as the rest of `treeship add`: refuses to write outside a `.treeship/`-initialized project, refuses through symlinks, never overwrites an existing `./TREESHIP.md`.
- The website's `setup.sh` one-liner is unchanged in behavior — `treeship add --all` (which it already calls) now drops TREESHIP.md automatically once v0.9.3 is published.
- Website-side fix for the original `treeship.dev/setup` 404 is in the `treeship-website` repo (added a Next.js rewrite for `/setup` → `/setup.sh` mirroring the existing `/install` rewrite). Independent of this CLI release; deploys with the website.

## 0.9.2 (2026-04-20)

All packages realigned at 0.9.2 after a partial v0.9.1 npm publish. v0.9.1 landed successfully on crates.io, PyPI, and for the `treeship` wrapper + platform binaries on npm, but the new `@treeship/core-wasm` and `@treeship/verify` packages failed to bootstrap (scope permissions for new package names), which cascaded failure to `@treeship/sdk`, `@treeship/mcp`, and `@treeship/a2a`. The release workflow has been hardened to fail loud on publish failures, pre-flight every expected package on the `@treeship` scope, and verify each package post-publish.

**v0.9.2 is the first version where every package lands cleanly on every registry together. Install v0.9.2 everywhere; do not mix with 0.9.1.**

### Release workflow hardening

- Every `npm publish` / `cargo publish` / `twine upload` step has `continue-on-error` removed. A failure in any one now fails the workflow — no more silent partial releases.
- New pre-flight step on the `publish-npm` job enumerates every expected package on the `@treeship` scope and fails fast if any is missing. New scoped packages must be bootstrapped once with a web-auth `npm publish` from an account that owns the scope; thereafter the workflow's OIDC trusted publisher handles all future versions.
- New `.github/scripts/wait-for-{npm,crates,pypi}-version.sh` helpers poll each registry after publish and fail the workflow if the expected version does not appear within 30 seconds. Catches partial propagation, transient registry errors, and accidentally-skipped publish steps.

### Contents of this release

All v0.9.1 work below. Semantically identical; the only difference is the version string and that every package actually lands on its registry this time.

#### Added

- `@treeship/core-wasm` npm package. The Rust core compiled to WebAssembly with 10 exported functions (`verify_envelope`, `artifact_id`, `digest`, `decode_payload`, `verify_merkle_proof`, `verify_zk_proof`, `version`, plus the three new high-level ones below). Bundle size: **167 KB gzipped** (target was under 250 KB). First-class published npm package; pinned to exact versions across all dependents to prevent silent drift.
- `@treeship/verify` zero-dependency verification package at `packages/verify-js/`. Install alone, verify receipts and certificates in any runtime with WebAssembly + `fetch`. Only dependency is `@treeship/core-wasm`. This is what Witness, dashboards, and third-party consumers install.
- High-level WASM exports: `verify_receipt`, `verify_certificate`, `cross_verify`. Previously only low-level envelope and Merkle primitives were exposed. Each returns JSON in / JSON out with an error shape on malformed input rather than panicking.
- Reusable library primitive `treeship_core::verify::verify_receipt_json_checks` — lifted from the CLI's URL-fetch path so CLI and WASM share one implementation. Same checks (Merkle root recomputation, inclusion proofs, leaf count, timeline ordering, chain linkage) produce the same result across every runtime.
- `treeship_core::agent::verify_certificate` — Ed25519 signature check against the certificate's embedded public key. Exposed so the CLI, `@treeship/verify`, and future WASM consumers share one implementation.
- Runtime compatibility: **Node.js 18+, Deno, browser (bundler), Vercel Edge, Cloudflare Workers, AWS Lambda**. Edge runtime deploy harnesses at `tests/runtime-acceptance/{vercel-edge,cloudflare-worker,aws-lambda}/` — runnable projects with per-runtime READMEs.
- New docs: `sdk/verify.mdx`, `guides/edge-runtime.mdx`. Runtime compatibility matrices added to `@treeship/sdk`, `@treeship/a2a`, and `@treeship/mcp` READMEs. `reference/schema.mdx` gains a "Parity between CLI and WASM" section.
- Command-line build pipeline: `packages/core-wasm/build-npm.sh <version>` runs `wasm-pack build --target bundler`, optionally `wasm-opt -Oz`, then rewrites `pkg/package.json` with scoped name + license + repo + keywords. Release workflow installs wasm-pack + binaryen and runs this before the other npm publish steps so dependents resolve against the fresh core-wasm.

#### Changed

- `@treeship/sdk` verification path migrated from CLI subprocess to direct WASM calls. `ship.verify.verify(id)` (legacy artifact-ID form) still subprocesses; new `verifyReceipt` / `verifyCertificate` / `crossVerify` methods run in-process via WASM. Stateful operations (attest, session, dock, agent register) still use subprocess.
- `@treeship/a2a` `verifyReceipt` now performs real cryptographic verification (was previously network-only structural summary). `VerifiedReceipt.cryptographicallyVerified` surfaces the WASM result; `verifyChecks` carries the per-step breakdown. Graceful fallback: if `@treeship/core-wasm` can't load in the runtime, returns the pre-v0.9.1 summary with `cryptographicallyVerified: false`.
- `@treeship/mcp` gains WASM-backed verification helpers alongside its attestation surface. Attest paths remain subprocess-based.
- `scripts/release.sh` now pins `@treeship/core-wasm` to the exact release version across all dependent packages (sdk-ts, a2a, mcp, verify-js) at tag time. No caret ranges for this dependency — drift would break the schema-rules parity guarantee.
- Workspace `Cargo.toml` adds `[profile.release.package.treeship-core-wasm]` with `opt-level = "z"` and `codegen-units = 1`. CLI release tuning unchanged.
- `treeship_core` `hostname` dep moved to `target.'cfg(not(target_family = "wasm"))'`. WASM builds fall back to `"host_unknown"` in `default_host_id`; WASM contexts consume receipts rather than author them, so the fallback is benign.

#### Notes

- All packages that depend on `@treeship/core-wasm` pin to exact version `0.9.2` (no caret). `release.sh` enforces this at tag time.
- Subprocess fallback was not implemented for WASM. The SDK's `verifyReceipt` / `verifyCertificate` / `crossVerify` functions require a runtime that can load the bundled WebAssembly. Runtimes without WASM support can continue using the legacy `verify(id)` subprocess path.
- WASM imports are lazy: the SDK and bridge modules can load in environments where `@treeship/core-wasm` is not yet resolvable (early-bootstrap CI, non-verification code paths). The first verification call pays the load cost; subsequent calls reuse cached bindings.

#### Release-window follow-ups

- Edge runtime acceptance deploys to Vercel Edge, Cloudflare Workers, and AWS Lambda are **code-complete** in `tests/runtime-acceptance/` but the actual deploys + cold-start measurements run out-of-band. Acceptance criteria are documented in each subdirectory's README; rerun to reproduce.
- Comprehensive Codex adversarial review of the v0.9.x WASM migration surface is planned before v0.10.0 cuts. 174+ unit / integration tests pass workspace-wide, but a formal adversarial pass adds a second set of eyes.

#### Not in this release (coming in v0.10.0)

- Approval loop primitives (5 new Hub endpoints + `--require-approval` flag on `treeship wrap` + `treeship approver` CLI)
- `treeship.dev/verify` browser drag-and-drop page (unblocked now that v0.9.2 publishes `@treeship/core-wasm` and `@treeship/verify`)
- Command-artifact CLI surfaces to issue `KillCommand` / `TerminateSession` / etc. — the schemas exist as of v0.9.0

#### Rollback

Previous stable is v0.9.0 and remains published on every registry. **Do not roll back to v0.9.1** — the npm side of that tag is partial and will leave installs in an inconsistent state. Downgrade straight to v0.9.0:

```bash
npm install @treeship/sdk@0.9.0 @treeship/a2a@0.9.0 @treeship/mcp@0.9.0 treeship@0.9.0
cargo install treeship-core@0.9.0
pip install treeship-sdk==0.9.0
```

v0.9.0 verification uses the CLI subprocess — less portable, but still correct. `@treeship/core-wasm` and `@treeship/verify` are new in v0.9.2 and have no v0.9.0 counterpart to roll back to.

## 0.9.1 (2026-04-18)

> **Partial publish; superseded by 0.9.2. Do not install 0.9.1 npm packages.** This entry remains as a historical record. On npm, only `treeship`, `@treeship/cli-linux-x64`, `@treeship/cli-darwin-arm64`, and `@treeship/cli-darwin-x64` reached 0.9.1. `@treeship/core-wasm` and `@treeship/verify` never published, which cascaded install failures to `@treeship/sdk`, `@treeship/mcp`, and `@treeship/a2a`. `treeship-core` (crates.io) and `treeship-sdk` (PyPI) did reach 0.9.1 cleanly. v0.9.2 realigns everything.

Verification runs anywhere. WASM migration of the core verification surface, published as an npm package, and rewired through the SDK and bridge packages. Second of three planned releases in this window; see v0.9.0 for the schema foundation and v0.10.0 (upcoming) for the approval loop and drag-drop verifier.

### Added

- `@treeship/core-wasm` npm package. The Rust core compiled to WebAssembly with 10 exported functions (`verify_envelope`, `artifact_id`, `digest`, `decode_payload`, `verify_merkle_proof`, `verify_zk_proof`, `version`, plus the three new high-level ones below). Bundle size: **167 KB gzipped** (target was under 250 KB). First-class published npm package; pinned to exact versions across all dependents to prevent silent drift.
- `@treeship/verify` zero-dependency verification package at `packages/verify-js/`. Install alone, verify receipts and certificates in any runtime with WebAssembly + `fetch`. Only dependency is `@treeship/core-wasm`. This is what Witness, dashboards, and third-party consumers install.
- High-level WASM exports: `verify_receipt`, `verify_certificate`, `cross_verify` (item 1). Previously only low-level envelope and Merkle primitives were exposed. Each returns JSON in / JSON out with an error shape on malformed input rather than panicking.
- Reusable library primitive `treeship_core::verify::verify_receipt_json_checks` — lifted from the CLI's URL-fetch path so CLI and WASM share one implementation. Same checks (Merkle root recomputation, inclusion proofs, leaf count, timeline ordering, chain linkage) produce the same result across every runtime.
- `treeship_core::agent::verify_certificate` — Ed25519 signature check against the certificate's embedded public key. Exposed so the CLI, `@treeship/verify`, and future WASM consumers share one implementation.
- Runtime compatibility: **Node.js 18+, Deno, browser (bundler), Vercel Edge, Cloudflare Workers, AWS Lambda**. Edge runtime deploy harnesses at `tests/runtime-acceptance/{vercel-edge,cloudflare-worker,aws-lambda}/` — runnable projects with per-runtime READMEs.
- New docs: `sdk/verify.mdx`, `guides/edge-runtime.mdx`. Runtime compatibility matrices added to `@treeship/sdk`, `@treeship/a2a`, and `@treeship/mcp` READMEs. `reference/schema.mdx` gains a "Parity between CLI and WASM" section.
- Command-line build pipeline: `packages/core-wasm/build-npm.sh <version>` runs `wasm-pack build --target bundler`, optionally `wasm-opt -Oz`, then rewrites `pkg/package.json` with scoped name + license + repo + keywords. Release workflow installs wasm-pack + binaryen and runs this before the other npm publish steps so dependents resolve against the fresh core-wasm.

### Changed

- `@treeship/sdk` verification path migrated from CLI subprocess to direct WASM calls. `ship.verify.verify(id)` (legacy artifact-ID form) still subprocesses; new `verifyReceipt` / `verifyCertificate` / `crossVerify` methods run in-process via WASM. Stateful operations (attest, session, dock, agent register) still use subprocess.
- `@treeship/a2a` `verifyReceipt` now performs real cryptographic verification (was previously network-only structural summary). `VerifiedReceipt.cryptographicallyVerified` surfaces the WASM result; `verifyChecks` carries the per-step breakdown. Graceful fallback: if `@treeship/core-wasm` can't load in the runtime, returns the pre-v0.9.1 summary with `cryptographicallyVerified: false`.
- `@treeship/mcp` gains WASM-backed verification helpers alongside its attestation surface. Attest paths remain subprocess-based.
- `scripts/release.sh` now pins `@treeship/core-wasm` to the exact release version across all dependent packages (sdk-ts, a2a, mcp, verify-js) at tag time. No caret ranges for this dependency — drift would break the schema-rules parity guarantee.
- Workspace `Cargo.toml` adds `[profile.release.package.treeship-core-wasm]` with `opt-level = "z"` and `codegen-units = 1`. CLI release tuning unchanged.
- `treeship_core` `hostname` dep moved to `target.'cfg(not(target_family = "wasm"))'`. WASM builds fall back to `"host_unknown"` in `default_host_id`; WASM contexts consume receipts rather than author them, so the fallback is benign.

### Notes

- All packages that now depend on `@treeship/core-wasm` pin to exact version `0.9.1` (no caret). `release.sh` enforces this at tag time.
- Subprocess fallback was not implemented for WASM. The SDK's `verifyReceipt` / `verifyCertificate` / `crossVerify` functions require a runtime that can load the bundled WebAssembly. Runtimes without WASM support can continue using the legacy `verify(id)` subprocess path.
- WASM imports are lazy: the SDK and bridge modules can load in environments where `@treeship/core-wasm` is not yet resolvable (early-bootstrap CI, non-verification code paths). The first verification call pays the load cost; subsequent calls reuse cached bindings.

### Release-window follow-ups

- Edge runtime acceptance deploys to Vercel Edge, Cloudflare Workers, and AWS Lambda are **code-complete** in `tests/runtime-acceptance/` but the actual deploys + cold-start measurements run out-of-band (this session cannot authenticate to any of the three providers). Acceptance criteria are documented in each subdirectory's README; rerun to reproduce.
- Comprehensive Codex adversarial review of the v0.9.1 WASM migration surface is planned before v0.10.0 cuts. v0.9.0 carried the same note and the same plan holds here: 174+ unit / integration tests pass workspace-wide, but a formal adversarial pass adds a second set of eyes.

### Not in this release (coming in v0.10.0)

- Approval loop primitives (5 new Hub endpoints + `--require-approval` flag on `treeship wrap` + `treeship approver` CLI)
- `treeship.dev/verify` browser drag-and-drop page (unblocked now that v0.9.1 publishes `@treeship/core-wasm` and `@treeship/verify`)
- Command-artifact CLI surfaces to issue `KillCommand` / `TerminateSession` / etc. — the schemas exist as of v0.9.0

### Rollback

Previous stable is v0.9.0 and remains published on every registry. Downgrade:

```bash
npm install @treeship/sdk@0.9.0 @treeship/a2a@0.9.0 @treeship/mcp@0.9.0 treeship@0.9.0
cargo install treeship-core@0.9.0
pip install treeship-sdk==0.9.0
```

v0.9.0 verification uses the CLI subprocess — less portable, but still correct. `@treeship/core-wasm` and `@treeship/verify` are new in v0.9.1 and have no v0.9.0 counterpart to roll back to.

## 0.9.0 (2026-04-18)

Verification UX is now complete and future-proofed. v0.9.0 is the first of three planned releases in this window; see the roadmap at the bottom of this entry for the story.

### Added

- `treeship verify <url-or-path-or-artifact-id>` accepts three target shapes: HTTPS/HTTP URL fetched as receipt JSON, path to a local `.treeship` or `.agent` package directory, or a local artifact ID (the original v0.1 form). The URL and file paths produce the full checkmark-style output specified for the release. (item 1)
- `treeship verify --certificate <path-or-url>` cross-verifies a receipt against an Agent Certificate. Pass or fail is a roll-up of three checks: ship IDs match, certificate is valid at verify time, every tool the session called is authorized by the certificate. (item 1 + item 2)
- New exit codes on `verify`: `0` success, `1` verification failed, `2` cross-verification failed, `3` network or filesystem error. Documented in `docs/cli/verify.mdx`. (item 1)
- Reusable library primitive `treeship_core::verify::cross_verify_receipt_and_certificate(receipt, certificate, now_rfc3339)` returning `CrossVerifyResult` with authorized / unauthorized / never-called tool lists, ship-ID status, and certificate validity. Explicit `now` argument keeps the function deterministic for testing and for future edge-runtime callers. (item 2)
- `schema_version` field on Session Receipts and Agent Certificates. New documents emit `"1"`; documents without the field are treated as `"0"` (legacy) and verified under existing rules. Optional `Option<String>` with `#[serde(skip_serializing_if = "Option::is_none")]` so legacy documents round-trip byte-identical. Full semantics in `docs/reference/schema.mdx`. (item 3)
- `session.ship_id` field on Session Receipts, parsed from the manifest's `actor` URI when it starts with `ship://`. Absent on pre-v0.9.0 receipts and on non-ship actors (`human://alice`, bare `agent://`). Cross-verification uses it to check receipt and certificate reference the same ship. (item 2)
- `treeship_core::artifacts` module with five DSSE-signed command artifact schemas for supervisor → ship control-plane messaging: `KillCommand`, `ApprovalDecision`, `MandateUpdate`, `BudgetUpdate`, `TerminateSession`. Plus `verify_command(envelope, &authorized_keys)` helper. Ship as primitives in v0.9.0; CLI surfaces that issue and consume them ship in v0.10.0. (item 7)
- `treeship_core::agent::verify_certificate` validates the embedded Ed25519 signature on an `AgentCertificate` against its embedded public key. Exposed as a public library API so the CLI, `@treeship/verify` (v0.9.1), and third parties share one implementation. (item 1)
- `treeship_core::agent::effective_schema_version` helper resolves `Option<String>` to its effective string (`"0"` default). Use this over manual `Option` checks so the legacy default flows from one place.
- New docs: `cli/verify.mdx` rewrite, `concepts/cross-verification.mdx`, `concepts/command-artifacts.mdx`, `reference/schema.mdx`. `concepts/session-receipts.mdx` updated to mention the new fields. (item 11)
- Backwards-compatibility regression suite at `packages/core/tests/legacy_receipt_fixtures.rs` with synthesized + hand-curated v0.7.2 and v0.8.0 fixtures. Every future release must keep these fixtures verifying cleanly; if the schema changes in a way that breaks them, it must be documented here first. (item 9)

### Changed

- `treeship verify` dispatcher: URL-shaped and existing-path-shaped targets, or any invocation with `--certificate`, go through the new external path. Bare artifact IDs (including `"last"`) fall through to the original local-storage verify path unchanged.
- `ArtifactEntry` re-exported from `treeship_core::session` so downstream code can construct receipts without reaching into the package module.
- Legacy `Option<String>` defaults on `schema_version` and `session.ship_id` are deliberately informational in v0.9.0: `schema_version: "1"` and `"0"` both select the same ruleset. Future versions that diverge will bump to `"2"` and move the field inside the signed payload. See `reference/schema.mdx`.

### Explicitly deferred

Not hidden, not quiet. Each of these was in the original v0.9.0 draft; each got moved because shipping it with a cohesive announcement beats burying it in a release note. Three releases, three stories.

- **v0.9.1 — Runs everywhere.** WASM migration of `@treeship/sdk` and `@treeship/a2a` from CLI subprocess to direct `packages/core-wasm` calls, and the new `@treeship/verify` standalone npm package (zero `@treeship/sdk` dependency, pure WASM, for Vercel Edge / Cloudflare Workers / AWS Lambda / browser). The `@treeship/verify` package uses the same `cross_verify_receipt_and_certificate` implementation that ships in v0.9.0 — no semantic drift.
- **v0.10.0 — Live management primitives.** Approval-loop Hub endpoints (5 new routes), `--require-approval` flag on `treeship wrap`, `treeship approver add / list / remove` CLI. `treeship.dev/verify` browser-based drag-and-drop verifier (uses the WASM bundle from v0.9.1). The command artifact schemas are already in v0.9.0 (`ApprovalDecision`, etc.) so Witness can start consuming them before v0.10.0 lands.
- **v1.0.** API stability guarantee, `treeship upgrade` self-update, additional platform support and polish.

### Follow-ups in this release window

- Comprehensive Codex adversarial review: v0.9.0 included a scoped review item that was deferred on shipping constraints. The v0.9.0 surface is tested (165+ unit/integration tests across the workspace, including every legacy fixture), but a formal adversarial pass on the URL fetch / certificate cross-verify / command-artifact code paths will be run before v0.9.1 cuts.
- Page-by-page docs audit for feature status (AUTO / EXPLICIT / NOT YET CAPTURED) is partial. v0.9.0-specific pages are complete and the most-read concept page (`session-receipts.mdx`) is current; the remaining pages will be audited before v0.10.0.
- Clean-room VM acceptance tests on macOS arm64 / macOS x64 / Linux x64 run out-of-band.

### Rollback

Previous stable is v0.8.0 and remains published on every registry.

```bash
npm install -g treeship@0.8.0
npm install @treeship/sdk@0.8.0 @treeship/mcp@0.8.0 @treeship/a2a@0.8.0
cargo install treeship-cli@0.8.0 treeship-core@0.8.0
pip install treeship-sdk==0.8.0
```

No breaking wire-format changes between v0.8.0 and v0.9.0. A v0.9.0 verifier reads v0.8.0 receipts cleanly (regression suite enforces this). A v0.8.0 verifier reads v0.9.0 receipts cleanly as long as the new optional fields are ignored, which they are by default.

## 0.8.0 (2026-04-18)

### Added
- `treeship add` -- auto-detect and instrument installed agent frameworks (Claude Code, Cursor, Cline, Hermes, OpenClaw)
- `treeship quickstart` -- guided interactive setup from zero to receipt in under 90 seconds
- `treeship agent register` -- Agent Identity Certificate (.agent package with certificate.html)
- `treeship session event` -- append structured events to the active session's event log (used by MCP/A2A bridges)
- `treeship session status --watch` -- live terminal TUI showing agents, events, security, and verification progress
- `treeship declare` -- create .treeship/declaration.json with tool authorization scope
- `TREESHIP_PROVIDER` environment variable for provider attribution (anthropic, openrouter, bedrock)
- Setup one-liner at treeship.dev/setup (installs, initializes, instruments agents)
- Integration packages for Claude Code, Hermes, OpenClaw in integrations/ with skill files and MCP configs
- TREESHIP.md universal skill file for any agent that reads markdown instructions
- Production-quality preview.html: three-panel narrative, trust chain visual, agent cards, timeline grouping, retry detection, approval gates, honest empty states, sidebar IntersectionObserver, print stylesheet, copy buttons
- Tool authorization in receipts: declared vs actual tool usage, unauthorized calls flagged
- Self-contained Merkle verification in preview.html via Web Crypto API

### Changed
- `treeship init` output simplified to Ship ID + Key ID + next step hints
- `treeship wrap` without active session shows warning with fix instructions
- `treeship session close` auto-opens preview.html on macOS/Linux terminals
- All error messages now tell the user what command to run to fix the issue
- Root help text shows quick-start workflow first
- MCP bridge (@treeship/mcp) now emits session events so tool calls appear in receipt timeline
- Failed MCP tool calls are now audited (previously vanished from the audit trail)

### Removed
- `TREESHIP_COST_USD` environment variable and cost_usd field. Cost is a consumer concern (Witness dashboards, billing tools). Receipts store verifiable token usage only.
- RELEASE_NOTES_NEXT.md

### Fixed
- Device code auth: full 16-char code displayed, hub accepts 8-char prefix for backward compat
- Terminal escape injection in watch mode (sanitize all event fields)
- Path traversal in agent register (name sanitized to alphanumeric + dash + underscore)
- Case-insensitive script tag breakout in preview.html JSON escaping
- Raw mode guard ensures terminal restoration on all exit paths
- UTF-8 safe string truncation in TUI
- Hub: device_code redacted from access logs, format validated before DB lookup
- Hub: SQLite persistence reads DATABASE_PATH env var (Railway), consistent JSON error responses, session ID length cap, rate limiting

### Security
- 15+ findings from four rounds of Codex adversarial review, all addressed
- Atomic first-write ownership + write-once receipts on Hub
- 10 MB body-size limit on receipt upload
- Honest verification language ("Merkle structure verified", not "Verified")

## 0.7.2 (2026-04-15)

### Session Receipt: production-quality preview.html

- Self-contained verifier in preview.html: Merkle root recomputation, inclusion proof verification, and timeline ordering checks run client-side via Web Crypto API. Works air-gapped, zero network calls.
- Production design overhaul: three-panel narrative (planned/done/review), trust chain visual, agent cards with cost bars, command cards with retry detection, timeline grouped by agent, sidebar with IntersectionObserver, print stylesheet, copy buttons, mobile collapse.
- Honest empty states: grey "not captured" for unmeasured data, green confirmations only for things actually measured.
- Security hardening: XSS prevention via \u003c escaping, numeric coercion via num() helper, honest "Merkle structure verified" language (not "Verified").

### MCP bridge: session event wiring

- `treeship session event` CLI command: append structured events to the active session's event log. Used by MCP bridge, A2A bridge, and SDKs.
- `@treeship/mcp` now emits `agent.called_tool` session events after each tool call so MCP tool usage appears in the receipt timeline, agent graph, and side effects.
- Failed MCP tool calls are now audited (previously vanished from the audit trail).

### Agent instrumentation

- `TREESHIP_MODEL`, `TREESHIP_TOKENS_IN`, `TREESHIP_TOKENS_OUT`, `TREESHIP_COST_USD` environment variables: set these before `treeship wrap` to capture model, token counts, and cost in the receipt.
- `treeship declare` CLI command: create `.treeship/declaration.json` with `bounded_actions`, `forbidden`, `escalation_required`. Receipt compares declared vs actual tool usage and flags unauthorized calls.
- File operation type detection: wrap now distinguishes created, modified, and deleted files.
- ZK proof detection: `zk_proofs_present` is set automatically when proof files exist for the session.
- Approval gates shown in preview.html when approval artifacts are present.

### Hub hardening

- SQLite persistence: reads `DATABASE_PATH` env var (Railway), persistent default at `/var/lib/treeship/hub.db`.
- Consistent JSON error responses across all endpoints.
- Session ID length cap (128 chars).
- Rate limiting via chi Throttle middleware.
- Write-once receipts with RowsAffected check on conditional update.
- Crash-safe session close with `session.closing` recovery marker.
- Case-insensitive log redaction for session query parameters.

## 0.7.1 (2026-04-09)

### Security fixes (from Codex adversarial review)

- Store full 256-bit SHA-256 Merkle root in receipts instead of truncated 64-bit prefix. Prior receipts should be regenerated.
- Atomic first-write ownership on `PUT /v1/receipt/{session_id}`: dock_id is never overwritten on conflict, eliminating the race between two docks.
- Write-once receipt semantics: once a receipt is uploaded for a session_id, it cannot be replaced (byte-identical replays are accepted for retry safety). The `immutable` cache header is now honest.
- 10 MB body-size limit on receipt upload to prevent memory-DoS from authenticated docks.
- Daemon emits read events even when mtime also advances, preventing `touch` after a secret read from suppressing the `on: access` alert.
- Session close deletes `session.json` before composing the receipt to prevent late daemon events from landing in the log but not the receipt.
- `treeship session report` selects the most recently closed session by `session.ended_at` inside the receipt, not filesystem mtime.
- Log redaction matches the `session` query parameter case-insensitively.

## 0.7.0 (2026-04-09)

### Session Receipts

- New `treeship_core::session` module: event model, manifest, context propagation, agent graph, side effects, append-only event log, canonical receipt composer with Merkle root
- `.treeship` package format: deterministic `receipt.json` + `merkle.json` + `render.json` + per-artifact inclusion proofs + static `preview.html`
- `treeship session close` now composes a Session Receipt v1 and writes a `.treeship` package under `.treeship/sessions/`
- `treeship package inspect` and `treeship package verify` for offline inspection and local verification (no hub required)
- `treeship session report` uploads a closed session's receipt to the configured hub and prints the permanent public URL

### Hub: public receipt endpoints

- `PUT /v1/receipt/{session_id}` (DPoP-authenticated): idempotent upload, rejects cross-dock overwrites, refreshes per-ship agent registry from the receipt's agent graph
- `GET /v1/receipt/{session_id}` (public, no auth): returns 200 + raw receipt JSON, 403 "session still open" if the row exists without a receipt, 404 if not found. Permanent URL, immutable cache
- `GET /v1/ship/agents` and `GET /v1/ship/sessions`: per-ship registry endpoints for dashboards and A2A clients
- New `sessions` and `ship_agents` tables with composite keys scoped per dock

### Hub: workspace share tokens

- `POST /v1/session` (DPoP-authenticated): mints a short-lived opaque token bound to a dock_id at mint time
- New `auth.ResolveReader` helper: read endpoints accept either DPoP or `?session=TOKEN`, fails closed on expired tokens
- `treeship hub open` mints a share token and opens a browser URL that does not require a private key on the client
- Access logs now redact `session` query parameters to prevent tokens from landing in stdout

### Sensitive file read detection

- Daemon now tracks both mtime and atime per file; a `SnapshotDiff` separates writes from reads
- Sensitive-file pass walks dotfiles at the project root and one level into `.aws`, `.ssh`, `.gnupg`, `.docker`, `.kube`
- When a file matching an `on: access` rule has its atime advance, the daemon emits an `agent.read_file` event to the active session's event log with `capture_confidence: "inferred"` and writes an ALERT line if the rule has `alert: true`
- Closes the file-read capture gap that left `.env`, `*.pem`, and `.ssh/*` access invisible in prior releases

### A2A Integration

- New package: `@treeship/a2a`, framework-agnostic Treeship middleware for A2A (Agent2Agent) servers and clients
- `TreeshipA2AMiddleware` with `onTaskReceived` (awaited intent), `onTaskCompleted` (chained receipt), `onHandoff`, and `decorateArtifact`
- `buildAgentCard`, `hasTreeshipExtension`, `getTreeshipExtension`, `fetchAgentCard` for AgentCard discovery + extension publishing
- `verifyReceipt` and `verifyArtifact` for pre-delegation trust checks at line speed
- Canonical extension URI: `treeship.dev/extensions/attestation/v1`
- Zero runtime dependencies; never throws; CLI-missing path prints one actionable warning per process
- 15 vitest tests covering middleware, AgentCard helpers, CLI-missing handling, and `TREESHIP_DISABLE=1` short-circuit
- Docs: `docs/integrations/a2a.mdx` (Mintlify) and `treeship/docs/content/docs/integrations/a2a.mdx` (Fumadocs)
- Blog post: "A2A Makes Agents Interoperable. Treeship Makes That Interoperability Trustworthy."
- Release pipeline: `bridges/a2a` wired into `scripts/release.sh` and `.github/workflows/release.yml`

### Python SDK

- `Treeship.session_report(session_id=None)` returns a `SessionReportResult` with the permanent receipt URL, agent count, and event count
- Defaults to the most recently closed session when no `session_id` is given

## 0.5.0 (2026-04-04)

### Zero-Knowledge Proofs

- Circom Groth16 proofs: 3 circuits (policy-checker, input-output-binding, prompt-template)
- Trusted setup complete with Hermez powers-of-tau ceremony
- Real Groth16 WASM verification via ark-groth16 pairing math
- Verification keys embedded in WASM binary at compile time
- `treeship prove --circuit`, `treeship verify-proof`, `treeship zk-status` commands
- Auto-prove on declaration (when `bounded_actions` configured)
- Feature-flagged: `--features zk` (default build has zero ZK deps)

### RISC Zero Chain Proofs

- Guest program compiled for riscv32im target via rzup
- Real receipt-based proving and verification
- Background daemon proof queue with lock file safety
- Composite checkpoint: Merkle root + ChainProofSummary
- `treeship prove-chain` command
- Bonsai detection via `BONSAI_API_KEY` (local CPU default)

### Trust Model

- Documented Hermez ceremony trust assumption
- Bonsai marked as opt-in only (API key = consent)
- Offline verification documented for all proof types

### Release Pipeline

- npm: Pure OIDC via trusted publisher (no token)
- crates.io: ZK deps stripped for publish (full ZK via git install)
- All packages at 0.5.0 across npm, crates.io, PyPI

## 0.4.0

- Terminology: dock -> hub, login -> attach, logout -> detach, rm -> kill, workspace -> open
- Config: docks -> hub_connections, active_dock -> active_hub, dock_id -> hub_id
- New hub ID prefix: hub_ (backward compat with dck_)
- serde aliases for backward-compatible config deserialization
- All docs updated with new terminology
- New concept pages: ships, hub connections

## 0.3.1

- Fix: Remove print statement causing JSONDecodeError in synthetic_media_detector workflow
- Minor stability improvements

## 0.3.0

- Wrap command captures output digest, file changes, and git state
- Trust templates: 7 official templates (github-contributor, ci-cd, mcp-agent, claude-code, openclaw, hermes, research)
- Shell hooks for automatic attestation
- Background daemon for file watching
- Doctor diagnostic (9 checks)

## 0.2.1

- Hotfix for encrypted keystore path resolution on Linux
- Improved error messages for missing keys

## 0.1.0 (2026-03-31)

Initial release.

### Core
- DSSE envelope signing with Ed25519 (ed25519-dalek, NCC audited)
- 6 statement types: action, approval, handoff, endorsement, receipt, decision
- Encrypted keystore (AES-256-CTR + HMAC, machine-bound)
- Content-addressed artifact IDs from PAE bytes
- Rules engine with YAML config and command pattern matching
- Merkle tree with checkpoints, inclusion proofs, offline verification
- 120+ tests

### CLI
- 30+ commands: init, wrap, attest, verify, session, approve, hub, merkle, ui, otel
- Rich wrap receipts: output digest, file changes, git state, auto-chaining
- Shell hooks for automatic attestation
- Trust templates (7 official: github-contributor, ci-cd, mcp-agent, claude-code, openclaw, hermes, research)
- Interactive TUI dashboard (Ratatui)
- OpenTelemetry export (feature-flagged)
- Background daemon for file watching
- Doctor diagnostic (9 checks)

### Hub
- Go HTTP server with 12 API endpoints
- Device flow authentication with DPoP
- Artifact push/pull with Rekor anchoring
- Merkle checkpoint storage and proof serving
- CORS for treeship.dev

### SDKs
- @treeship/sdk (TypeScript, npm)
- @treeship/mcp (MCP bridge, npm)
- treeship-sdk (Python, PyPI)
- treeship-core, treeship-cli (Rust, crates.io)
- npm binary wrapper (treeship, platform packages)

### Website
- treeship.dev: landing page, /verify, /merkle, /connect, /hub/activate, /open
- docs.treeship.dev: 67 pages (Fumadocs), search, VS Code theme

### Security
- PID file locking, file permissions (0600/0700)
- Command sanitization (redact secrets)
- Untrusted config detection
- Shell hook absolute path (prevent PATH hijacking)
- DPoP (no stored session tokens)
