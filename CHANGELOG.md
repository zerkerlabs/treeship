# Changelog

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
