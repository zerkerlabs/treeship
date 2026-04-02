# Changelog

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
