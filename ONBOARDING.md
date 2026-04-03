
# Treeship Onboarding

Read this file to understand what Treeship is, how the repo is organized, and how to contribute.

## What Treeship Is

Portable trust layer for AI agent workflows. Every action, approval, and handoff gets a cryptographically signed receipt -- tamper-proof, verifiable by anyone, works offline.

The loop: `treeship wrap -- your-command` -> signed artifact -> `treeship dock push` -> `https://treeship.dev/verify/art_xxx`

## Links

| Resource | URL |
|----------|-----|
| GitHub | https://github.com/zerkerlabs/treeship |
| Docs | https://docs.treeship.dev |
| Website | https://treeship.dev |
| Hub API | https://api.treeship.dev |
| npm | https://www.npmjs.com/package/treeship |
| PyPI | https://pypi.org/project/treeship-sdk |
| Contributing | https://github.com/zerkerlabs/treeship/blob/main/CONTRIBUTING.md |
| Security | https://github.com/zerkerlabs/treeship/blob/main/SECURITY.md |
| Changelog | https://github.com/zerkerlabs/treeship/blob/main/CHANGELOG.md |
| License | Apache 2.0 |

## Quick Start

```bash
# Install
cargo install --git https://github.com/zerkerlabs/treeship treeship-cli
# or
npm install -g treeship

# Initialize
treeship init

# Sign an action
treeship wrap -- npm test

# Verify the chain
treeship verify last --full

# Push to Hub for a shareable link
treeship dock login

treeship dock push <artifact-id>
```

## Repo Structure

```
treeship/
  Cargo.toml              Rust workspace root
  AGENTS.md               Design spec + crypto invariants (READ FIRST)
  README.md               Project overview
  CONTRIBUTING.md          How to contribute
  SECURITY.md              Security policy
  CHANGELOG.md             Version history
  LICENSE                  Apache 2.0

  packages/
    core/                  Rust library (120 tests)
      src/
        attestation/       DSSE envelopes, PAE, Ed25519, content-addressed IDs
        statements/        6 types: action, approval, handoff, endorsement, receipt, bundle
        merkle/            Append-only tree, checkpoints, inclusion proofs
        keys/              AES-256-CTR + HMAC encrypted keystore
        storage/           Local artifact store
        bundle/            Pack/export/import .treeship files
        rules.rs           Policy engine with YAML config

    cli/                   Rust CLI binary (25+ commands)
      src/
        main.rs            Clap command tree, entrypoint
        config.rs          ~/.treeship/config.json management
        ctx.rs             Opens config + keys + storage
        printer.rs         Colored output, JSON mode, hints
        commands/           21 command modules (wrap, attest, verify, dock, etc.)
        templates/          7 YAML trust templates (openclaw, hermes, claude-code, etc.)
        tui/                Ratatui interactive dashboard
        otel/               OpenTelemetry export (feature-flagged)

    hub/                   Go HTTP server (12 endpoints)
      main.go              Chi router, CORS, all routes
      internal/
        db/                SQLite schema + queries
        dock/              Device flow auth (challenge/authorize)
        artifacts/         Push/pull + workspace
        verify/            Server-side verification
        dpop/              DPoP JWT verification
        merkle/            Checkpoint + proof endpoints
        rekor/             Sigstore Rekor anchoring

    core-wasm/             WASM verifier (241KB, browser-ready)
      src/lib.rs           verify_envelope, artifact_id, verify_merkle_proof

    sdk-ts/                TypeScript SDK (@treeship/sdk)
      src/                 ship.ts, attest.ts, verify.ts, dock.ts, exec.ts, types.ts

    sdk-python/            Python SDK (treeship-sdk)
      treeship_sdk/        client.py -- wraps CLI via subprocess

  bridges/
    mcp/                   MCP bridge (@treeship/mcp)
      src/                 client.ts, attest.ts, utils.ts, types.ts

  docs/                    Fumadocs site (57 pages, Next.js)
    content/
      docs/
        cli/               17 command reference pages
        api/               10 Hub API reference pages
        concepts/          8 pages (trust model, security, actors, approvals)
        guides/            4 pages (quickstart, how-it-works, templates)
        integrations/      6 pages (claude-code, cursor, openclaw, hermes, langchain, mcp)
        commerce/          3 pages (payment proofs, compliance)
        sdk/               2 pages
      blog/                15 technical posts

  npm/                     npm binary wrapper (zero-Rust install)
    treeship/              Main package -- detects platform, runs binary
    @treeship/             Platform-specific binary packages
      cli-darwin-arm64/
      cli-darwin-x64/
      cli-linux-x64/

  .github/workflows/
    ci.yml                 Tests on push/PR (cargo test, go build)
    release.yml            Build binaries, GitHub Release, npm + crates.io publish

  scripts/
    release.sh             Bumps version across all 8+ package files

  examples/                Usage examples
  test-vectors/            Cryptographic test fixtures
  schemas/                 JSON schemas
```

## Key Files to Read First

1. `AGENTS.md` -- single source of truth for design, crypto invariants, security model
2. `packages/core/src/attestation/pae.rs` -- PAE format (the foundation)
3. `packages/core/src/attestation/sign.rs` -- how artifacts are created
4. `packages/core/src/attestation/verify.rs` -- how artifacts are verified
5. `packages/core/src/statements/mod.rs` -- all statement types
6. `packages/cli/src/main.rs` -- CLI command structure
7. `packages/cli/src/commands/wrap.rs` -- the most important user-facing command
8. `packages/hub/main.go` -- Hub server routes and middleware

## Cryptographic Invariants (never change these)

**PAE format (DSSE spec)**
```
"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
```

**Artifact ID derivation**
```
artifact_id = "art_" + hex(sha256(PAE_bytes)[..16])
```
Same content always produces the same ID. ID is NOT stored inside statements.

**Envelope JSON (camelCase, DSSE spec)**
```json
{
  "payload":     "base64url(statement_bytes)",
  "payloadType": "application/vnd.treeship.action.v1+json",
  "signatures":  [{ "keyid": "key_...", "sig": "base64url(ed25519_sig)" }]
}
```

**Approval nonce binding**
```
action.approvalNonce == approval.nonce
```
Enforced at verify time. Prevents approval reuse.

## Statement Types

| Type | payloadType | Purpose |
|------|-------------|---------|
| Action | `application/vnd.treeship.action.v1+json` | Agent or human performed work |
| Approval | `application/vnd.treeship.approval.v1+json` | Human approved an action |
| Handoff | `application/vnd.treeship.handoff.v1+json` | Work transferred between agents |
| Endorsement | `application/vnd.treeship.endorsement.v1+json` | Third-party assertion |
| Receipt | `application/vnd.treeship.receipt.v1+json` | Wrap command output |
| Bundle | `application/vnd.treeship.bundle.v1+json` | Portable artifact package |

## CLI Commands

```bash
treeship init                    # Initialize ship (generates keypair)
treeship install                 # Install shell hooks
treeship wrap -- <cmd>           # Wrap command, auto-attest
treeship attest action           # Sign an action
treeship attest approval         # Sign an approval (returns nonce)
treeship attest handoff          # Sign agent-to-agent handoff
treeship attest decision         # Record LLM decision
treeship verify <id>             # Verify single artifact
treeship verify last --full      # Verify full chain
treeship log [--tail N]          # View receipt log
treeship session start|close     # Manage sessions
treeship approve|deny|pending    # Human approval workflow
treeship dock login              # Authenticate with Hub
treeship dock push <id>          # Push artifact to Hub
treeship dock pull <id>          # Pull artifact from Hub
treeship dock status             # Check dock state
treeship bundle create|export    # Create portable bundles
treeship checkpoint              # Create Merkle checkpoint
treeship merkle proof|verify     # Merkle operations
treeship trust-template <name>   # Apply trust template
treeship ui                      # Interactive TUI dashboard
treeship otel enable|test        # OpenTelemetry export
treeship doctor                  # Run diagnostic checks
treeship status                  # Show ship state
treeship keys list               # List signing keys
```

## Hub API Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | /v1/dock/challenge | Public | Start device flow |
| GET | /v1/dock/authorized | Public | Poll for approval |
| POST | /v1/dock/authorize | Public | Complete auth with keys |
| POST | /v1/artifacts | DPoP | Push artifact |
| GET | /v1/artifacts/:id | Public | Pull artifact |
| GET | /v1/workspace/:dockId | Public | List dock's artifacts |
| GET | /v1/verify/:id | Public | Verify artifact |
| POST | /v1/merkle/checkpoint | DPoP | Publish checkpoint |
| GET | /v1/merkle/checkpoint/:id | Public | Get checkpoint |
| POST | /v1/merkle/proof | DPoP | Publish proof |
| GET | /v1/merkle/:artifactId | Public | Get inclusion proof |
| GET | /.well-known/treeship/revoked.json | Public | Revocation list |

## Development Setup

```bash
git clone https://github.com/zerkerlabs/treeship
cd treeship

# Rust (core + CLI)
cargo build
cargo test -p treeship-core    # 120 tests

# Go (Hub)
cd packages/hub
go build ./...

# TypeScript SDK
cd packages/sdk-ts
npm install && npm test

# MCP bridge
cd bridges/mcp
npm install && npm test

# Docs site
cd docs
npm install && npm run dev     # localhost:3000

# Python SDK
cd packages/sdk-python
pip install -e .
```

## Contributing

1. Fork https://github.com/zerkerlabs/treeship
2. Create a branch: `git checkout -b fix/your-fix`
3. Make changes
4. Run tests: `cargo test -p treeship-core`
5. Commit with a clear message
6. Open a pull request

Style: `cargo fmt`, `cargo clippy`, `go fmt`. No em dashes in copy. Direct language, real CLI examples.

## Trust Templates

Built-in templates for common workflows:

| Template | Command | Use Case |
|----------|---------|----------|
| github-contributor | `treeship trust-template github-contributor` | OSS commit provenance |
| ci-cd-pipeline | `treeship trust-template ci-cd-pipeline` | Build/deploy chains |
| openclaw-agent | `treeship trust-template openclaw-agent` | OpenClaw legal workflows |
| hermes-agent | `treeship trust-template hermes-agent` | Hermes autonomous agent |
| claude-code-session | `treeship trust-template claude-code-session` | AI coding audit trail |
| mcp-agent | `treeship trust-template mcp-agent` | MCP tool attestation |
| research-agent | `treeship trust-template research-agent` | Multi-step research provenance |

## Architecture Principles

- **Local-first**: Every operation works offline. Hub adds shareability, never trust.
- **Self-contained**: A signed artifact is a JSON file. Verifies without database, API, or account.
- **Deterministic**: Same content always produces same artifact ID.
- **Open**: Verifier is open source. Anyone can verify without trusting Treeship.

## Context

- **Zerker Labs** is the company. **Treeship** is the open-source protocol and CLI. **treeship.dev Hub** is the hosted service.
- Built with: Rust (core + CLI), Go (Hub), TypeScript (SDK + MCP), Python (SDK), WASM (browser verifier)
- Standards: DSSE, Ed25519 (RFC 8032), RFC 8785 (JSON Canonicalization), SHA-256
