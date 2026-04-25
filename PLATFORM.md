# Treeship Platform Overview

> Portable trust receipts for agent workflows.
> Cryptographic proof of what your agents did, when, and under whose authority.

**Version:** 0.4.0
**Date:** April 1, 2026
**Maintainer:** Zerker Labs (@zerkerlabs)
**License:** Apache-2.0

---

## Table of Contents

- [Architecture](#architecture)
- [Repositories](#repositories)
- [Packages](#packages)
- [CLI Reference](#cli-reference)
- [Core Library](#core-library)
- [TypeScript SDK](#typescript-sdk)
- [Python SDK](#python-sdk)
- [MCP Bridge](#mcp-bridge)
- [Hub API](#hub-api)
- [Website](#website)
- [Documentation Site](#documentation-site)
- [npm Binary Distribution](#npm-binary-distribution)
- [Templates](#templates)
- [Release Pipeline](#release-pipeline)
- [Release History](#release-history)
- [Security](#security)
- [Contributing](#contributing)
- [Attribution](#attribution)

---

## Architecture

```
Layer 1: Agents      who acts (agent://coder, human://approver)
Layer 2: Treeships   the trust domain (one keypair, one artifact store)
Layer 3: Hub         how you share (named connections, attach/detach/kill)
```

**One Treeship, many agents, many hub connections.**

- The Treeship key signs everything.
- Hub connections control where artifacts appear on Hub.
- The tmux model: detach keeps the workspace alive on Hub. Kill removes it permanently.
- Verification is always offline. No network, no account, no trust in infrastructure.

---

## Repositories

| Repo | URL | Contents |
|------|-----|----------|
| **treeship** (monorepo) | https://github.com/zerkerlabs/treeship | CLI, core library, TypeScript SDK, Python SDK, MCP bridge, Hub API server, docs site |
| **treeship.dev** (website) | https://github.com/zerkerlabs/treeship.dev | Landing page, verification pages, activation flow, install script |

### Cloning

```bash
# Main monorepo
git clone https://github.com/zerkerlabs/treeship.git
cd treeship

# Website (separate repo)
git clone https://github.com/zerkerlabs/treeship.dev.git
```

### Monorepo structure

```
treeship/
  packages/
    core/           # Rust -- cryptographic engine (crates.io: treeship-core)
    cli/            # Rust -- CLI binary (crates.io: treeship-cli)
    core-wasm/      # Rust -- WASM build for browser verification
    sdk-ts/         # TypeScript -- @treeship/sdk
    sdk-python/     # Python -- treeship-sdk (PyPI)
    hub/            # Go -- Hub API server (api.treeship.dev)
  bridges/
    mcp/            # TypeScript -- @treeship/mcp
  npm/
    treeship/       # npm wrapper package
    @treeship/
      cli-darwin-arm64/
      cli-darwin-x64/
      cli-linux-x64/
  docs/             # Fumadocs (Next.js) -- docs.treeship.dev
  scripts/
    release.sh      # Version bump + tag script
  .github/
    workflows/
      release.yml   # CI/CD: build, publish to all registries
```

---

## Packages

All packages are at **v0.9.5** and published to their respective registries.

| Package | Registry | Install | Description |
|---------|----------|---------|-------------|
| `treeship` | [npm](https://www.npmjs.com/package/treeship) | `npm install -g treeship` | CLI wrapper (auto-downloads platform binary) |
| `treeship-core` | [crates.io](https://crates.io/crates/treeship-core) | `cargo add treeship-core` | Core cryptographic library |
| `@treeship/sdk` | [npm](https://www.npmjs.com/package/@treeship/sdk) | `npm install @treeship/sdk` | TypeScript SDK |
| `@treeship/mcp` | [npm](https://www.npmjs.com/package/@treeship/mcp) | `npm install @treeship/mcp` | MCP attestation bridge |
| `@treeship/a2a` | [npm](https://www.npmjs.com/package/@treeship/a2a) | `npm install @treeship/a2a` | Agent-to-agent message attestation bridge |
| `@treeship/verify` | [npm](https://www.npmjs.com/package/@treeship/verify) | `npm install @treeship/verify` | Zero-dep verification (WASM + fetch) |
| `@treeship/core-wasm` | [npm](https://www.npmjs.com/package/@treeship/core-wasm) | (transitive dep) | Rust core compiled to WebAssembly |
| `treeship-sdk` | [PyPI](https://pypi.org/project/treeship-sdk/) | `pip install treeship-sdk` | Python SDK |
| `@treeship/cli-darwin-arm64` | [npm](https://www.npmjs.com/package/@treeship/cli-darwin-arm64) | (auto-installed) | Binary for Apple Silicon |
| `@treeship/cli-darwin-x64` | [npm](https://www.npmjs.com/package/@treeship/cli-darwin-x64) | (auto-installed) | Binary for Intel Mac |
| `@treeship/cli-linux-x64` | [npm](https://www.npmjs.com/package/@treeship/cli-linux-x64) | (auto-installed) | Binary for Linux |

**Note:** the `treeship-cli` crate on crates.io is orphaned at v0.4.0. It is no longer the canonical install path; use the `treeship` npm wrapper instead. The crate name is preserved on crates.io to avoid squatting and to keep download counters meaningful for historical references.

**Plugin marketplace:** the treeship monorepo also ships `.claude-plugin/marketplace.json` at the root, so `claude plugin marketplace add zerkerlabs/treeship` registers the Treeship plugin marketplace. `claude plugin install treeship@treeship` then installs the official Claude Code plugin from `integrations/claude-code-plugin/`.

### npm organization

All scoped packages are under the **treeship** npm org: https://www.npmjs.com/org/treeship

The unscoped `treeship` wrapper is owned by `zerker1` with org access granted.

---

## CLI Reference

### Install

```bash
# Option 1: One-liner (recommended -- installs CLI + runs init + instruments any AI agents detected)
curl -fsSL treeship.dev/setup | sh

# Option 2: npm wrapper (binary only)
npm install -g treeship

# Option 3: Shell script (binary only, like option 2 but explicit)
curl -fsSL treeship.dev/install | sh
```

The `treeship-cli` cargo install path is no longer available; that crate is orphaned at v0.4.0. The CLI ships exclusively via the npm wrapper / shell installers above (which fetch a prebuilt platform binary, no Rust toolchain required).

### Quickstart

```bash
treeship init                          # create Treeship
treeship wrap -- npm test              # attest a command
treeship verify last                   # verify most recent artifact
treeship hub attach                    # connect to Hub
treeship hub push last                 # push to Hub, get verify URL
```

### Full command surface

```bash
# Identity
treeship init                           # create Treeship (keypair + artifact store)
treeship status                         # show state, keys, hub status
treeship version                        # show version
treeship doctor                         # health checks (11 checks)

# Attestation
treeship wrap -- <cmd>                  # attest any command execution
treeship attest action                  # manual action attestation
treeship attest approval                # cryptographic approval with nonce binding
treeship attest handoff                 # signed work transfer between actors
treeship attest endorsement             # third-party validation of an artifact
treeship attest receipt                 # external system confirmation
treeship attest decision                # agent reasoning and decision context

# Verification
treeship verify <id>                    # verify single artifact (offline)
treeship verify last                    # verify most recent artifact
treeship verify <id> --full             # full chain timeline with all checks
treeship verify <id> --format json      # machine-readable output

# Sessions
treeship session start [--name NAME]    # start a new session
treeship session status                 # show current session state
treeship session close [--summary TEXT] # close the active session

# Log
treeship log [--tail N]                 # list recent artifacts (default: 20)
treeship log --follow                   # stream artifacts in real time

# Hub connections (treeship.dev Hub)
treeship hub attach                     # connect to Hub (or reconnect)
treeship hub attach --name acme-corp    # named hub connection
treeship hub detach                     # disconnect (workspace persists on Hub)
treeship hub ls                         # list all known hub connections
treeship hub status                     # show active hub connection details
treeship hub use <name>                 # switch active hub connection
treeship hub push <id>                  # push artifact through active hub
treeship hub push <id> --hub <name>     # push through specific hub connection
treeship hub push <id> --all            # push through all hub connections
treeship hub pull <id>                  # pull artifact from Hub
treeship hub open                       # open workspace in browser
treeship hub kill <name>                # permanently remove a hub connection

# Merkle tree
treeship checkpoint                     # seal a signed Merkle root
treeship merkle status                  # show Merkle tree state
treeship merkle proof <id>              # generate inclusion proof
treeship merkle verify <file.json>      # verify proof offline
treeship merkle publish                 # publish to Hub + Rekor

# Templates
treeship templates                      # list bundled templates
treeship template preview <name>        # preview a template
treeship template apply <name>          # apply template to current project
treeship template validate <file>       # validate a template YAML file
treeship template save --name <name>    # save current config as template
treeship init --template <name>         # initialize with a template

# Approval workflow
treeship pending                        # list pending approvals
treeship approve [index]                # approve a pending action
treeship deny <index>                   # deny a pending action

# Bundle
treeship bundle create                  # create a bundle from artifacts
treeship bundle export <id>             # export a chain as a .treeship file
treeship bundle import <file>           # import a .treeship file

# Daemon
treeship daemon start [--foreground]    # start background watcher
treeship daemon stop                    # stop daemon
treeship daemon status                  # check daemon state

# TUI
treeship ui                             # interactive terminal dashboard

# Shell hooks
treeship install                        # install shell hooks (~/.zshrc)
treeship uninstall                      # remove shell hooks

# OTel (requires --features otel build)
treeship otel test                      # test OTel export
treeship otel status                    # show OTel config
```

---

## Core Library

**Package:** `treeship-core` on crates.io
**Language:** Rust
**Location:** `packages/core/`

The cryptographic engine used by the CLI and the WASM verifier.

- **DSSE** envelope signing and verification (Ed25519)
- **PAE** (Pre-Authentication Encoding) per DSSE spec
- **Content-addressed IDs** -- artifact IDs derived from content hash (`art_` prefix)
- **8 statement types:** action, approval, handoff, endorsement, receipt, bundle, decision, declaration
- **Merkle tree** -- RFC 9162 compliant (`sha256-rfc9162`), with algorithm versioning for backward compat
- **Signed checkpoints** -- binds index, root, tree_size, height, signer, signed_at
- **Encrypted keystore** -- AES-256-CTR + HMAC, keys encrypted at rest
- **WASM build** -- `packages/core-wasm/` compiles to WebAssembly for browser-side verification

### Standards

| Standard | Usage |
|----------|-------|
| DSSE (Dead Simple Signing Envelope) | Artifact envelope format |
| Ed25519 | Signature algorithm |
| RFC 9162 (Certificate Transparency) | Merkle tree construction |
| RFC 9449 (DPoP) | Hub authentication |
| RFC 8628 (Device Authorization) | Hub device flow login |
| Sigstore Rekor | Transparency log anchoring |

---

## TypeScript SDK

**Package:** `@treeship/sdk` on npm
**Language:** TypeScript
**Location:** `packages/sdk-ts/`

```typescript
import { ship, Ship } from '@treeship/sdk';

// Check CLI availability
const version = await Ship.checkCli();
// Returns version string or throws if treeship binary not found

const s = ship();

// Attest
const action = await s.attest.action({
  actor: 'agent://coder',
  action: 'file.write',
  inputDigest: 'sha256:abc123',
  meta: { key: 'value' }
});

const approval = await s.attest.approval({
  approver: 'human://alice',
  description: 'approve deploy to staging',
  expires: '2026-12-31T00:00:00Z',  // ISO-8601
  subject: 'art_xxx'
});

const decision = await s.attest.decision({
  actor: 'agent://analyst',
  model: 'claude-opus-4',
  tokensIn: 8432,
  tokensOut: 1247,
  summary: 'Analysis complete',
  confidence: 0.91
});

// Verify -- returns typed result, never throws for crypto failures
const check = await s.verify.verify('art_xxx');
// { outcome: 'pass' | 'fail', chain: number, target: string }
// Throws only for operational errors (binary not found, timeout)

// Hub
await s.hub.push('art_xxx');
await s.hub.pull('art_xxx');
const status = await s.hub.status();
// { attached: boolean, endpoint: string, hubId: string }
```

### Exports

```typescript
export { ship, Ship }           // Main entry point and class
export { AttestModule }         // s.attest.*
export { VerifyModule }         // s.verify.*
export { HubModule }            // s.hub.*
export { TreeshipError }        // Error class with .args property
export type {
  ActionParams, ApprovalParams, HandoffParams, DecisionParams,
  ActionResult, ApprovalResult, VerifyResult, PushResult
}
```

**Note:** The SDK shells out to the `treeship` CLI binary. Requires `treeship` on PATH. Use `Ship.checkCli()` to verify availability before calling other methods.

---

## Python SDK

**Package:** `treeship-sdk` on PyPI
**Language:** Python 3.9+
**Location:** `packages/sdk-python/`

```python
from treeship_sdk import Treeship

ts = Treeship()

# Wrap and attest
result = ts.wrap("npm test")
print(result.artifact_id)  # art_xxx

# Verify
ts.verify(result.artifact_id)

# Push to Hub
ts.hub.push(result.artifact_id)
```

---

## MCP Bridge

**Package:** `@treeship/mcp` on npm
**Language:** TypeScript
**Location:** `bridges/mcp/`

Drop-in replacement for `@modelcontextprotocol/sdk` Client that auto-attests every MCP tool call.

```typescript
import { TreeshipMCPClient } from '@treeship/mcp';

const client = new TreeshipMCPClient({
  actor: 'agent://my-agent'
});

const result = await client.callTool({
  name: 'search',
  arguments: { q: 'quarterly revenue' }
});

// Metadata attached to every tool result
result._treeship.intent        // intent artifact ID (synchronous)
result._treeship.tool          // tool name
result._treeship.actor         // actor URI
result._treeship.receipt       // receipt artifact ID (undefined initially)
result._treeship.receiptReady  // Promise<string | undefined>

// Wait for receipt if you need the ID
const receiptId = await result._treeship?.receiptReady;
```

### How it works

Two artifacts per tool call:

1. **Intent** (before call) -- `treeship/action/v1` with `.intent` action label. Proves what was about to happen. Nonce-bound if `TREESHIP_APPROVAL_NONCE` env var is set (uses `--approval-nonce` flag).

2. **Receipt** (after call) -- `treeship/receipt/v1` with system, kind, and subject linkage back to the intent. Proves what happened after.

Receipt attestation is **async/fire-and-forget**. It does not block tool call responses. Callers who need the receipt ID can `await result._treeship.receiptReady`.

---

## Hub API

**Base URL:** `https://api.treeship.dev`
**Language:** Go
**Location:** `packages/hub/`

### Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/v1/dock/challenge` | None | Start device flow |
| `POST` | `/v1/dock/authorize` | None | Complete device flow (two-step) |
| `GET` | `/v1/dock/authorized` | None | Poll device flow status |
| `POST` | `/v1/artifacts` | DPoP | Push a signed artifact |
| `GET` | `/v1/artifacts/:id` | None | Retrieve an artifact |
| `GET` | `/v1/workspace/:hubId` | DPoP | List workspace artifacts |
| `GET` | `/v1/verify/:id` | None | Server-side verification |
| `POST` | `/v1/merkle/checkpoint` | DPoP | Publish Merkle checkpoint |
| `POST` | `/v1/merkle/proof` | DPoP | Publish inclusion proof |
| `GET` | `/v1/merkle/checkpoint/latest` | None | Latest checkpoint |
| `GET` | `/v1/merkle/checkpoint/:id` | None | Specific checkpoint |
| `GET` | `/v1/merkle/:artifactId` | None | Get inclusion proof |
| `GET` | `/.well-known/treeship/revoked.json` | None | Revoked key list |

### Authentication

DPoP (RFC 9449) proof-of-possession on all write endpoints. No API keys, no session tokens, no bearer tokens.

Every authenticated request requires two headers:

```
Authorization: DPoP {hub_id}
DPoP: {proof_jwt}
```

The DPoP JWT is signed by the hub connection's Ed25519 private key and contains `iat`, `jti` (replay protection), `htm` (method), and `htu` (URL).

### Device flow (hub attach)

1. CLI calls `GET /v1/dock/challenge` -- gets `device_code` and `nonce`
2. User visits `treeship.dev/hub/activate` and enters the code
3. Browser calls `POST /v1/dock/authorize` without keys -- marks challenge approved
4. CLI polls `GET /v1/dock/authorized` until approved
5. CLI calls `POST /v1/dock/authorize` with `ship_public_key`, `hub_public_key`, `device_code`, and mandatory `nonce`
6. Hub atomically consumes the challenge (single-use) and creates the hub connection record
7. CLI saves `hub_id` and keys to local config

### Security hardening (v0.3.1+)

- Workspace endpoint requires DPoP (was publicly enumerable)
- Nonce is mandatory for key-bearing authorize finalization
- Challenge consumption is atomic (prevents race condition replay)
- Exact device_code matching (no LIKE prefix matching)

---

## Website

**URL:** https://treeship.dev
**Framework:** Next.js on Vercel
**Repo:** https://github.com/zerkerlabs/treeship.dev

### Routes

| Route | Description |
|-------|-------------|
| `/` | Landing page |
| `/hub/activate` | Device flow activation (enter code, click Approve) |
| `/verify/[id]` | Client-side artifact verification via WebAssembly |
| `/workspace/[hubId]` | Workspace dashboard |
| `/merkle` | Browser-based Merkle proof verifier |
| `/connect` | Installation page with copy-paste commands |
| `/install` | Shell script (OS detection, binary download, cargo fallback) |
| `/blog` | Redirects to docs.treeship.dev/blog |

`/dock/activate` permanently redirects to `/hub/activate` for backward compat.

Verification runs entirely client-side via WebAssembly (`treeship-core-wasm`). No server trust required.

---

## Documentation Site

**URL:** https://docs.treeship.dev
**Framework:** Fumadocs (Next.js)
**Location:** `docs/` in the main monorepo
**Auto-deploys** from `main` branch via Vercel

### Structure

| Section | Pages | Covers |
|---------|-------|--------|
| Get Started | 4 | Introduction, quickstart, how it works, templates |
| Core Concepts | 11 | Treeships, agents, hub connections, trust model, approvals, handoffs, declarations, merkle proofs, chain integrity, security, vocabulary |
| CLI Reference | 14 | All commands with flags, examples, output |
| SDK | 2 | TypeScript (full export reference), MCP bridge |
| API | 8 | All 13 endpoints, OpenAPI 3.1 spec, request/response schemas |
| Integrations | 5 | Claude Code, Cursor, OpenClaw, Hermes, LangChain |
| Commerce | 3 | Overview, payment proofs, compliance |

### OpenAPI spec

Available at `docs.treeship.dev/api/hub-openapi.yaml` and in the repo at `docs/public/api/hub-openapi.yaml`.

---

## npm Binary Distribution

The `treeship` npm package is a thin wrapper that auto-downloads the correct platform binary on `npm install`:

```
npm install -g treeship
  -> installs treeship (wrapper)
  -> optionalDependency: @treeship/cli-{platform}
  -> postinstall downloads binary from GitHub Releases
  -> binary placed at node_modules/@treeship/cli-{platform}/bin/treeship
  -> wrapper bin/treeship.js routes to platform binary
```

Platform packages:
- `@treeship/cli-darwin-arm64` -- Apple Silicon (M1/M2/M3)
- `@treeship/cli-darwin-x64` -- Intel Mac
- `@treeship/cli-linux-x64` -- Linux x86_64

If the binary download fails, postinstall prints a fallback message pointing the user to the shell installer (`curl -fsSL treeship.dev/install | sh`) or the one-liner setup (`curl -fsSL treeship.dev/setup | sh`). The `cargo install treeship-cli` fallback is no longer offered (that crate is orphaned at v0.4.0).

---

## Templates

7 bundled templates in `packages/cli/src/templates/`:

| Template | Description | Use case |
|----------|-------------|----------|
| `github-contributor` | Git workflow attestation | Open source contributions |
| `ci-cd-pipeline` | CI/CD pipeline receipts | Build and deploy automation |
| `research-agent` | Research workflow with approvals | AI research agents |
| `mcp-agent` | MCP tool call attestation | Model Context Protocol agents |
| `claude-code-session` | Claude Code session tracking | AI coding sessions |
| `openclaw-agent` | OpenClaw integration | Legal AI workflows |
| `hermes-agent` | Hermes integration | Multi-agent orchestration |

### Template YAML schema

Templates define session config, attestation rules, approval requirements, and hub settings. Full schema documented at `docs.treeship.dev/guides/templates`.

Key fields: `session` (auto_start, auto_checkpoint), `attest.commands[]` (match, action, capture_output_digest), `attest.paths[]` (glob, alert), `approvals.require_for[]`, `hub` (auto_push, push_on, endpoint).

---

## Release Pipeline

### How to release

```bash
# From the repo root:
./scripts/release.sh 0.5.0
git push && git push --tags
```

The release script:
1. Bumps version in all 9 package manifests (Cargo.toml, package.json, pyproject.toml)
2. Updates cross-references (optionalDependencies, Cargo inter-crate deps)
3. Updates Cargo.lock
4. Commits with `Release vX.Y.Z` message
5. Creates git tag `vX.Y.Z`

The `v*` tag triggers `.github/workflows/release.yml`:
1. **Build** -- compiles Rust binaries for 3 platforms (linux-x64, darwin-arm64, darwin-x64)
2. **Release** -- creates GitHub Release with binaries and auto-generated notes
3. **publish-npm** -- publishes 7 npm packages (SDK, MCP, CLI wrappers, main)
4. **publish-crates** -- publishes treeship-core and treeship-cli to crates.io
5. **publish-pypi** -- builds and publishes treeship-sdk to PyPI

### Secrets required (GitHub repo settings)

| Secret | Registry | How to get |
|--------|----------|------------|
| `NPM_TOKEN` | npm | npmjs.com > Access Tokens > Granular (read-write all packages) |
| `CARGO_TOKEN` | crates.io | crates.io > Account Settings > API Tokens |
| `PYPI_TOKEN` | PyPI | pypi.org > Account > API tokens (scoped to treeship-sdk) |

All publish steps use `continue-on-error: true` so re-runs don't fail on already-published versions.

---

## Release History

### v0.4.0 (April 1, 2026)

**Terminology rename: dock -> hub, attach/detach/kill**

- All `dock` commands renamed to `hub` with tmux-inspired verbs
- `dock login` -> `hub attach`, `dock logout` -> `hub detach`, `dock rm` -> `hub kill`, `dock workspace` -> `hub open`
- Config: `docks` -> `hub_connections`, `active_dock` -> `active_hub`, `dock_id` -> `hub_id`
- New `hub_` ID prefix (backward compat with `dck_` via serde aliases)
- Website: `/dock/activate` redirects to `/hub/activate`
- New concept docs: Treeships, Hub connections (with tmux model)
- Bare "ship" renamed to "Treeship" in all docs

### v0.3.1 (April 1, 2026)

**13 security and correctness fixes from Codex adversarial reviews**

Hub:
- Workspace endpoint requires DPoP authentication (was publicly enumerable)
- Mandatory nonce in authorize finalization (was optional, bypassing validation)
- Atomic challenge consumption (prevents race condition replay)
- Removed LIKE prefix matching from challenge lookups

Core:
- `verify_with_key` fixed (was using pubkey bytes as secret key seed)
- Merkle tree now RFC 9162 compliant (promote unpaired nodes, not duplicate)
- Checkpoint signatures bind all metadata (index, height, signer)
- Merkle algorithm versioning (`sha256-rfc9162` field, backward compat with `sha256-duplicate-last`)

MCP:
- Approval nonce passed via `--approval-nonce` flag (was buried in `--meta`)
- Post-call attestation uses real `treeship/receipt/v1` artifacts
- Receipt attestation moved off hot path (async, fire-and-forget with `receiptReady` promise)

SDK:
- `verify()` returns typed `{ outcome: "fail" }` for crypto failures (was throwing)
- Approval API: `expires` takes ISO-8601, `subject` replaces dropped `scope`
- Added `Ship.checkCli()` for CLI availability checking

### v0.3.0 (April 1, 2026)

**Multi-dock architecture**

- Named dock connections: `dock login --name acme-corp`
- Config schema: flat `hub` -> `docks` HashMap with `active_dock`
- Auto-migration from v0.1/v0.2 config on first run
- `dock push --dock <name>` and `--all` flags
- `dock workspace` command
- Breaking: `dock undock` replaced by `dock logout`

### v0.2.1 (April 1, 2026)

**Feature pass fixes**

- Secret leak in `output_summary` -- redaction applied to stdout capture
- Daemon untrusted config -- `init` writes `config.json` marker
- `treeship verify last` keyword support
- `treeship attest endorsement` subcommand implemented
- Auto-chain all attest commands via `write_last()`
- `~/.treeship/` directory permissions set to 0700
- Hub Dockerfile with treeship CLI for `/v1/verify`
- Full release pipeline: npm, crates.io, PyPI, GitHub Releases
- Automated PyPI publishing in CI

---

## Security

**Hub authentication (summary):** **Enrollment** uses a device-style browser flow (see [Hub API](#authentication) / `GET /v1/dock/challenge` ...). **Every authenticated Hub write** uses **DPoP (RFC 9449)** with the connection's private key -- **not** a replayable bearer token. A **device code is not required on each push**; that is by design. What the Hub calls a "device" is a **registered dock (cryptographic identity)**, not hardware attestation, unless a future release adds it.

**Threat model and operational guidance:** [docs: Security (concepts)](https://docs.treeship.dev/concepts/security) -- see *Hub connection model: enrollment and operation*.

**Supported versions:**

| Version | Status |
|---------|--------|
| 0.9.x | Supported (current) |
| 0.8.x | Security fixes only |
| < 0.8 | No longer supported |

Report vulnerabilities to security@treeship.dev or via GitHub Security Advisories.

See [SECURITY.md](SECURITY.md) for reporting policy, Hub auth summary, and version table.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Local development

```bash
# Rust (CLI + core)
cargo build -p treeship-cli
cargo test --workspace
cargo check -p treeship-cli

# TypeScript SDK
cd packages/sdk-ts && npm install && npm run build && npm test

# MCP bridge
cd bridges/mcp && npm install && npm run build && npm test

# Hub (Go)
cd packages/hub && go build ./... && go test ./...

# Docs
cd docs && npm install && npm run dev
```

---

## Attribution

- **Zerker Labs** -- architecture, specification, and product design
- **Claude Opus 4.6** -- implementation, security fixes, documentation, release engineering
- **OpenAI Codex (via Claude Code plugin)** -- adversarial security reviews across Hub, core, SDK, and MCP bridge

Built with: Rust, Go, TypeScript, Python, Next.js, Fumadocs, Ed25519, DSSE, DPoP (RFC 9449), RFC 9162 (Certificate Transparency), Sigstore Rekor.
