<div align="center">

# Treeship

**Portable, cryptographically signed receipts for AI agent sessions.**

[![Crates.io](https://img.shields.io/crates/v/treeship-core.svg)](https://crates.io/crates/treeship-core)
[![npm](https://img.shields.io/npm/v/treeship.svg)](https://www.npmjs.com/package/treeship)
[![PyPI](https://img.shields.io/pypi/v/treeship-sdk.svg)](https://pypi.org/project/treeship-sdk/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/zerkerlabs/treeship/actions/workflows/ci.yml/badge.svg)](https://github.com/zerkerlabs/treeship/actions/workflows/ci.yml)

Treeship turns every AI agent session into a portable, signed receipt.
Local-first. Cryptographically verifiable. Works offline.
Shareable with anyone. **The receipt is yours, not ours.**

</div>

---

## Why this exists

AI agents are doing real work — real money, real code, real decisions. But there's no clean way to answer the simplest question afterward: *what did the agent actually do?*

Chat logs are editable, screenshottable, deniable. They're a story, not evidence.

Treeship produces evidence: signed, timestamped, portable, verifiable receipts of every tool call an agent made. Show the receipt to a customer, a regulator, a teammate, or your future self in six months. It stays true.

## Install

### CLI (the binary you'll always need)

```bash
# One-liner: installs CLI, runs treeship init, instruments any AI agents
# it detects (Claude Code, Cursor, Hermes, OpenClaw)
curl -fsSL treeship.dev/setup | sh

# Or via npm (inspectable, signed package, no shell pipe)
npm install -g treeship
```

`/setup` and `/install` are both POSIX shell. macOS and Linux native. Windows users: use WSL — a native Windows binary is planned for v0.10.0.

### Claude Code plugin (recommended for Claude Code users)

```bash
claude plugin marketplace add zerkerlabs/treeship
claude plugin install treeship@treeship
```

After this, every Claude Code session in a project with a `.treeship/` directory auto-records to a portable, signed receipt. The plugin's SessionStart / PostToolUse / SessionEnd hooks fire automatically — no `treeship session start` to remember, no manual wrapping.

See [`integrations/claude-code-plugin/`](./integrations/claude-code-plugin/) for the full design.

## First receipt in 60 seconds

```bash
treeship init                       # one-time, per machine
treeship session start              # opens a recording session
treeship wrap -- npm test           # captures the command + its exit code + file writes
treeship session close              # seals the receipt
treeship session report             # uploads + prints a shareable URL
```

Or with the Claude Code plugin installed: just open Claude Code in a `treeship init`-ed project. Sessions start and seal themselves.

## What you get

- **Signed receipts** — Ed25519 over RFC 8785 canonical JSON (DSSE envelopes, in-toto compatible)
- **Auto-chaining** — every receipt links to the hash of the previous one
- **Merkle inclusion proofs** — packaged with the receipt for offline verification
- **Hash-only payloads** — by default the receipt stores SHA-256 of arguments and outputs, not the raw content
- **Approval binding** — `treeship attest action --approval-nonce` wires a human approval to the action it authorized
- **Local-first** — everything works offline; the hub is a publishing surface, not a custodian
- **Offline verification** — `treeship package verify` is pure WASM, no network required
- **Multi-runtime SDKs** — TypeScript, Python, Go (hub), Rust core; verifier runs on Node, Deno, browser, Vercel Edge, Cloudflare Workers, AWS Lambda

## Trust model

Treeship doesn't decide trust globally. Each verifier decides trust using local policy.

- Trust comes from keys + your policy, not from a Treeship server
- Receipts are portable bundles — verify anywhere, no callback to a Treeship API
- Privacy-aware default: payloads are hashed, not stored raw
- Hub connections are optional and per-receipt opt-in

For an exhaustive description of what `@treeship/mcp` actually captures (every field, in every artifact type), see [`TREESHIP.md`](./TREESHIP.md). It's the universal trust + onboarding doc that any AI agent can read to evaluate Treeship before using it.

## How it works

```
Agent / human action
        │
        ▼
  Treeship core
        │
        ├─ Canonicalize payload (RFC 8785)
        ├─ Hash inputs/outputs (SHA-256)
        ├─ Link to previous receipt
        ├─ Sign with Ed25519
        └─ Append to Merkle log
        │
        ▼
  Local receipt store (.treeship/)
        │
        ├─ Bundle builder
        ├─ Checkpoint (signed Merkle root)
        ├─ Verifier (pure WASM)
        └─ Optional: hub publish
```

Verification runs five checks: signatures (DSSE envelope), chain integrity (each receipt links to its parent), Merkle inclusion, checkpoint signature, and policy. All offline.

## Packages

### Rust crates (crates.io)

| Crate | Path | Description |
|---|---|---|
| `treeship-core` | `packages/core/` | Receipt engine, signing, Merkle tree, verification |

The CLI is distributed via the `treeship` npm wrapper (which auto-fetches the right platform binary), not as a separate cargo install.

### npm packages

| Package | Path | Description |
|---|---|---|
| `treeship` | `npm/treeship/` | CLI wrapper that auto-installs the right platform binary |
| `@treeship/sdk` | `packages/sdk-ts/` | TypeScript SDK (wraps the WASM verifier) |
| `@treeship/mcp` | `bridges/mcp/` | MCP bridge — every tool call gets a signed receipt with one import change |
| `@treeship/a2a` | `bridges/a2a/` | A2A bridge — verify receipts attached to agent-to-agent messages |
| `@treeship/verify` | `packages/verify-js/` | Zero-dependency verification package (WASM + fetch) |
| `@treeship/core-wasm` | `packages/core-wasm/` | Rust core compiled to WebAssembly (167 KB gzipped) |

### PyPI

| Package | Path | Description |
|---|---|---|
| `treeship-sdk` | `packages/sdk-python/` | Python SDK |

### Hub server (Go)

The reference hub server is at `packages/hub/` and runs at <https://api.treeship.dev>. Self-hosting is supported but uncommon today.

### Claude Code plugin

| Path | Description |
|---|---|
| `integrations/claude-code-plugin/` | Marketplace-installable plugin: SessionStart/PostToolUse/SessionEnd hooks + MCP server + skills |
| `.claude-plugin/marketplace.json` | Marketplace manifest at the repo root |

Install with `claude plugin marketplace add zerkerlabs/treeship && claude plugin install treeship@treeship`.

### Other agent integrations

| Path | Description |
|---|---|
| `integrations/claude-code/` | Manual Claude Code wiring (CLAUDE.md template + MCP config) — for users who don't want the plugin |
| `integrations/cursor/` | Cursor MCP wiring |
| `integrations/hermes/` | Hermes skill |
| `integrations/openclaw/` | OpenClaw skill |

## SDK example (TypeScript)

```typescript
import { Ship } from "@treeship/sdk";

const ship = await Ship.init("./.treeship", "agent://researcher");

const { receipt } = ship.attestAction({
  actor:      { type: "agent", id: "agent://researcher" },
  actionType: "tool.call",
  actionName: "search.web",
  inputs:     JSON.stringify({ query: "AI safety" }),
  outputs:    JSON.stringify({ results: ["paper1"] }),
});

ship.attestHandoff({
  fromActor:      { type: "agent", id: "agent://researcher" },
  toActor:        { type: "agent", id: "agent://executor" },
  taskCommitment: "complete-purchase",
});

ship.createCheckpoint();
const bundle = ship.createBundle("Research workflow");

await ship.save();
```

## Standards

Treeship builds on existing standards rather than inventing cryptography:

- **RFC 8785** (JSON Canonicalization Scheme) for deterministic signing
- **Ed25519** (RFC 8032) for signatures
- **DSSE** for signed envelopes (compatible with Sigstore / in-toto)
- **SHA-256** for content addressing and the Merkle tree

## Documentation

- Docs site: **<https://docs.treeship.dev>**
- Trust model + capture inventory: [`TREESHIP.md`](./TREESHIP.md)
- Changelog: [`CHANGELOG.md`](./CHANGELOG.md)
- Plugin design: [`integrations/claude-code-plugin/README.md`](./integrations/claude-code-plugin/README.md)

## Roadmap

Realistic, version-tagged.

**Shipped (v0.9.x)**
- Rust core, CLI, hub server, WASM verifier, TypeScript / Python SDKs
- MCP bridge (`@treeship/mcp`) and A2A bridge (`@treeship/a2a`)
- Merkle tree with inclusion proofs and checkpoints
- DSSE envelopes, Ed25519 signing, hash-only payload defaults
- ZK proofs (Circom Groth16, RISC Zero chain proofs)
- Hub authentication (DPoP, device flow), multi-hub support
- OpenTelemetry export (feature-flagged)
- Cross-process safe event log (flock + fail-open under contention)
- **Official Claude Code plugin** with auto-recording hooks (v0.9.3+)
- **Universal SKILL.md** at <https://treeship.dev/SKILL.md> for AI agent self-onboarding

**v0.9.5 / v0.10.0 (next)**
- O(1) event-log append (counter sidecar instead of full file rescan)
- Native Windows binary + PowerShell setup script
- Anthropic official-marketplace listing for the Claude Code plugin
- `treeship attach <agent>` — process detection for non-MCP agents
- Selective disclosure (redactable receipts)

**Researching, no commitment**
- ZK TLS (TLSNotary) — waiting on the TLSNotary alpha to stabilize
- Hub Merkle Rekor anchoring
- Anchoring adapters for OTS / Bitcoin / Solana

## License

Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2025–2026 Zerker Labs, Inc.
