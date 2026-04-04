<div align="center">

# Treeship

**Portable trust receipts for agent workflows.**

[![Crates.io](https://img.shields.io/crates/v/treeship-cli.svg)](https://crates.io/crates/treeship-cli)
[![npm](https://img.shields.io/npm/v/@treeship/sdk.svg)](https://www.npmjs.com/package/@treeship/sdk)
[![PyPI](https://img.shields.io/pypi/v/treeship-sdk.svg)](https://pypi.org/project/treeship-sdk/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![CI](https://github.com/zerkerlabs/treeship/actions/workflows/ci.yml/badge.svg)](https://github.com/zerkerlabs/treeship/actions/workflows/ci.yml)

An open-source, local-first trust layer that creates and verifies signed receipts
for agent actions, handoffs, approvals, and dependencies.
Works offline. No central server. Portable evidence bundles anyone can verify.

</div>

---

Before you trust an agent's output, verify its receipts.

## Why

AI agents are being deployed into workflows where no one can verify what actually happened. Traditional logs are mutable, vendor-locked, and break across trust domains. Treeship fills the gap between "tool authorization" and "verifiable proof of what occurred."

- **Actions**: Signed receipts for every tool call, API request, or agent decision
- **Approvals**: Cryptographic proof that a human or authority approved an intent
- **Handoffs**: Tamper-evident records when work moves between agents or humans
- **Endorsements**: Third-party assertions of compliance or validation
- **Bundles**: Portable packages containing everything needed for offline verification

## Three Layers

| Layer | What it is |
|-------|------------|
| **Agents** | Actors (humans or AI) that produce receipts for their actions |
| **Treeships** | Trust domains that hold receipts, keys, and Merkle trees |
| **Hub connections** | Workspace links that connect a local Treeship to a remote hub for sharing and visibility |

## Prerequisites

- **Node.js 18+** (for npm install) or **Rust 1.75+** (for cargo install)
- Works on macOS, Linux, and Windows (WSL)

## Quick Start

### Install

```bash
# npm (recommended) -- prebuilt binary, no Rust required
npm install -g treeship

# Shell script -- auto-detects platform
curl -fsSL treeship.dev/install | sh

# From source (Rust engineers) -- full ZK support
cargo install --git https://github.com/zerkerlabs/treeship treeship-cli --features zk
```

### First receipt in 60 seconds

```bash
# Initialize a local Treeship
treeship init

# Wrap a command and capture a trust receipt
treeship wrap -- npm test

# Verify the last receipt
treeship verify last

# Attach to a hub (connects your Treeship to treeship.dev)
treeship hub attach

# Push the last receipt to the hub
treeship hub push last
```

### Multi-hub setup

You can connect a single Treeship to multiple hubs at once.

```bash
# Attach a named hub connection
treeship hub attach --name work

# Push to a specific hub
treeship hub push last --hub work
```

## How It Works

```
Agent / Human Action
        |
        v
  Treeship Core
        |
        +--> Canonicalize payload (RFC 8785)
        +--> Hash inputs/outputs (SHA-256)
        +--> Link to previous receipt
        +--> Sign with Ed25519
        +--> Append to Merkle log
        |
        v
  Local Receipt Store
        |
        +--> Bundle Builder
        +--> Checkpoint (signed Merkle root)
        +--> Verifier
        +--> Optional: Hub connection
```

### Verification checks

When you verify a bundle, Treeship runs:

1. **Signature verification** on each receipt (Ed25519 via DSSE envelope)
2. **Chain integrity** (each receipt links to the hash of the previous one)
3. **Merkle inclusion proofs** (each receipt is in the tree)
4. **Checkpoint verification** (signed snapshot of tree state)
5. **Policy evaluation** (optional local trust rules)

All checks work offline. No server callback required.

## Architecture

### Core Primitives

| Primitive | Purpose |
|-----------|---------|
| **Receipt** | Signed record of one action, approval, handoff, or endorsement |
| **DSSE Envelope** | Minimal signed container (Dead Simple Signing Envelope) |
| **Merkle Tree** | Append-only log with inclusion proofs |
| **Checkpoint** | Signed snapshot of tree state (anchoring point) |
| **Bundle** | Portable package for cross-system verification |
| **Policy** | Local trust rules (who to trust, what checks to require) |

### Trust Model

Treeship does not decide trust globally. Each verifier decides trust using local policy.

- **Local-first**: All signing and verification works offline
- **No central authority**: Trust comes from keys and policy, not a Treeship server
- **Portable**: Bundles are self-contained -- verify anywhere
- **Privacy-aware**: Default to input/output hashes, not raw content
- **Optional hub connections**: Connect your Treeship to treeship.dev for visibility and sharing

### Statement Types

```
treeship/action/v1       -- an agent or human did something
treeship/approval/v1     -- someone approved an intent or action
treeship/handoff/v1      -- work moved between actors
treeship/endorsement/v1  -- third-party asserts compliance
```

## SDK Usage

```typescript
import { Ship } from "@treeship/sdk";

// Initialize or load a ship
const ship = await Ship.init("./.treeship", "my-agent");

// Attest an action
const { receipt, receiptHash } = ship.attestAction({
  actor: { type: "agent", id: "agent://researcher" },
  actionType: "tool.call",
  actionName: "search.web",
  inputs: JSON.stringify({ query: "AI safety" }),
  outputs: JSON.stringify({ results: ["paper1"] }),
});

// Attest a handoff
ship.attestHandoff({
  fromActor: { type: "agent", id: "agent://researcher" },
  toActor: { type: "agent", id: "agent://executor" },
  taskCommitment: "complete-purchase",
});

// Create checkpoint and export bundle
ship.createCheckpoint();
const bundle = ship.createBundle("Research workflow");

// Save state
await ship.save();
```

## Packages

| Package | Location | Description |
|---------|----------|-------------|
| `treeship` (Rust core) | `packages/core/` | Receipt engine, signing, Merkle tree, verification |
| `treeship` (CLI) | `packages/cli/` | 25+ commands for issuing, bundling, verifying, hub connections |
| Hub server (Go) | `packages/hub/` | 12-endpoint API for treeship.dev |
| `@treeship/core-wasm` | `packages/core-wasm/` | 241KB WASM verifier (Merkle + Ed25519) |
| `@treeship/sdk` | `packages/sdk-ts/` | TypeScript SDK wrapping the WASM verifier |
| `@treeship/mcp` | `bridges/mcp/` | MCP bridge for agent tool integration |
| `treeship-sdk` | `packages/sdk-py/` | Python SDK |
| TUI | `packages/cli/` | Interactive terminal dashboard (Ratatui) |

## Documentation

Full documentation is available at **[docs.treeship.dev](https://docs.treeship.dev)**.

## Standards

Treeship builds on existing standards rather than inventing cryptography:

- **RFC 8785** (JSON Canonicalization Scheme) for deterministic signing
- **Ed25519** (RFC 8032) for signatures
- **DSSE** for signed envelopes (compatible with Sigstore/in-toto ecosystem)
- **SHA-256** for content addressing and Merkle tree
- **RATS/EAT** concepts for attestation roles (future)
- **SCITT** patterns for optional transparency anchoring (future)

## Roadmap

- [x] Rust core receipt engine and verification (120 tests)
- [x] CLI with 25+ commands
- [x] DSSE envelope support
- [x] Merkle tree with inclusion proofs and checkpoints
- [x] Policy and rules engine
- [x] Go Hub server (12 API endpoints)
- [x] Hub authentication (DPoP, device flow)
- [x] WASM verifier (241KB, browser-ready)
- [x] TypeScript SDK (@treeship/sdk)
- [x] MCP bridge (@treeship/mcp)
- [x] Fumadocs site (45 pages)
- [x] Terminal UI (`treeship ui` -- Ratatui interactive dashboard)
- [x] OpenTelemetry export (feature-flagged, works with Jaeger/Datadog/Langfuse)
- [x] Merkle tree (checkpoint, proof, verify, publish)
- [x] Zero-knowledge proofs (Circom Groth16, RISC Zero chain proofs)
- [ ] ZK TLS (TLSNotary) -- specced, feature-flagged, waiting on TLSNotary alpha
- [ ] `treeship attach claude/cursor` -- agent process detection
- [ ] Install script (`curl treeship.dev/install | sh`)
- [ ] Hub Merkle Rekor anchoring
- [ ] Capture adapters (shell, file, HTTP, A2A)
- [ ] Anchoring adapters (OTS/Bitcoin, Solana)
- [ ] Selective disclosure

## License

Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2025-2026 Zerker Labs, Inc.
