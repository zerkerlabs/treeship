# Treeship

**Portable trust receipts for agent workflows.**

Treeship is an open-source, local-first trust layer that creates and verifies signed receipts for agent actions, handoffs, approvals, and dependencies. It works offline, requires no central server, and produces portable evidence bundles that anyone can verify independently.

Before you trust an agent's output, verify its receipts.

## Why

AI agents are being deployed into workflows where no one can verify what actually happened. Traditional logs are mutable, vendor-locked, and break across trust domains. Treeship fills the gap between "tool authorization" and "verifiable proof of what occurred."

- **Actions**: Signed receipts for every tool call, API request, or agent decision
- **Approvals**: Cryptographic proof that a human or authority approved an intent
- **Handoffs**: Tamper-evident records when work moves between agents or humans
- **Endorsements**: Third-party assertions of compliance or validation
- **Bundles**: Portable packages containing everything needed for offline verification

## Quick Start

```bash
# Initialize a local Treeship
treeship init

# Issue action receipts as your agents work
treeship issue action \
  --actor agent://researcher \
  --action-name search.web \
  --inputs '{"query":"AI safety papers"}' \
  --outputs '{"results":["paper1","paper2"]}'

treeship issue action \
  --actor agent://checkout \
  --action-name payments.create \
  --inputs '{"amount":1200}' \
  --outputs '{"payment_id":"pay_123"}'

# Record a human approval
treeship issue approval \
  --approver human://ops-manager \
  --action-hash <hash-from-above>

# Record an agent-to-agent handoff
treeship issue handoff \
  --from agent://researcher \
  --to agent://checkout \
  --task "purchase laptop under budget"

# Create a checkpoint (signed Merkle root)
treeship checkpoint

# Export a portable bundle
treeship bundle --out workflow.treeship.json

# Verify the bundle (works offline, no server needed)
treeship verify workflow.treeship.json

# View the receipt log
treeship log
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
        +--> Optional: Dock to Hub
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
- **Optional docking**: Connect to treeship.dev Hub for visibility and sharing

### Statement Types

```
treeship/action/v1       -- an agent or human did something
treeship/approval/v1     -- someone approved an intent or action
treeship/handoff/v1      -- work moved between actors
treeship/endorsement/v1  -- third-party asserts compliance
```

## SDK Usage

```typescript
import { Ship } from "@treeship/core";

// Initialize or load a Treeship
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

| Package | Description |
|---------|-------------|
| `@treeship/core` | Receipt engine, signing, Merkle tree, verification |
| `treeship` (CLI) | Developer CLI for issuing, bundling, and verifying |

## Standards

Treeship builds on existing standards rather than inventing cryptography:

- **RFC 8785** (JSON Canonicalization Scheme) for deterministic signing
- **Ed25519** (RFC 8032) for signatures
- **DSSE** for signed envelopes (compatible with Sigstore/in-toto ecosystem)
- **SHA-256** for content addressing and Merkle tree
- **RATS/EAT** concepts for attestation roles (future)
- **SCITT** patterns for optional transparency anchoring (future)

## Roadmap

- [x] Core receipt engine and verification
- [x] CLI for local operations
- [x] DSSE envelope support
- [x] Merkle tree with inclusion proofs
- [x] Signed checkpoints
- [x] Policy evaluation
- [ ] Capture adapters (shell, file, HTTP, MCP, A2A)
- [ ] Dock to treeship.dev Hub
- [ ] Anchoring adapters (OTS/Bitcoin, Solana)
- [ ] Selective disclosure
- [ ] Rust core + WASM verifier

## License

Apache License 2.0. See [LICENSE](LICENSE).

Copyright 2025-2026 Zerker Labs, Inc.
