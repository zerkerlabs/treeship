---
name: treeship
description: Create cryptographically signed, portable trust receipts for AI agent workflows using Treeship.dev. Use when the user wants to sign agent actions, create verifiable receipts, wrap commands with attestations, verify artifact chains, push artifacts to the Treeship Hub, manage approval-gated actions, or integrate Treeship into their agent workflow. Covers the Treeship CLI (treeship), Python SDK (treeship-sdk), TypeScript SDK (@treeship/sdk), MCP bridge (@treeship/mcp), and Hub API (api.treeship.dev). Trigger on any mention of attestation, verifiable receipts, signed receipts, agent trust, Treeship, action signing, cryptographic proof of agent work, portable receipts, approval workflows, session receipts, Merkle proofs, decision cards, or coverage levels.
---

# Treeship — Portable Trust Receipts for Agent Workflows

Local-first. Cryptographically verifiable. Works offline. Ed25519 signatures. SHA-256 content hashing. Merkle proofs. The receipt is yours, not ours.

## Quick Start

```bash
# Install Treeship
curl -fsSL treeship.dev/setup | sh

# Core loop
treeship wrap -- npm test        # sign what happened
treeship verify last             # verify offline
treeship hub push last           # share verify URL
```

## When to Use Treeship

- **Sign agent actions** — tamper-proof receipts of what an agent did
- **Verify workflows** — cryptographically verify chains of actions
- **Audit agent work** — evidence, not chat logs
- **Gate sensitive actions** — human approval before execution
- **Hand off between agents** — cryptographically signed transitions
- **Share verification URLs** — publish to treeship.dev
- **Comply with requirements** — auditable proof of behavior

## Installation

```bash
# One-liner (setup + init + instrument)
curl -fsSL treeship.dev/setup | sh

# Step by step
curl -fsSL treeship.dev/install | sh
treeship init
treeship setup

# Python SDK
pip install treeship-sdk

# TypeScript SDK
npm install -g treeship
npm install @treeship/sdk
npm install @treeship/mcp
```

## Core CLI Commands

```bash
treeship wrap -- <command>              # wrap with signed receipt
treeship verify <id>                    # verify chain
treeship verify last                    # verify most recent
treeship session start --name "..."     # start session
treeship session close                  # close session
treeship session report                 # upload receipt
treeship hub push last                  # push to Hub
treeship approve --approver human://... # create approval
treeship wrap --approval-nonce <n> --   # use approval
treeship init                           # keypair generation
treeship key show                       # show public key
treeship inspect <id>                   # inspect artifact
treeship doctor                         # check workspace
treeship ui                             # TUI dashboard
treeship setup                          # guided first-run
treeship add --discover                 # discover agents
treeship harness list                   # list harnesses
treeship harness inspect <id>           # inspect harness
treeship harness smoke <id>             # smoke test
```

## Actor URIs

- `agent://<name>` — AI agent
- `human://<name>` — Human operator
- `agent://ci-pipeline` — CI/CD system

## Statement Types

| Type | Purpose | Method |
|------|---------|--------|
| `treeship/action/v1` | Agent did something | `attest_action()` / `wrap` |
| `treeship/approval/v1` | Someone approved | `attest_approval()` / `approve` |
| `treeship/handoff/v1` | Work moved between agents | `attest_handoff()` |
| `treeship/decision/v1` | LLM made a decision | `attest_decision()` |
| `treeship/use/v1` | Approval consumed | auto (v0.9.9+) |

## Python SDK

```python
from treeship_sdk import Treeship

ts = Treeship()

# Attest action
result = ts.attest_action(
    actor="agent://my-agent",
    action="tool.call",
    parent_id="art_abc123",
    approval_nonce="nonce_xyz",
    meta={"tool": "read_file", "path": "src/main.rs"}
)
print(result.artifact_id)  # art_...

# Attest approval
approval = ts.attest_approval(
    approver="human://alice",
    description="approve deployment",
    expires_in=3600
)
print(approval.artifact_id, approval.nonce)

# Verify
verified = ts.verify(result.artifact_id)
# verified.outcome: "pass" | "fail" | "error"
# verified.chain: number of linked artifacts

# Push to Hub
push = ts.dock_push(result.artifact_id)
# push.hub_url: https://treeship.dev/verify/art_xxx

# Wrap command
result = ts.wrap("npm test", actor="agent://ci")

# Session report
report = ts.session_report()
# report.receipt_url: permanent public URL
```

## TypeScript SDK

```typescript
import { Ship } from "@treeship/sdk";

const ship = await Ship.init("./.treeship", "agent://my-agent");

const { receipt } = ship.attestAction({
  actor: { type: "agent", id: "agent://my-agent" },
  actionType: "tool.call",
  actionName: "search.web",
  inputs: JSON.stringify({ query: "AI safety" }),
  outputs: JSON.stringify({ results: ["paper1"] }),
});

ship.attestHandoff({
  fromActor: { type: "agent", id: "agent://researcher" },
  toActor: { type: "agent", id: "agent://writer" },
  taskCommitment: "complete-report",
});

ship.createCheckpoint();
const bundle = ship.createBundle("Workflow");
await ship.save();
```

## Approval-Gated Actions

```python
# 1. Human creates approval
approval = ts.attest_approval(
    approver="human://alice",
    description="approve payment up to $500",
    expires_in=3600
)

# 2. Agent uses approval nonce
result = ts.attest_action(
    actor="agent://executor",
    action="stripe.charge.create",
    approval_nonce=approval.nonce,
    meta={"amount": 299.00}
)

# 3. Verify (checks replay levels)
verified = ts.verify(result.artifact_id)
```

## Chained Workflow

```python
prev_id = None
for step in [
    {"actor": "agent://researcher", "action": "search.web"},
    {"actor": "agent://analyst", "action": "analyze.data"},
    {"actor": "agent://writer", "action": "generate.report"},
]:
    result = ts.attest_action(
        actor=step["actor"],
        action=step["action"],
        parent_id=prev_id
    )
    prev_id = result.artifact_id

result = ts.verify(prev_id)
print(f"Chain: {result.outcome}, {result.chain} steps")
```

## MCP Bridge

For agents with MCP support, add Treeship as an MCP server:

```bash
# Claude Code
claude mcp add --transport stdio treeship -- npx -y @treeship/mcp

# Kimi Code CLI
kimi mcp add --transport stdio treeship -- npx -y @treeship/mcp

# Cursor
# Add to ~/.cursor/mcp.json:
{
  "mcpServers": {
    "treeship": {
      "command": "npx",
      "args": ["-y", "@treeship/mcp"]
    }
  }
}
```

## Hub API

- Base: `https://api.treeship.dev/v1/`
- Auth: DPoP (no API keys)
- `POST /v1/artifacts` — push artifact
- `GET /v1/verify/:id` — public verification (no auth)
- `PUT /v1/receipt/{session_id}` — upload session receipt
- `GET /v1/merkle/:id` — Merkle inclusion proof

Public URLs: `https://treeship.dev/verify/{artifact_id}`

## Result Types

```python
ActionResult(artifact_id: str)
ApprovalResult(artifact_id: str, nonce: str)
VerifyResult(outcome: str, chain: int, target: str)
PushResult(hub_url: str, rekor_index: Optional[int])
SessionReportResult(session_id, receipt_url, agents, events)
```

All methods raise `TreeshipError` on failure.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `TREESHIP_API_KEY` | Hub API key (optional) |
| `TREESHIP_AGENT` | Default agent slug |
| `TREESHIP_HUB_ID` | Hub workspace ID |

## Key Files

- `~/.treeship/` — config, keys, local receipt store
- `~/.treeship/sessions/` — session packages
- `.treeship/` — project-local ship

## Standards

- **Ed25519** (RFC 8032) — signatures
- **DSSE** — envelope format (Sigstore/in-toto compatible)
- **SHA-256** — content addressing + Merkle tree
- **RFC 8785** — JSON canonicalization

## Resources

- Docs: https://docs.treeship.dev
- Hub: https://treeship.dev
- GitHub: https://github.com/zerkerlabs/treeship
