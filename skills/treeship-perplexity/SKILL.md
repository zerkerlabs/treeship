---
name: treeship-perplexity
description: "Use Treeship (treeship.dev) from Perplexity Computer — install, configure, sign agent actions, verify receipts, push to the Hub, run approval-gated workflows, and work on the zerkerlabs/treeship source repo via GitHub. Trigger on any mention of Treeship, treeship.dev, signed receipts, agent attestation, verifiable agent actions, cryptographic proof of agent work, DSSE artifacts, Merkle proofs, approval-gated actions, session receipts, or the treeship CLI. Also load when asked to contribute to or inspect the zerkerlabs/treeship GitHub repository."
license: Apache-2.0
metadata:
  author: zerkerlabs
  version: '1.0'
  repo: https://github.com/zerkerlabs/treeship
  docs: https://docs.treeship.dev
  hub: https://treeship.dev
---

# Treeship — Perplexity Computer Skill

Treeship turns every AI agent session into a portable, signed receipt. Local-first. Cryptographically verifiable. Works offline. Shareable with anyone.

**The receipt is yours, not ours.**

## When to Use This Skill

Load this skill when the user:

- Wants to install or set up Treeship
- Asks to sign, attest, or create receipts for agent actions
- Wants to verify a Treeship artifact chain
- Asks about the Hub, pushing artifacts, or shareable verify URLs
- Needs approval-gated actions (human-in-the-loop before execution)
- Asks about the Python SDK (`treeship-sdk`), TypeScript SDK (`@treeship/sdk`), or MCP bridge (`@treeship/mcp`)
- Wants to inspect, browse, or contribute to the `zerkerlabs/treeship` GitHub repo
- Asks about Treeship's cryptographic design (DSSE, Ed25519, Merkle trees, SHA-256)

## GitHub Access

The `zerkerlabs/treeship` repo is accessible via the `gh` CLI with the `github` credential preset:

```bash
# List repo structure
gh api repos/zerkerlabs/treeship/contents/

# Read a file from the repo
gh api repos/zerkerlabs/treeship/contents/<path> | python3 -c \
  "import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['content']).decode())"

# Search issues
gh issue list --repo zerkerlabs/treeship

# Search pull requests
gh pr list --repo zerkerlabs/treeship
```

Always use `api_credentials=["github"]` in bash tool calls when using `gh`.

**Key files to read for contributor tasks:**
1. `AGENTS.md` — source of truth for repo structure, crypto invariants, CLI UX rules
2. `TREESHIP.md` — what the MCP bridge captures, field-by-field inventory
3. `README.md` — full feature set, packages, roadmap
4. `ONBOARDING.md` — onboarding guide

**Repo structure (key paths):**

| Path | What |
|------|------|
| `packages/core/` | Rust core library — attestation, signing, Merkle, verifier |
| `packages/cli/` | Rust CLI — 25+ commands |
| `packages/hub/` | Go Hub server — 12 API endpoints |
| `packages/sdk-ts/` | TypeScript SDK (`@treeship/sdk`) |
| `packages/sdk-python/` | Python SDK (`treeship-sdk`) |
| `bridges/mcp/` | MCP bridge (`@treeship/mcp`) |
| `docs/` | Fumadocs documentation site |
| `skills/` | Agent skills (including this one) |
| `integrations/claude-code-plugin/` | Claude Code plugin |

## Installation

```bash
# One-liner: installs CLI, runs treeship init, instruments detected agents
curl -fsSL treeship.dev/setup | sh

# Via npm (no shell pipe)
npm install -g treeship

# Python SDK
pip install treeship-sdk

# TypeScript SDK + MCP bridge
npm install @treeship/sdk @treeship/mcp
```

**Platform support:** macOS (arm64, x64) and Linux x86_64. Windows: use WSL.

## Core CLI Loop

```bash
treeship init                             # one-time keypair generation
treeship session start --name "my task"   # open a session
treeship wrap -- npm test                 # wrap a command → signed receipt
treeship verify last                      # verify offline
treeship hub push last                    # push → shareable URL
treeship session close --headline "done"  # seal the session receipt
treeship session report                   # upload session receipt
```

## Full CLI Reference

```bash
# Session management
treeship session start --name "..."
treeship session status
treeship session close --headline "..."
treeship session report

# Wrapping and attesting
treeship wrap -- <command>
treeship attest action --actor agent://name --action tool.call
treeship attest approval --approver human://alice --expires 2026-12-31T00:00:00Z
treeship attest handoff --from agent://a --to agent://b

# Verification
treeship verify <artifact-id>
treeship verify last
treeship package verify <path-to.treeship>
# Since v0.10.3, verifying hub-checkpoint or agent-certificate artifacts
# requires the issuer to be pinned via `treeship trust add` — otherwise
# verify fails with "untrusted issuer" instead of silently passing.

# Hub / Dock
treeship hub attach [--endpoint https://api.treeship.dev]
treeship hub push <artifact-id>
treeship hub pull <artifact-id>
treeship hub status

# Inspection
treeship inspect <artifact-id>
treeship log [--tail N] [--follow]
treeship status
treeship doctor

# Keys
treeship keys list
treeship key show

# Trust roots (v0.10.3+)
treeship trust list
treeship trust add <key_id> <pubkey> --kind <hub_checkpoint|ship|agent_cert>
treeship trust remove <key_id>

# Merkle
treeship checkpoint
treeship merkle proof <artifact-id>
treeship merkle verify <artifact-id>

# Setup
treeship setup
treeship add --all           # instrument detected agents
treeship add --discover

# UI
treeship ui                  # Ratatui interactive TUI dashboard
```

## Python SDK

```python
from treeship_sdk import Treeship

ts = Treeship()

# Sign an action
result = ts.attest_action(
    actor="agent://my-agent",
    action="tool.call",
    meta={"tool": "read_file", "path": "src/main.rs"}
)
print(result.artifact_id)  # art_...

# Create approval (human-in-the-loop)
approval = ts.attest_approval(
    approver="human://alice",
    description="approve deployment",
    expires_in=3600          # seconds
)
# approval.nonce → pass to action as approval_nonce

# Approval-gated action
result = ts.attest_action(
    actor="agent://executor",
    action="deploy.production",
    approval_nonce=approval.nonce,
    meta={"commit": "abc123", "env": "prod"}
)

# Verify
verified = ts.verify(result.artifact_id)
# verified.outcome: "pass" | "fail" | "error"
# verified.chain:   number of linked artifacts

# Push to Hub
push = ts.dock_push(result.artifact_id)
print(push.hub_url)   # https://treeship.dev/verify/art_xxx

# Wrap a shell command
result = ts.wrap("npm test", actor="agent://ci")

# Session report (permanent shareable URL)
report = ts.session_report()
print(report.receipt_url)
```

## TypeScript SDK

```typescript
import { Ship } from "@treeship/sdk";

const ship = await Ship.init("./.treeship", "agent://my-agent");

const { receipt } = ship.attestAction({
  actor:      { type: "agent", id: "agent://my-agent" },
  actionType: "tool.call",
  actionName: "search.web",
  inputs:     JSON.stringify({ query: "AI safety" }),
  outputs:    JSON.stringify({ results: ["paper1"] }),
});

ship.attestHandoff({
  fromActor: { type: "agent", id: "agent://researcher" },
  toActor:   { type: "agent", id: "agent://writer" },
  taskCommitment: "complete-report",
});

ship.createCheckpoint();
const bundle = ship.createBundle("Workflow");
await ship.save();
```

## MCP Bridge

Adds Treeship attestation to every MCP tool call — no code changes required.

```bash
# Claude Code
claude mcp add --transport stdio treeship -- npx -y @treeship/mcp

# Cursor — add to ~/.cursor/mcp.json
{
  "mcpServers": {
    "treeship": { "command": "npx", "args": ["-y", "@treeship/mcp"] }
  }
}
```

The bridge signs an **intent attestation** before each tool call and a **result receipt** after. Arguments and outputs are stored as SHA-256 digests only — never raw content.

MCP tools exposed (v0.10.1+):
- `treeship_session_status`
- `treeship_session_event`
- `treeship_attest_action`
- `treeship_verify`
- `treeship_session_report`

## Approval-Gated Workflow (CLI)

```bash
# 1. Create approval
approval=$(treeship attest approval \
  --approver human://alice \
  --description "deploy v2.1" \
  --expires 2026-12-31T00:00:00Z \
  --format json | jq -r .approval_nonce)

# 2. Use approval nonce in action
treeship attest action \
  --actor agent://deployer \
  --action deploy.production \
  --approval-nonce "$approval"

# 3. Verify full chain (checks nonce binding)
treeship verify last
```

## Hub API

Base URL: `https://api.treeship.dev/v1/`

Auth: DPoP (no API keys or session tokens). Set up via `treeship hub attach`.

| Endpoint | Description |
|----------|-------------|
| `POST /v1/artifacts` | Push artifact (auth required) |
| `GET /v1/artifacts/:id` | Fetch artifact (public) |
| `GET /v1/verify/:id` | Verify artifact (public) |
| `GET /v1/workspace` | List your artifacts (auth required) |
| `POST /v1/merkle/checkpoint` | Store Merkle checkpoint |
| `GET /v1/merkle/proof/:artifact_id` | Fetch inclusion proof |

Public verify URL: `https://treeship.dev/verify/{artifact_id}`

## Statement Types

| Type | Purpose |
|------|---------|
| `treeship/action/v1` | Agent did something |
| `treeship/approval/v1` | Human approved something |
| `treeship/handoff/v1` | Work transferred between agents |
| `treeship/decision/v1` | LLM made a decision |
| `treeship/receipt/v1` | Session sealed receipt |
| `treeship/bundle/v1` | Bundled artifact package |

## Cryptographic Invariants (read-only reference)

These never change. Do not suggest modifications to them.

- **Signature algorithm:** Ed25519 (RFC 8032)
- **Envelope format:** DSSE (Sigstore/in-toto compatible)
- **Canonicalization:** RFC 8785 JSON Canonicalization Scheme
- **Content addressing:** SHA-256
- **PAE format:** `"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload`
- **Artifact ID:** `"art_" + hex(sha256(PAE_bytes)[..16])`
- Statement structs do NOT contain an `id` field — IDs live on records/sign results only.
- Approval nonce binding: `action.approvalNonce == approval.nonce` enforced at verify time.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `TREESHIP_ACTOR` | Default actor URI (e.g. `agent://my-agent`) |
| `TREESHIP_DISABLE` | Set to `1` to disable receipt capture |
| `TREESHIP_DEBUG` | Set to `1` for verbose output |
| `TREESHIP_APPROVAL_NONCE` | Pass approval nonce without flag |
| `TREESHIP_PARENT` | Default parent artifact ID |

## Key Local Paths

| Path | Contents |
|------|---------|
| `~/.treeship/config.json` | Global config, keypair references |
| `~/.treeship/sessions/` | Local session receipts |
| `.treeship/` | Project-local ship (when `treeship init` run in project) |

## Resources

- Website: https://treeship.dev
- Docs: https://docs.treeship.dev
- GitHub: https://github.com/zerkerlabs/treeship
- Hub: https://treeship.dev/verify/
- npm: `treeship`, `@treeship/sdk`, `@treeship/mcp`, `@treeship/verify`, `@treeship/core-wasm`
- PyPI: `treeship-sdk`
- crates.io: `treeship-core`, `treeship-cli`, `treeship-core-wasm`
