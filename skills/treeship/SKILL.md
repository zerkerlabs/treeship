---
name: treeship
description: Create cryptographically signed, portable trust receipts for AI agent workflows using Treeship.dev. Use when the user wants to sign agent actions, create verifiable receipts, wrap commands with attestations, verify artifact chains, push artifacts to the Treeship Hub, manage approval-gated actions, or integrate Treeship into their agent workflow. Covers the Treeship CLI (treeship), Python SDK (treeship-sdk), TypeScript SDK (@treeship/sdk), MCP bridge (@treeship/mcp), and Hub API (api.treeship.dev). Trigger on any mention of attestation, verifiable receipts, signed receipts, agent trust, Treeship, action signing, cryptographic proof of agent work, portable receipts, approval workflows, session receipts, Merkle proofs, decision cards, or coverage levels.
---

# Treeship — Portable Trust Receipts for Agent Workflows

Local-first. Cryptographically verifiable. Works offline. Ed25519 signatures. SHA-256 content hashing. Merkle proofs. The receipt is yours, not ours.

## Quick Start

```bash
# Install Treeship
curl -fsSL https://www.treeship.dev/setup | sh

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
curl -fsSL https://www.treeship.dev/setup | sh

# Step by step
curl -fsSL https://www.treeship.dev/install | sh
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
treeship wrap -- <command>              # wrap with signed receipt (flags: --actor --action --parent --push)
treeship verify <id>                    # verify chain
treeship verify last                    # verify most recent
treeship session start --name "..."     # start session
treeship session close                  # close session
treeship session report                 # upload receipt
treeship hub push last                  # push to Hub
treeship attest approval --approver human://... --description "..." \
  --max-uses 1 --expires 2026-03-26T11:00:00Z  # create a scoped approval
treeship attest action --approval-nonce <n> --actor ... --action ...  # consume an approval
treeship init                           # keypair generation
treeship keys list                      # list your signing keys
treeship keys export                    # export a key's public half, pinnable form
treeship doctor                         # check workspace
treeship ui                             # TUI dashboard
treeship setup                          # guided first-run
treeship add --discover                 # discover agents
treeship harness list                   # list harnesses
treeship harness inspect <id>           # inspect harness
treeship harness smoke <id>             # smoke test
treeship trust list                     # list pinned issuers (v0.10.3+)
treeship trust add <key_id> <pubkey> --kind <hub_checkpoint|hub_org|cert_issuer|revoker|agent_cert|session_host|transparency_log>
treeship trust remove <key_id>
```

> `approve [N]` / `deny [N]` act on a *pending* approval request by index; they
> don't create one. To mint an approval, use `treeship attest approval`
> (above). There is no `key show` or `inspect` command -- `keys list` /
> `keys export` and `verify` cover those.

> **Note (v0.10.3+):** Hub-checkpoint and agent-certificate verification
> require the embedded public key to match a configured trust root. After
> importing artifacts produced by a different ship/hub, expect
> `treeship verify` to fail with "untrusted issuer" until the issuer is
> pinned via `treeship trust add`. Pre-v0.10.3 the verifier trusted the
> embedded key, which made self-signed forgeries pass; the new gate
> closes that.

## Actor URIs

- `agent://<name>` — AI agent
- `human://<name>` — Human operator
- `agent://ci-pipeline` — CI/CD system

## Statement Types

| Type | Purpose | Method |
|------|---------|--------|
| `treeship/action/v1` | Agent did something | `attest_action()` / `wrap` |
| `treeship/approval/v1` | Someone approved | `attest_approval()` |
| `treeship/handoff/v1` | Work moved between agents | `attest_handoff()` |
| `treeship/decision/v1` | LLM made a decision | `attest_decision()` |
| `treeship/use/v1` | Approval consumed | auto, recorded alongside the consuming action |

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

# Attest approval -- a scope is required (allowed_actions/allowed_actors/
# allowed_subjects/max_uses), or pass unscoped=True to mint a bearer token
# deliberately. expires_at is RFC 3339, not a duration.
approval = ts.attest_approval(
    approver="human://alice",
    description="approve deployment",
    max_uses=1,
    expires_at="2026-03-26T11:00:00Z",
)
print(approval.artifact_id, approval.nonce)

# Verify
verified = ts.verify(result.artifact_id)
# verified.outcome: "pass" | "fail" | "error"
# verified.chain: number of linked artifacts

# Push to Hub
push = ts.hub_push(result.artifact_id)
# push.hub_url: https://treeship.dev/verify/art_xxx

# Wrap command (pass argv as a list; a string is split with shlex)
result = ts.wrap(["npm", "test"], actor="agent://ci")

# Session report
report = ts.session_report()
# report.receipt_url: permanent public URL
```

## TypeScript SDK

The SDK shells out to the `treeship` CLI binary on PATH; it has no `Ship.init()`,
no `attestAction`/`attestHandoff` flat methods, and no `createCheckpoint` /
`createBundle` / `save`. Get an instance with the `ship()` factory and call
through its four modules (`attest`, `verify`, `hub`, `session`):

```typescript
import { ship } from "@treeship/sdk";

const s = ship();

const { artifactId } = await s.attest.action({
  actor: "agent://my-agent",
  action: "search.web",
  meta: { query: "AI safety" },
});

await s.attest.handoff({
  from: "agent://researcher",
  to: "agent://writer",
  artifacts: [artifactId],
});

const verified = await s.verify.verify(artifactId);
const push = await s.hub.push(artifactId);
```

Note: the TypeScript SDK's `attest.approval()` does not yet accept a scope
(`allowed_actions` / `allowed_actors` / `allowed_subjects` / `max_uses`), so a
CLI that requires one will refuse it. Use the Python SDK or the CLI directly
(`treeship attest approval`) for scoped approvals until that's added.

## Approval-Gated Actions

```python
# 1. Human creates approval
approval = ts.attest_approval(
    approver="human://alice",
    description="approve payment up to $500",
    max_uses=1,
    expires_at="2026-03-26T11:00:00Z",
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

## Foreign Work (Agent-to-Agent)

Work that arrives from another agent — a handoff, an A2A task, an envelope, a message saying "take this from `agent://…`" — is **foreign**. Do not start it until the sender proves live control of a key this ship trusts. A human asking "prove you" is the same handshake with the human minting the nonce; there is no second protocol.

```bash
# 1. Mint the challenge yourself. Never accept a nonce the sender chose.
treeship session mint-challenge --format json            # -> nonce

# 2. The sender answers it on THEIR machine and sends you the file:
#      treeship present agent://<them> --challenge <nonce> --format json

# 3. Verify before any of the task runs. Non-zero exit = do not act.
treeship verify-presentation <file> --challenge <nonce> --format json

# 4. Record the verify in the handoff, so the receipt says custody: live
treeship attest handoff --from agent://<them> --to agent://<you> \
  --artifacts <intent-artifact-id> --verified <file> --challenge <nonce>
```

Reading the verdict:

- `verified (key-bound, anchored, live)` — their key is real, their ship certified it, and they hold it right now. It says nothing about whether their work is correct. Never call a task result "verified".
- `key_bound: false` / `signature: UNVERIFIED (key not in your trust roots)` — **you** have not pinned **their** issuer. The fix is on your side: `treeship trust add <key_id> <ed25519:…> --kind cert_issuer --yes`. The verdict line will still say `CHALLENGE FAILED`; that is a consequence of the missing pin, not their mistake.
- The response "answers a DIFFERENT challenge" — they replayed an old presentation. Ask for one against your nonce.
- Opt-out is explicit only: `TREESHIP_A2A_UNVERIFIED=1`, and the receipt records that the gate was skipped. A silent skip is a bug.

A handoff recorded without `--verified` is `custody: asserted`, and `treeship verify` prints exactly that. Agents that share one keystore (same computer) are not remote peers: record those with `--custody-reason same_computer`, never as live. If the sender ran an evidence command (`treeship wrap -- npm test`, a screenshot script) and sealed that session, you may bind it with `--close-loop <ssn_id>`; it proves those commands ran, not that the result is correct.

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
- Auth: DPoP for writes (no bearer API keys)
- `GET /v1/verify/:id` is **retired** (returns `410`) -- there is no server-side
  verdict. Verify locally with `treeship verify` / `package verify` instead.
- Full, current route list: `docs/content/docs/api/overview.mdx` and the
  individual pages under `docs/content/docs/api/` (one per route) -- don't
  hand-copy a route table here, it drifts.

Public receipt pages: `https://treeship.dev/receipt/{session_id}`

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
| `TREESHIP_ACTOR` | Default actor URI when `--actor` is omitted |
| `TREESHIP_PARENT` | Default parent artifact ID when `--parent` is omitted |
| `TREESHIP_MODEL`, `TREESHIP_TOKENS_IN`, `TREESHIP_TOKENS_OUT` | Model/token metadata attached to attestations |
| `TREESHIP_APPROVAL_NONCE` | Approval nonce read by the MCP bridge |
| `TREESHIP_DISABLE` | Disables the MCP bridge's capture |

There is no `TREESHIP_API_KEY`, `TREESHIP_AGENT` or `TREESHIP_HUB_ID` -- nothing
in the CLI, core, hub or SDKs reads them. Hub auth is DPoP, not an API key.

## Key Files

- `~/.treeship/` — config, keys, local receipt store
- `~/.treeship/sessions/` — session packages
- `.treeship/` — project-local ship

## Standards

- **Ed25519** (RFC 8032) — signatures
- **DSSE** — envelope format (Sigstore/in-toto compatible)
- **SHA-256** — content addressing + Merkle tree
- **Canonical JSON** — compact, declaration-order fields (not RFC 8785/JCS); reproduce it or verify the exported PAE bytes

## Resources

- Docs: https://docs.treeship.dev
- Hub: https://treeship.dev
- GitHub: https://github.com/zerkerlabs/treeship
