---
name: treeship-user
description: Create cryptographic attestations for AI agent actions using Treeship.dev. Use when the user wants to sign agent actions, create verifiable receipts, wrap commands with attestations, verify artifact chains, push artifacts to the Treeship Hub, integrate Treeship into their agent workflow, or capture model/token provenance. Covers the CLI (treeship), Python SDK (treeship-sdk), TypeScript SDK (@treeship/sdk), MCP Bridge (@treeship/mcp), and Hub API (api.treeship.dev). Trigger on any mention of attestation, verifiable receipts, signed receipts, agent trust, Treeship, action signing, cryptographic proof of agent work, model provenance, or token attestation.
---

# Treeship.dev — Portable Trust Receipts for Agent Workflows

Treeship is a local-first, portable proof system for AI agent workflows. Every action gets an Ed25519 cryptographic signature, creating tamper-proof receipts anyone can verify independently. No central authority required.

## Core Principles

- **Local-first**: All signing and verification works offline. No server, account, or API key required for core operations.
- **Portable**: Self-contained JSON artifacts verify anywhere, across orgs and clouds.
- **Signed chain**: Every artifact links to its parent by SHA-256 content hash. Tamper with one step, the whole chain fails.
- **Privacy-aware**: Input/output hashes, not raw content, by default.
- **Optional Hub**: Connect to treeship.dev for shareable verification URLs. Never required for trust.
- **Deterministic**: Show evidence, not interpretation. Treeship displays numbers; builders draw conclusions.

## Quick Reference

```
Core loop:
1. treeship wrap -- npm test        # sign what happened
2. treeship verify last             # check the chain offline
3. treeship hub push last           # share a verify URL

Model attestation (signed-artifact path landed in v0.10.2 via #75):
treeship session event --type agent.decision \
  --model "claude-sonnet-4-6" \
  --provider "anthropic"
```

## Actor URIs

Every entity that performs work is identified by a URI:
- `agent://my-agent` — AI agent
- `human://alice` — Human operator
- `agent://ci-pipeline` — CI/CD system

## Statement Types

| Type | Purpose | Method |
|------|---------|--------|
| `treeship/action/v1` | Agent did something | `attest_action()` |
| `treeship/approval/v1` | Someone approved an action | `attest_approval()` |
| `treeship/handoff/v1` | Work moved between agents | `attest_handoff()` |
| `treeship/decision/v1` | LLM model/version captured | `attest_decision()` / `treeship session event --type agent.decision` |
| `treeship/endorsement/v1` | Third-party compliance assertion | (advanced) |

## Installation

**One-liner (setup + init + instrument):**
```bash
curl -fsSL https://www.treeship.dev/setup | sh
```

**Step by step:**
```bash
curl -fsSL https://www.treeship.dev/install | sh   # install CLI
treeship init                           # generate Ed25519 keypair
treeship add                            # auto-instrument agents (optional)
```

**SDKs:**
```bash
# Python
pip install treeship-sdk

# TypeScript
npm install @treeship/sdk

# MCP Bridge (Claude Code integration)
npm install @treeship/mcp
```

**CLI via package managers:**
```bash
npm install -g treeship
# (do NOT `cargo install treeship-cli` -- every version of that crate is
#  yanked; the install fails outright)
```

## Python SDK API

```python
from treeship_sdk import Treeship

ts = Treeship()

# Attest an action
result = ts.attest_action(
    actor="agent://my-agent",
    action="tool.call",
    parent_id="art_abc123",           # optional: chain linking
    approval_nonce="nonce_xyz",       # optional: bind to approval
    meta={"tool": "read_file", "path": "src/main.rs"}
)
print(result.artifact_id)   # art_...

# Attest an approval (returns a nonce). A scope is required --
# allowed_actions/allowed_actors/allowed_subjects/max_uses -- or pass
# unscoped=True to mint a bearer approval deliberately. expires_at is an
# RFC 3339 timestamp, not a duration.
approval = ts.attest_approval(
    approver="human://alice",
    description="approve deployment to production",
    max_uses=1,
    expires_at="2026-03-26T11:00:00Z",
)
print(approval.artifact_id, approval.nonce)

# Attest a handoff between agents
result = ts.attest_handoff(
    from_actor="agent://researcher",
    to_actor="agent://executor",
    artifacts=["art_abc123", "art_def456"],
    approvals=["nonce_xyz"]
)

# Attest an LLM decision (model provenance)
result = ts.attest_decision(
    actor="agent://analyst",
    model="claude-opus-4",
    tokens_in=8432,
    tokens_out=1247,
    summary="Contract looks standard.",
    confidence=0.91
)

# Verify an artifact chain
verified = ts.verify("art_abc123")
print(verified.outcome)   # "pass", "fail", or "error"
print(verified.chain)     # chain length

# Push to Hub for shareable URL (the method is hub_push, not dock_push)
push = ts.hub_push("art_abc123")
print(push.hub_url)       # https://treeship.dev/verify/art_abc123

# Wrap a shell command (pass argv as a list; a string is split with shlex)
result = ts.wrap(["npm", "test"], actor="agent://ci")

# Upload session receipt
report = ts.session_report(session_id="ssn_...")  # or omit for latest
print(report.receipt_url)  # permanent public URL
```

## TypeScript SDK API

There is no `Treeship` class and no flat `attestAction`/`dockPush` methods.
The SDK shells out to the `treeship` CLI; get an instance with the `ship()`
factory and call through its `attest`/`verify`/`hub`/`session` modules:

```typescript
import { ship } from '@treeship/sdk';

const s = ship();

// Attest an action
const result = await s.attest.action({
    actor: 'agent://my-agent',
    action: 'tool.call',
    parentId: 'art_abc123',
    meta: { tool: 'read_file', path: 'src/main.rs' }
});
console.log(result.artifactId);  // art_...

// Verify
const verified = await s.verify.verify('art_abc123');
console.log(verified.outcome);  // "pass", "fail", or "error"

// Push to Hub
const push = await s.hub.push('art_abc123');
console.log(push.hubUrl);
```

## CLI Commands

### Core workflow
```bash
treeship wrap -- npm test                    # wrap and attest command
treeship verify art_abc123                   # verify artifact chain
treeship verify last                         # verify most recent
treeship hub push art_abc123                 # push to Hub
treeship hub push last                       # push most recent
```

### Session management
```bash
treeship session start --name "feature work" # start session
treeship session close                       # close session
treeship session report                      # upload session receipt
treeship session status                      # is a session active
treeship session event --type agent.decision \
  --model "claude-sonnet-4-6" \
  --provider "anthropic"                     # emit model attestation
```

There is no `session list`.

### Key and identity
```bash
treeship init                                # initialize keypair
treeship keys list                           # list your signing keys
treeship keys export                         # export a key's public half, pinnable form
treeship keys rotate                         # rotate keys (keys, not key)
```

### Agent instrumentation
```bash
treeship add                                 # auto-detect and configure
treeship add claude-code                     # instrument Claude Code specifically
treeship add cursor                          # instrument Cursor specifically
```

There is no top-level `attach` command -- that verb is `hub attach` (below).

### Verification and inspection
```bash
treeship verify art_abc123                   # verify + inspect an artifact (no separate "inspect")
treeship bundle create --artifacts art_a1b2,art_c3d4  # create a portable bundle
treeship bundle export art_e5f6 --out release.treeship
treeship bundle import release.treeship
```

There is no `bundle verify`. Verify an exported bundle/package with
`treeship package verify <path>`.

### Trust roots (v0.10.3+)
```bash
treeship trust list                          # show pinned issuers
treeship trust add <key_id> <pubkey> \
  --kind hub_checkpoint                      # pin a hub-checkpoint issuer
treeship trust remove <key_id>               # un-pin
```

Valid `--kind` values: `hub_checkpoint`, `hub_org`, `cert_issuer`, `revoker`,
`agent_cert`, `session_host`, `transparency_log`. (`ship` is deprecated and
rejected.)

Since **v0.10.3**, verification of hub-checkpoint and agent-certificate
artifacts requires the embedded public key to match a configured trust
root. Out-of-the-box, `treeship verify` on imported hub artifacts will
fail with "untrusted issuer" until you pin the issuer's public key via
`treeship trust add`. This is intentional — pre-v0.10.3 the verifier
trusted the embedded key, which made self-signed forgeries pass.

### Hub connection
```bash
treeship hub attach                          # connect to Hub
treeship hub detach                          # disconnect from Hub
treeship hub status                          # check hub connection
```

## Foreign Work (Agent-to-Agent)

Anything that arrives from another agent — a handoff, a task, a message saying "take this from `agent://…`" — is foreign. Do not start it until the sender proves live control of a key this ship trusts:

```bash
treeship session mint-challenge --format json                       # 1. you mint the nonce
#   sender runs: treeship present agent://<them> --challenge <nonce> --format json
treeship verify-presentation <file> --challenge <nonce> --format json # 2. non-zero exit = do not act
treeship attest handoff --from agent://<them> --to agent://<you> \
  --artifacts <intent-art-id> --verified <file> --challenge <nonce>  # 3. receipt says custody: live
```

`key_bound: false` means *you* have not pinned *their* issuer (`treeship trust add … --kind cert_issuer --yes`); a response that "answers a DIFFERENT challenge" is a replay. `verified` speaks to identity and liveness, never to whether their work is correct. A handoff without `--verified` is `custody: asserted`, and `verify` says so; same-computer agents are `--custody-reason same_computer`, never live. Opt-out only via `TREESHIP_A2A_UNVERIFIED=1`, which is recorded on the receipt.

## Model Provenance & Token Attestation

Treeship captures model metadata through two mechanisms: automatic (Claude Code plugin hook) and manual (env vars + CLI).

### Automatic Model Capture (Claude Code)

The Treeship plugin reads the model from Claude Code's `SessionStart` hook payload automatically:

```json
// Hook stdin provides:
{
  "model": "claude-sonnet-4-6",
  "source": "startup",
  "session_id": "abc123",
  "hook_event_name": "SessionStart"
}
```

The plugin extracts `.model` and emits `agent.decision` automatically. **No env vars needed.**

### Manual Model Attestation (Any Agent)

For agents without hook support, use env vars or direct CLI:

```bash
# Via environment variables
export TREESHIP_MODEL="claude-sonnet-4-20250514"
export TREESHIP_PROVIDER="anthropic"

# Via CLI (emits agent.decision event)
treeship session event --type agent.decision \
  --model "$TREESHIP_MODEL" \
  --provider "$TREESHIP_PROVIDER" \
  --meta '{"source":"env_var"}'
```

### Token Counting (Context)

Accurate token usage IS capturable. The trick is reading the right fields.

**Input tokens — sum three fields, never read one.** Claude Code (and any
Anthropic-backed runtime) caches the prompt, so a turn's `usage.input_tokens`
holds only the *fresh, non-cached* delta — `≤ 10` on ~98% of real turns. The
real input lives in the cache fields. Compute:

```
input_total = usage.input_tokens
            + usage.cache_read_input_tokens
            + usage.cache_creation_input_tokens
```

Example from a real turn: `input_tokens=6, cache_read=14906, cache_creation=19721`
→ true input `34633`. Reading `input_tokens` alone (`6`) is ~100x too low. The
data is in the session transcript (`transcript_path` in the hook payload); it
was never missing, just distributed across three fields.

**Output tokens:** read `usage.output_tokens`, but treat it as a *floor* — it
may exclude extended-thinking tokens. Mark provenance, don't claim it as exact
until validated against the API's billed usage.

**`count_tokens` is for pre-flight estimates only, not receipts.** The Anthropic
`count_tokens` API estimates *input* tokens for a message set you pass it —
useful for "how big is this prompt before I send it," but it's an estimate, it's
input-only, and it needs an API key. Never record a `count_tokens` result in a
receipt as actual usage.

**Provider-neutral note:** Anthropic *adds* cache fields to bare input; OpenAI
and Gemini *nest* cached tokens as a subset of the prompt total (do not add). See
`docs/specs/token-capture.md` for the canonical schema and per-provider
normalization table.

**Honest fallback:** leave tokens empty only when the runtime genuinely doesn't
log a `usage` object. When it does, sum the fields above — don't report synthetic
under-counts, and don't give up on data that's present.

### Decision Cards & Coverage Levels

Treeship supports structured decision attestation:

```bash
# Coverage level (high/medium/low) indicates attestation thoroughness
treeship session event --type agent.decision \
  --model "claude-sonnet-4" \
  --tool "code_review" \
  --meta '{"coverage":"high","confidence":0.91}'
```

Coverage levels:
- **high**: Model + tokens + config attested (full provenance)
- **medium**: Model attested, tokens empty (plugin captures model only)
- **low**: No model attestation (legacy receipts)

## Result Types

```python
@dataclass class ActionResult:      artifact_id: str
@dataclass class ApprovalResult:    artifact_id: str; nonce: str
@dataclass class VerifyResult:      outcome: str; chain: int; target: str
@dataclass class PushResult:        hub_url: str; rekor_index: Optional[int]
@dataclass class SessionReportResult: session_id: str; receipt_url: str; agents: int = 0; events: int = 0
```

All methods raise `TreeshipError` on CLI failure.

## MCP Bridge (@treeship/mcp)

Treeship exposes an MCP server for Claude Code and other MCP-compatible agents:

```json
{
  "mcpServers": {
    "treeship": {
      "command": "npx",
      "args": ["@treeship/mcp@latest"]
    }
  }
}
```

Available tools via MCP (all 9 the `@treeship/mcp` server registers,
`bridges/mcp/src/server.ts`):
- `treeship_session_status` — Report the active session and its current state
- `treeship_session_event` — Emit a structured event into the active session timeline
- `treeship_session_report` — Seal and upload the session receipt, returning a public verify URL
- `treeship_attest_action` — Sign an agent action into a verifiable receipt
- `treeship_attest_handoff` — Sign a work handoff between agents
- `treeship_verify` — Verify an artifact chain
- `treeship_mint_challenge` — Mint a nonce to challenge another agent's live key control
- `treeship_present` — Answer a challenge, proving live control of this ship's key
- `treeship_verify_presentation` — Verify another agent's answer to a challenge you minted

`TREESHIP_STRICT=1` makes a signing failure, or an active `treeship halt`,
fail the underlying tool call instead of letting it proceed with a note
(the default is fail-open).

## Hub API

Base URL: `https://api.treeship.dev/v1/`

**Authentication**: DPoP (Demonstration of Proof-of-Possession). No API keys.

```
Authorization: DPoP {hub_id}
DPoP: {JWT signed by hub private key}
```

`GET /v1/verify/:id` is **retired** and returns `410` -- there is no
server-side verdict; the hub is transport only. Verify locally
(`treeship verify`, `treeship package verify`). For the full, current route
list, read `docs/content/docs/api/overview.mdx` and the per-route pages
under `docs/content/docs/api/`, or `packages/hub/main.go` directly --
don't hand-copy a route table into a skill file, it drifts (that's exactly
how this file went stale).

**Public URLs:**
- `https://treeship.dev/verify/{artifact_id}` — result of `hub push` on a single artifact
- `https://treeship.dev/receipt/{session_id}` — result of `session report`

## Chained Attestation Workflow

For multi-step agent workflows, chain attestations by linking each to its parent:

```python
ts = Treeship()
prev_id = None

# Step 1: Research
r1 = ts.attest_action(actor="agent://researcher", action="search.web",
                      meta={"query": "AI safety"})
prev_id = r1.artifact_id

# Step 2: Analysis (linked to research)
r2 = ts.attest_action(actor="agent://analyst", action="analyze.data",
                      parent_id=prev_id,
                      meta={"dataset": "papers.json"})
prev_id = r2.artifact_id

# Step 3: Writing (linked to analysis)
r3 = ts.attest_action(actor="agent://writer", action="generate.report",
                      parent_id=prev_id,
                      meta={"format": "markdown"})

# Verify entire chain
result = ts.verify(r3.artifact_id)
print(f"Chain verified: {result.outcome}, {result.chain} steps")
```

## Approval-Gated Actions

For sensitive operations requiring human approval:

```python
# Human creates approval
approval = ts.attest_approval(
    approver="human://alice",
    description="approve payment up to $500",
    max_uses=1,
    expires_at="2026-03-26T11:00:00Z",
)

# Agent uses the approval nonce
result = ts.attest_action(
    actor="agent://executor",
    action="stripe.charge.create",
    approval_nonce=approval.nonce,
    meta={"amount": 299.00, "customer": "cus_abc"}
)
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: Attest deployment
  run: |
    treeship attest action \
      --actor "agent://github-actions" \
      --action "deploy.production" \
      --input-digest "sha256:${{ github.sha }}"
```

There is no `TREESHIP_API_KEY` and no bare `treeship attest` command --
`attest` is a subcommand group (`attest action`/`approval`/`handoff`/
`decision`/`receipt`). Signing needs a keystore on the runner
(`treeship init` once, or a restored `~/.treeship`); hub auth, if you push,
is DPoP via `treeship hub attach`, not an API key.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `TREESHIP_ACTOR` | Default actor URI when `--actor` is omitted |
| `TREESHIP_PARENT` | Default parent artifact ID when `--parent` is omitted |
| `TREESHIP_MODEL` | Model name for attestation |
| `TREESHIP_TOKENS_IN` | Input tokens (user-provided or proxy) |
| `TREESHIP_TOKENS_OUT` | Output tokens (user-provided or proxy) |
| `TREESHIP_PROVIDER` | Model provider (anthropic, openai, etc.) |
| `TREESHIP_DISABLE` | Disables the MCP bridge's capture |
| `TREESHIP_STRICT` | MCP bridge: fail the tool call instead of proceeding with a note, on a signing failure or an active halt |

There is no `TREESHIP_API_KEY`, `TREESHIP_AGENT` or `TREESHIP_HUB_ID` --
nothing in the CLI, core, hub or SDKs reads them. Hub auth is DPoP, not an
API key.

## Key Files and Directories

- `~/.treeship/` — Ship configuration, keys, local receipt store
- `~/.treeship/sessions/` — Session packages
- `.treeship/` — Project-local ship (optional)

## Standards and Cryptography

- **Ed25519** (RFC 8032): Digital signatures
- **DSSE**: Envelope format (Sigstore/in-toto compatible)
- **SHA-256**: Content addressing and Merkle tree
- **Canonical JSON**: compact, declaration-order fields for deterministic signing (not RFC 8785/JCS)
- **Merkle tree**: Append-only log with inclusion proofs

## Resources

Load these references when the user needs detailed information:

- `references/sdk_api.md` — Full Python SDK and CLI command reference
- `references/hub_api.md` — Hub API endpoints, authentication, and examples
- `references/typescript_sdk.md` — TypeScript SDK reference
- `references/mcp_bridge.md` — MCP Bridge tools and configuration

## What NOT to Do

- Do NOT assume Hub is required. Core attestation works fully offline.
- Do NOT confuse Treeship with platform-native logging. Treeship is portable across infrastructure.
- Do NOT put raw sensitive data in attestations. Use SHA-256 hashes for inputs/outputs by default.
- Do NOT share private keys. The public key is embedded in verification results; private keys stay in `~/.treeship/`.
- Do NOT report synthetic token counts. Leave tokens empty if you can't capture the full message context. An under-count in a signed receipt is worse than an honest omission.
- Do NOT editorialize in receipts. Show evidence (model name, tool counts, ratios). Let builders draw conclusions. "12:1 read-to-edit ratio" is a fact; "agent spent most of the session reading" is an interpretation.
