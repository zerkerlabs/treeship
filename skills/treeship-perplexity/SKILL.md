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
| `packages/hub/` | Go Hub server (see `packages/hub/main.go` for the current route list) |
| `packages/sdk-ts/` | TypeScript SDK (`@treeship/sdk`) |
| `packages/sdk-python/` | Python SDK (`treeship-sdk`) |
| `bridges/mcp/` | MCP bridge (`@treeship/mcp`) |
| `docs/` | Fumadocs documentation site |
| `skills/` | Agent skills (including this one) |
| `integrations/claude-code-plugin/` | Claude Code plugin |

## Installation

```bash
# One-liner: installs CLI, runs treeship init, then asks before instrumenting
# detected agents (no tty: skipped unless TREESHIP_SETUP_YES=1)
curl -fsSL https://www.treeship.dev/setup | sh

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
treeship wrap -- <command>                      # flags: --actor --action --parent --push
treeship attest action --actor agent://name --action tool.call
treeship attest approval --approver human://alice --description "..." \
  --max-uses 1 --expires 2026-12-31T00:00:00Z   # a scope (--max-uses/--allowed-*) is required, or pass --unscoped
treeship attest handoff --from agent://a --to agent://b --artifacts art_a1b2

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

# Inspection -- there is no separate "inspect" command; `verify` doubles as
# the artifact inspector, and `log` reads the local timeline
treeship log [--tail N] [--follow]
treeship status                 # ship state: keys, recent artifacts, hub status
treeship doctor

# Keys -- there is no "key show"; use "keys" (plural)
treeship keys list
treeship keys export [--agent <uri>] [--key <key_id>]

# Trust roots (v0.10.3+)
treeship trust list
treeship trust add <key_id> <pubkey> --kind <hub_checkpoint|hub_org|cert_issuer|revoker|agent_cert|session_host|transparency_log>
treeship trust remove <key_id>

# Merkle (both hidden from --help but present)
treeship checkpoint
treeship merkle proof <artifact-id> > proof.json
treeship merkle verify proof.json       # takes a proof file, not an artifact id

# Setup
treeship setup
treeship add --all           # instrument detected agents
treeship add --discover

# UI
treeship ui                  # Ratatui interactive TUI dashboard
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

# Create approval (human-in-the-loop) -- a scope is required
# (allowed_actions/allowed_actors/allowed_subjects/max_uses), or pass
# unscoped=True; expires_at is RFC 3339, not a duration
approval = ts.attest_approval(
    approver="human://alice",
    description="approve deployment",
    max_uses=1,
    expires_at="2026-12-31T00:00:00Z",
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

# Push to Hub -- the method is hub_push, not dock_push
push = ts.hub_push(result.artifact_id)
print(push.hub_url)   # https://treeship.dev/verify/art_xxx

# Wrap a shell command (pass argv as a list; a string is split with shlex)
result = ts.wrap(["npm", "test"], actor="agent://ci")

# Session report (permanent shareable URL)
report = ts.session_report()
print(report.receipt_url)
```

## TypeScript SDK

The SDK shells out to the `treeship` CLI on PATH. There is no `Ship.init()`,
no flat `attestAction`/`attestHandoff` methods, and no `createCheckpoint` /
`createBundle` / `save`. Get an instance with `ship()` and call through its
four modules (`attest`, `verify`, `hub`, `session`):

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

The TS SDK's `attest.approval()` doesn't yet accept a scope
(`allowed_actions`/`allowed_actors`/`allowed_subjects`/`max_uses`); use the
Python SDK or `treeship attest approval` directly for scoped approvals.

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

MCP tools exposed (9 total, `bridges/mcp/src/server.ts`):
- `treeship_session_status`
- `treeship_session_event`
- `treeship_session_report`
- `treeship_attest_action`
- `treeship_attest_handoff`
- `treeship_verify`
- `treeship_mint_challenge`
- `treeship_present`
- `treeship_verify_presentation`

`TREESHIP_STRICT=1` makes a signing failure or an active `treeship halt`
fail the underlying tool call instead of letting it proceed with a note
(the default is fail-open).

## Approval-Gated Workflow (CLI)

```bash
# 1. Create approval -- a scope is required (--max-uses / --allowed-*), or pass --unscoped
approval=$(treeship attest approval \
  --approver human://alice \
  --description "deploy v2.1" \
  --max-uses 1 \
  --expires 2026-12-31T00:00:00Z \
  --format json | jq -r .nonce)

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

`GET /v1/verify/:id` is **retired** and returns `410` -- there is no
server-side verdict; the hub is transport only, and callers verify against
their own pinned roots (`treeship verify`, `package verify`). For the current
route list, read `docs/content/docs/api/overview.mdx` and the per-route pages
under `docs/content/docs/api/`, or `packages/hub/main.go` directly -- don't
hand-copy a route table here, it drifts.

Public receipt pages: `https://treeship.dev/receipt/{session_id}` (from
`session report`). Public artifact push URLs: `https://treeship.dev/verify/{artifact_id}`
(from `hub push`).

## Statement Types

These are `statement.type` values (a separate string from the DSSE
`payloadType`, which is `application/vnd.treeship.<suffix>.v1+json`):

| Type | Purpose |
|------|---------|
| `treeship/action/v1` | Agent did something |
| `treeship/approval/v1` | Human approved something |
| `treeship/handoff/v1` | Work transferred between agents |
| `treeship/decision/v1` | LLM made a decision |
| `treeship/endorsement/v1` | An actor vouches for another artifact |
| `treeship/receipt/v1` | External system receipt (webhook, confirmation) |
| `treeship/bundle/v1` | Bundled artifact package |
| `session.v1`, `judgement.v1`, `judgement.resolution.v1` | Registered predicates carried inside a receipt/action payload, not top-level statement types |

## Cryptographic Invariants (read-only reference)

These never change. Do not suggest modifications to them.

- **Signature algorithm:** Ed25519 (RFC 8032)
- **Envelope format:** DSSE (Sigstore/in-toto compatible)
- **Canonicalization:** compact JSON with fields in declaration order (not RFC 8785/JCS)
- **Content addressing:** SHA-256
- **PAE format:** `"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload`
- **Artifact ID:** `"art_" + hex(sha256(PAE_bytes)[..16])`
- Statement structs do NOT contain an `id` field — IDs live on records/sign results only.
- Approval nonce binding: `action.approvalNonce == approval.nonce` enforced at verify time.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `TREESHIP_ACTOR` | Default actor URI (e.g. `agent://my-agent`) |
| `TREESHIP_DISABLE` | Set to `1` to disable the MCP bridge's capture |
| `TREESHIP_STRICT` | Set to `1` to fail the tool call (instead of proceeding with a note) on a signing failure or an active `treeship halt` |
| `TREESHIP_APPROVAL_NONCE` | Pass approval nonce without flag |
| `TREESHIP_PARENT` | Default parent artifact ID |
| `TREESHIP_A2A_UNVERIFIED` | Set to `1` to skip the agent-to-agent liveness gate (recorded on the receipt) |

There is no `TREESHIP_DEBUG` -- nothing in the CLI or the MCP bridge reads it.

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
- crates.io: `treeship-core`, `rig-treeship` -- `treeship-cli` is fully yanked (`cargo install treeship-cli` fails); there is no `treeship-core-wasm` crate
