---
name: treeship
description: Use when operating Hermes Agent in a repo or organization where AI work should produce Treeship-verifiable receipts. Captures Hermes sessions, MCP-routed tool calls, wrapped shell commands, approvals, handoffs, and publishable session reports while avoiding raw secrets in receipts.
version: 1.0.0
author: Treeship
license: MIT
metadata:
  hermes:
    tags: [treeship, receipts, provenance, hermes, mcp, agent-trust]
    related_skills: []
---

# Treeship for Hermes — Verifiable Agent Work

## Overview

Treeship creates local-first, cryptographically signed receipts for agent work. In Hermes, use Treeship to answer:

- Who asked for the work?
- Which Hermes actor did it?
- Which commands, MCP tool calls, files, approvals, and handoffs were involved?
- Can someone verify the receipt offline without trusting Treeship Hub?

Hermes currently integrates through **skill instructions + the universal Treeship MCP bridge**. There is no Hermes-native in-process hook yet, so be honest about coverage: MCP-routed tool calls can be captured automatically; built-in Hermes tool calls and direct shell work should be wrapped or summarized as explicit session events.

## Quick Start

```bash
# Install and initialize Treeship
curl -fsSL https://treeship.dev/install | sh
treeship init

# Register Hermes as a distinct agent identity.
# --own-key makes Hermes receipts verify as key-bound when the MCP path signs as agent://hermes.
treeship agent register --name hermes --own-key --tools mcp,terminal,file,git --description "Hermes Agent"

# Start a named session before important work
treeship session start --name "hermes: <task>"
```

If the workspace already has Treeship initialized, do not reinitialize or rotate keys unless the user asks.

## Hermes MCP Configuration

Add the Treeship MCP server to Hermes so MCP-routed tool calls create intent/result receipts and session events:

```bash
hermes mcp add treeship --command npx \
  --env TREESHIP_ACTOR=agent://hermes TREESHIP_HUB_ENDPOINT=https://api.treeship.dev \
  --args -y @treeship/mcp
```

Then ensure the server environment includes the Hermes actor:

```yaml
# ~/.hermes/config.yaml
mcp_servers:
  treeship:
    command: npx
    args: ["-y", "@treeship/mcp"]
    env:
      TREESHIP_ACTOR: "agent://hermes"
      TREESHIP_HUB_ENDPOINT: "https://api.treeship.dev"
```

`TREESHIP_ACTOR=agent://hermes` is required. Without it, receipts may fall back to a generic MCP actor and lose useful identity.

After changing Hermes MCP config, start a fresh Hermes session or run `/reload-mcp` if available.

## Operating Loop

1. **Start or inspect the session**
   ```bash
   treeship session status --format json || treeship session start --name "hermes: <task>"
   ```
   Completion criterion: there is an active session ID.

2. **Record intent for significant work**
   ```bash
   treeship session event \
     --type agent.decision \
     --actor agent://hermes \
     --agent-name hermes \
     --meta '{"decision":"approach chosen","reason":"brief non-secret reason"}'
   ```
   Completion criterion: the receipt timeline explains why the agent took meaningful actions.

3. **Wrap shell commands with side effects**
   ```bash
   treeship wrap --actor agent://hermes -- <command>
   ```
   Use wrapping for builds, tests, git operations, deploy commands, migrations, scripts, package publishing, or any command whose result should be auditable. Avoid putting secrets or bearer tokens in command-line args; prefer env vars or config files that Treeship does not print.
   Completion criterion: important command boundaries are signed or represented by a session event.

4. **Use approvals for sensitive actions**
   ```bash
   treeship approve --approver human://<slack-or-github-id> --description "Approve deploy to production"
   treeship wrap --approval-nonce <nonce> --actor agent://hermes -- <deploy-command>
   ```
   Completion criterion: the receipt links the sensitive action to a human approval artifact.

5. **Record handoffs and collaboration**
   ```bash
   treeship attest handoff \
     --from agent://hermes \
     --to agent://claude-code \
     --task "continue implementation" \
     --format json
   ```
   Completion criterion: multi-agent transitions are explicit rather than hidden in chat text.

6. **Close, verify, and publish when useful**
   ```bash
   treeship session close --summary "<non-secret summary>"
   treeship session report
   treeship verify last
   ```
   Completion criterion: local verification passes and, if published, the user gets a shareable receipt URL.

## What Treeship Should Capture

| Evidence | Preferred Hermes capture path | Notes |
|---|---|---|
| MCP tool call intent/result | `@treeship/mcp` | Automatic when tools route through MCP. |
| Shell command boundary | `treeship wrap -- ...` | Captures command boundary and exit status; avoid raw secrets in args. |
| File changes | MCP event when routed, otherwise git reconcile/session report | Do not paste file contents into metadata. |
| Human approval | `treeship approve` + `--approval-nonce` | Use stable human URIs such as `human://slack/T123/U456`. |
| Agent handoff | `treeship attest handoff` or `treeship session event` | Use `agent://hermes`, `agent://claude-code`, etc. |
| Model/provider/cost | Session metadata/event | Only include values the user is comfortable sharing. |
| Final deliverable | `treeship session report` | Produces a portable report and optional Hub URL. |

## Identity Conventions

Use stable actor URIs:

- `agent://hermes` — this Hermes instance or profile.
- `agent://claude-code` — Claude Code.
- `agent://claude-tag/<workspace>/<channel>` — a channel-scoped Claude Tag identity when known.
- `agent://perplexity/<surface>` — Perplexity/Comet-style agent surfaces when known.
- `human://slack/<team_id>/<user_id>` — Slack human identity.
- `room://slack/<team_id>/<channel_id>` — Slack channel / trusted room.

Do not use mutable display names as the only identity. Put display names in metadata if needed.

## Trusted Room Pattern

When Hermes is working in a Slack/channel-style room, treat the room as a policy boundary:

1. Record the room identity: `room://slack/<team>/<channel>`.
2. Record the requester as a human identity: `human://slack/<team>/<user>`.
3. Record the agent identity: `agent://hermes` or the channel-scoped agent URI.
4. Keep room memories, tool permissions, approvals, spend limits, and reports scoped to that room.
5. Never let private-room memory or evidence leak into another room’s receipt unless an explicit approved handoff exists.

This aligns with Claude Tag-style team agents: channel-scoped agent identity, controlled tools, scoped memory, task log, requester log, and channel-level spend limits.

## Privacy Rules

- Do not include API keys, OAuth tokens, bearer tokens, private URLs, raw prompts with secrets, or database connection strings in Treeship metadata.
- Prefer hashes, artifact IDs, paths, command names, exit codes, and short non-secret summaries.
- For commands that require secrets, pass secrets through environment/config and record only the command boundary.
- If a receipt must mention sensitive context, ask the user before publishing it to Hub.

## Common Pitfalls

1. **No `TREESHIP_ACTOR`.** MCP receipts become generic and harder to trust. Set `TREESHIP_ACTOR=agent://hermes`.
2. **Assuming Hermes skill coverage is bypass-proof.** It is instruction-based. Use MCP and `treeship wrap` for stronger evidence.
3. **Leaking command-line secrets.** Treeship can record command boundaries; do not put secrets in args.
4. **Using display names as identities.** Slack names change; use workspace/user/channel IDs.
5. **Publishing before checking.** Run `treeship verify last` before sharing a Hub URL.
6. **Mixing room memory.** Keep channel-scoped agent memories and receipts separate unless there is an explicit handoff/approval.

## Verification Checklist

Before saying a Hermes task is Treeship-verifiable:

- [ ] `treeship init` has been run for the workspace or user.
- [ ] Hermes has an agent identity, preferably from `treeship agent register --name hermes --own-key`.
- [ ] Hermes MCP config includes `TREESHIP_ACTOR=agent://hermes`.
- [ ] Important shell commands were run via `treeship wrap` or recorded as session events.
- [ ] Sensitive actions have approval artifacts.
- [ ] Handoffs identify both agents.
- [ ] `treeship verify last` passes.
- [ ] Published reports contain no secrets.
