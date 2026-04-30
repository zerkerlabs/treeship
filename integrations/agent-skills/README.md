# Agent Skills — Multi-Agent Integration

One [`SKILL.md`](../../skills/treeship/SKILL.md) file teaches every coding agent how to use Treeship. Install it on Kimi Code CLI, Claude Code, Codex, Cursor, OpenClaw, or Hermes and the agent can sign actions, verify chains, manage approvals, and push receipts to the Hub — all without you re-explaining the API every conversation.

The skill covers the full Treeship surface: CLI commands (`treeship wrap`, `treeship verify`, `treeship session report`, `treeship approve`, `treeship hub push`), Python SDK (`treeship-sdk`), TypeScript SDK (`@treeship/sdk`), MCP bridge (`@treeship/mcp`), Hub API (`api.treeship.dev`), approval-gated workflows, and chained multi-agent handoffs.

## Quick Reference

| Agent | Install Command | `--agent` flag | Skills Path |
|---|---|---|---|
| Kimi Code CLI | `npx skills add zerkerlabs/treeship --skill treeship --agent kimi-cli -g -y` | `kimi-cli` | `~/.config/agents/skills/` |
| Claude Code | `npx skills add zerkerlabs/treeship --skill treeship --agent claude-code -g -y` | `claude-code` | `~/.claude/skills/` |
| Codex | `npx skills add zerkerlabs/treeship --skill treeship --agent codex -g -y` | `codex` | `~/.codex/skills/` |
| Cursor | `npx skills add zerkerlabs/treeship --skill treeship --agent cursor -g -y` | `cursor` | `~/.cursor/skills/` |
| OpenClaw | `npx skills add zerkerlabs/treeship --skill treeship --agent openclaw -g -y` | `openclaw` | `~/.openclaw/skills/` |
| Hermes | Manual curl (see below) | — | `~/.hermes/skills/` |

The `-g` installs globally (one copy on the machine, every project sees it). `-y` skips the confirmation prompt — useful in CI and scripted setup. Drop both for an interactive install scoped to the current project.

## Per-Agent Setup

### Kimi Code CLI

```bash
npx skills add zerkerlabs/treeship --skill treeship --agent kimi-cli -g -y
```

The skill lands at `~/.config/agents/skills/treeship/SKILL.md` and auto-loads on every Kimi session. Verify:

```bash
ls ~/.config/agents/skills/treeship/
# SKILL.md
```

**MCP bridge (optional)** — for automatic attestation of every tool call without prompting Kimi to run `treeship wrap`:

```bash
kimi mcp add --transport stdio treeship -- npx -y @treeship/mcp
```

**Coverage:** High when the MCP bridge is attached (every MCP tool call is captured); Medium with the skill alone (the agent runs `treeship wrap` when prompted by the skill).

### Claude Code

```bash
npx skills add zerkerlabs/treeship --skill treeship --agent claude-code -g -y
```

The skill lands at `~/.claude/skills/treeship/SKILL.md`. Claude Code reads agent skills automatically — no restart required for new sessions.

**MCP bridge (recommended for full coverage)** — pairs with the skill so Claude Code attests automatically as well as explaining attestation when asked:

```bash
claude mcp add --transport stdio treeship -- npx -y @treeship/mcp
```

**Plugin alternative** — Claude Code also supports the [Treeship plugin](../claude-code-plugin), which bundles the skill, MCP bridge, and SessionStart/PostToolUse/SessionEnd hooks into one install. Use the plugin when you want zero-config session sealing. Use the skill alone when you want the agent to know the API without auto-attaching a session.

**Coverage:** High with the plugin; High with skill + MCP; Medium with skill alone.

### Codex

```bash
npx skills add zerkerlabs/treeship --skill treeship --agent codex -g -y
```

Skill lands at `~/.codex/skills/treeship/SKILL.md`. Codex picks up new skills on the next conversation; no restart required.

**MCP bridge (optional)** — Codex's MCP config lives at `~/.codex/config.toml`:

```toml
[mcp_servers.treeship]
command = "npx"
args = ["-y", "@treeship/mcp"]
```

Or use Codex's CLI to add it:

```bash
codex mcp add treeship npx -y @treeship/mcp
```

**Coverage:** High with skill + MCP; Medium with skill alone.

### Cursor

```bash
npx skills add zerkerlabs/treeship --skill treeship --agent cursor -g -y
```

Skill lands at `~/.cursor/skills/treeship/SKILL.md`. Cursor reads global skills on startup; restart Cursor (or open a new chat session) for the skill to register.

**MCP bridge (optional)** — Cursor's MCP config lives at `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "treeship": {
      "command": "npx",
      "args": ["-y", "@treeship/mcp"]
    }
  }
}
```

**Coverage:** High with skill + MCP; Medium with skill alone.

### OpenClaw

```bash
npx skills add zerkerlabs/treeship --skill treeship --agent openclaw -g -y
```

Skill lands at `~/.openclaw/skills/treeship/SKILL.md`. OpenClaw treats skills as durable instructions; the skill applies to every project where OpenClaw is active.

**MCP bridge** — OpenClaw is currently MCP-routed only; the skill provides the API knowledge, the MCP bridge provides the capture surface. Add it the same way as Cursor (config at `~/.openclaw/mcp.json`).

**Coverage:** Medium with skill alone; High with skill + MCP bridge.

### Hermes

Hermes doesn't have an automated skill installer, so the skill goes in via plain `curl`:

```bash
mkdir -p ~/.hermes/skills/treeship
curl -fsSL https://raw.githubusercontent.com/zerkerlabs/treeship/main/skills/treeship/SKILL.md \
  -o ~/.hermes/skills/treeship/SKILL.md
```

Hermes loads skills from `~/.hermes/skills/<skill_name>/SKILL.md` automatically on its next conversation.

**MCP bridge** — Hermes uses skill files rather than an MCP transport, so the skill is the canonical integration. Coverage stays Medium because Hermes routes commands through `treeship wrap` per the skill's guidance rather than through a passive observer.

**Coverage:** Medium (skill-driven; agent runs `treeship wrap` when needed).

## MCP Bridge (optional, all agents)

For agents that speak MCP (every supported agent except Hermes today), the [`@treeship/mcp`](https://www.npmjs.com/package/@treeship/mcp) bridge captures every tool call automatically. The skill teaches the agent what to do; the bridge captures whatever the agent does. Together they give High coverage without prompting.

Generic install:

```bash
npm install -g @treeship/mcp     # optional pre-install; npx pulls it lazily
```

Per-agent commands above show the wiring. The MCP bridge runs on stdio, talks to the local `treeship` CLI, and attests every tool call into the active session — the same way `treeship wrap` would for a single command, but applied to the agent's full tool surface.

## What the Skill Provides

- **API reference** — every CLI command, SDK method, and Hub API endpoint, with realistic examples
- **Statement type vocabulary** — when to attest action vs. approval vs. handoff vs. decision
- **Approval-gated workflows** — the create-approval / consume-with-nonce / verify pattern
- **Chained workflows** — `parent_id`-linked attestation chains across multi-agent handoffs
- **MCP bridge wiring** — per-agent setup snippets the agent can paste back to a user
- **Hub API surface** — DPoP auth, public verification URLs, Merkle inclusion proofs
- **Standards reference** — Ed25519, DSSE, SHA-256, RFC 8785 canonicalization
- **Result types** — `ActionResult`, `ApprovalResult`, `VerifyResult`, `PushResult`, `SessionReportResult`

The skill is **declarative, not procedural**: it doesn't run anything itself. It teaches the agent the API and the right shape for each use case. The agent decides when to call the CLI / SDK based on what the user asked for.

## Updating

To pull the latest skill content after an upstream change:

```bash
# Same install command — `-y` overwrites without prompting
npx skills add zerkerlabs/treeship --skill treeship --agent <agent> -g -y
```

For Hermes (manual install), re-run the curl one-liner.

The skill content is versioned with the Treeship release — each `treeship` release that changes the CLI surface or SDK shape pushes a matching skill update. Pin to a specific release tag if you need stability:

```bash
npx skills add zerkerlabs/treeship@v0.10.0 --skill treeship --agent <agent> -g -y
```

## Removing

```bash
# Skills installer removal
npx skills remove --skill treeship --agent <agent> -g

# Manual removal (any agent)
rm -rf ~/.<agent-config-dir>/skills/treeship/
```

The skill leaves no other state behind — no daemons, no background processes, no tracking. Removing the directory un-installs cleanly.

## Coverage Levels by Agent

| Agent | Skill alone | Skill + MCP | Plugin (where available) |
|---|---|---|---|
| Kimi Code CLI | Medium | High | — |
| Claude Code | Medium | High | High |
| Codex | Medium | High | — |
| Cursor | Medium | High | — |
| OpenClaw | Medium | High | — |
| Hermes | Medium | (no MCP today) | — |

**Coverage levels** match Treeship's [coverage-levels guide](https://docs.treeship.dev/guides/coverage-levels):

- **High** — Treeship sees every Read, Write, Bash, MCP tool call. The agent's full execution surface is captured.
- **Medium** — Treeship sees the commands the agent explicitly wraps with `treeship wrap` (the skill teaches the agent when this matters); other tool calls aren't captured.
- **Basic** — fallback. The agent knows about Treeship and runs `treeship wrap` for explicit commands the user asked it to attest, but no passive observation.

The skill's job is to lift any agent from "doesn't know about Treeship" to at least Medium. Adding the MCP bridge (or installing the plugin where available) lifts coverage to High.

## See Also

- [`skills/treeship/SKILL.md`](../../skills/treeship/SKILL.md) — the skill content itself
- [Claude Code plugin](../claude-code-plugin) — the higher-coverage path for Claude Code
- [Treeship docs — integrations](https://docs.treeship.dev/integrations) — per-agent integration pages
- [Treeship docs — coverage levels](https://docs.treeship.dev/guides/coverage-levels) — what High/Medium/Basic mean
