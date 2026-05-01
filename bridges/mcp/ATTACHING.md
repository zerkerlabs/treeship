# Attaching any MCP-compatible agent to Treeship

Treeship is a **trust fabric**, not an agent. The product promise is:

> Every agent gets a verifiable work receipt — same shape, regardless of vendor.

This document shows how to attach any MCP-compatible coding agent so its tool calls flow into a Treeship session and end up on a shareable receipt at `treeship.dev/receipt/<id>`.

## What ships today (v0.10)

`@treeship/mcp` ships in two modes:

1. **MCP server mode** (new in 0.10.1) — add `npx -y @treeship/mcp` as an MCP server in your agent's config. The server exposes Treeship tools (`treeship_session_status`, `treeship_session_event`, `treeship_attest_action`, `treeship_verify`, `treeship_session_report`) so any MCP client can read/write the active session.
2. **Library mode** — `import { Client } from '@treeship/mcp'` to drop-in replace your `@modelcontextprotocol/sdk` client; every `callTool()` it makes is signed and recorded automatically.

The **transparent forwarder** model described below — where the bridge proxies every call to an upstream MCP server and attests in between — is roadmap (target v0.11). The diagram and "what the agent sees" sections describe that future shape, not today's behavior. If you need every MCP tool call attested today, use library mode.

## How it works (one diagram)

```
                  ┌──────────────────────────────────┐
   YOUR AGENT ──▶ │  @treeship/mcp  (this bridge)    │ ──▶ AGENT'S TARGET MCP SERVERS
   (any MCP       │                                  │     (filesystem, github, etc.)
    client)       │  • forwards every callTool       │
                  │  • signs an intent attestation   │
                  │  • signs a result receipt        │
                  │  • emits a session event         │
                  └──────────────────────────────────┘
                                  │
                                  ▼
                  ┌──────────────────────────────────┐
                  │  .treeship/sessions/<id>/         │
                  │   events.jsonl, artifacts/, …     │
                  │                                  │
                  │  treeship session close           │
                  │   → reconcile via git diff        │
                  │   → compose Session Receipt       │
                  │   → seal merkle root              │
                  └──────────────────────────────────┘
                                  │
                                  ▼
                       treeship.dev/receipt/<id>
```

The bridge is a transparent forwarder. Your agent connects to it as if it were a normal MCP server; it forwards every `callTool` to the actual target server and adds the trust layer in between. **No agent code changes are required.**

## What the agent sees

Exactly the MCP server it would have configured directly. The bridge speaks MCP on both sides.

## What the receipt sees

For every tool call the agent makes:

1. **Intent attestation** (signed before the call):
   - actor URI (e.g. `agent://cursor`)
   - action label (`mcp.tool.<TOOL_NAME>.intent`)
   - args digest (sha256, never raw values)

2. **Result receipt** (signed after the call):
   - tool name, elapsed time, exit code, output digest
   - error message text on thrown errors

3. **Session event** in the timeline:
   - `agent.called_tool` with full meta the receipt aggregator can promote into `files_read`/`files_written`/`processes` (so the file/command actually appears on the receipt page, not just a tool-call counter)

Plus the surrounding session pulls in:
- per-agent **model + provider** attribution from `agent.decision` events (when the integration emits one)
- **git reconciliation** at session close to catch files edited outside any tool channel
- Merkle root + per-artifact inclusion proofs

## Three axes, one receipt

The trust fabric separates these cleanly:

| Axis | Examples | How the receipt shows it |
|---|---|---|
| **Agent surface** | Claude Code, Cursor, Codex, OpenClaw, Hermes, Cline | `agent_name` per event, `agent_graph` per session |
| **Model / provider** | claude-opus-4-7 / anthropic, gpt-5 / openai, kimi-k2 / moonshot, llama-3 / meta, local / ollama | Provider-colored pill on each agent card |
| **Tool channel** | native hook, MCP gateway (this bridge), shell wrap, git reconciliation | `source` field on every file/process row |

Any agent that speaks MCP attaches via this bridge. Any model/provider behind that agent gets attributed. Any tool channel that touches the working directory gets witnessed.

## Three ways to attach

### 1. The CLI does it for you

```bash
treeship init           # if you haven't already
treeship add            # auto-detects every supported agent and writes the right config
```

`treeship add` knows about Claude Code (`~/.claude/`), Cursor (`~/.cursor/`), Codex (`~/.codex/config.toml`), Cline (`~/.config/cline/`), Hermes (skill file), and OpenClaw (skill file). For each MCP-compatible agent it merges a `treeship` server entry into the agent's config.

### 2. Drop-in MCP config (any vendor)

For agents `treeship add` doesn't know about yet, paste this into the agent's MCP config (the JSON or TOML key your agent uses to register MCP servers):

JSON-style (Claude Code, Cursor, Cline, most others):

```json
{
  "mcpServers": {
    "treeship": {
      "command": "npx",
      "args": ["-y", "@treeship/mcp"],
      "env": {
        "TREESHIP_ACTOR": "agent://YOUR_AGENT_NAME",
        "TREESHIP_HUB_ENDPOINT": "https://api.treeship.dev"
      }
    }
  }
}
```

TOML-style (Codex CLI):

```toml
[mcp_servers.treeship]
command = "npx"
args = ["-y", "@treeship/mcp"]

[mcp_servers.treeship.env]
TREESHIP_ACTOR = "agent://YOUR_AGENT_NAME"
TREESHIP_HUB_ENDPOINT = "https://api.treeship.dev"
```

Set `TREESHIP_ACTOR` to a URI that uniquely identifies the agent. The receipt uses this to attribute tool calls — `agent://cursor`, `agent://codex`, `agent://your-custom-agent`, etc.

Restart the agent so it reloads MCP settings.

### 3. Skill-style agents (no MCP)

For agents that follow skill files instead of MCP (OpenClaw, Hermes, and similar agents that load instructions from a directory):

```bash
treeship add hermes      # writes ~/.hermes/skills/treeship/SKILL.md
treeship add openclaw    # writes ~/.openclaw/skills/treeship/SKILL.md
```

The skill file tells the agent the same thing the MCP bridge enforces: prefix shell commands with `treeship wrap --`, emit decision events at the right times, close the session when work is done.

## What you need to add for a NEW agent

Whether it's a new MCP-compatible coding agent, a new skill-based agent, or anything else: the receipt format doesn't care. To support a new agent:

1. **MCP-compatible**: nothing in core Treeship needs to change. Add detection to `treeship add` (cwd or env probe → write the right config file) and an integration directory `integrations/<vendor>/` with a README and template config. See `integrations/cursor/` and `integrations/codex/` as reference.

2. **Skill-style**: add an `integrations/<vendor>/treeship.skill/SKILL.md` and wire detection in `treeship add`. See `integrations/openclaw/` and `integrations/hermes/` as reference.

3. **Hook-based** (the agent has its own session-lifecycle hooks, like the Claude Code plugin): add scripts under `integrations/<vendor>-plugin/` and let the agent's plugin loader pick them up. See `integrations/claude-code-plugin/scripts/`.

In every case the receipt looks identical. That's the whole point.

## What gets captured vs what doesn't

Captured:
- Every MCP tool call, with the action label and a digest of the input args
- Tool name, elapsed time, exit code
- A digest of the output (so repudiation is harder, no raw content to leak)
- Error message text on thrown errors (treat like a logged stack trace — make sure your tools don't put secrets in error strings)
- Files written/read when the tool's input includes a file path
- Commands run when the tool's input includes a command string
- Model/provider/token counts when the integration emits an `agent.decision` event
- Files changed outside the tool channel, via git reconciliation at close

Not captured (by design):
- Raw argument values or raw output content (digests only)
- File contents (the bridge has no FS access)
- Environment variables or secrets (env vars are read for behavior, never logged)
- Anything outside the MCP tool-call boundary (unless the integration adds its own hooks)

## The bar

> **If an agent changes code during a Treeship session and the receipt does not show it, Treeship failed.**

The MCP gateway is the universal attach path that makes this bar achievable for any vendor that speaks MCP. The git reconciliation at close is the backstop that closes the gap when MCP isn't enough.

For everything beyond MCP (native hooks, shell wraps), see `integrations/`. For the on-disk receipt format, see `packages/core/src/session/receipt.rs`. For the verifiability story, see `treeship.dev/docs`.
