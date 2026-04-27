# Treeship + Codex CLI

Codex CLI talks to MCP servers via TOML config in `~/.codex/config.toml`. The same [`@treeship/mcp`](../../bridges/mcp/) bridge that powers the Claude Code and Cursor integrations works here too: every MCP `callTool` is attested and appears in the session timeline when a Treeship session is active.

## Method 1: CLI (recommended)

From a project with `treeship init` already run:

```bash
curl -fsSL treeship.dev/install | sh
treeship init
treeship add codex
# or: treeship add   # configures every detected agent, including Codex
```

This appends a `[mcp_servers.treeship]` block to `~/.codex/config.toml` (creating the file and parent dirs if needed). The actor URI is `agent://codex` so receipts identify Codex as the tool caller.

**Restart Codex** so it reloads MCP settings.

`treeship add` also drops `./TREESHIP.md` in the project (once) with the trust and capture details — read that before enabling the server.

## Method 2: Copy the template

If you prefer to edit config by hand, append the contents of `config.toml` in this directory to your existing `~/.codex/config.toml`.

## Prerequisites

- [Codex CLI](https://github.com/openai/codex) installed (so `~/.codex/` exists — run `codex` once if the folder is missing).
- `treeship` CLI on `PATH` and Node/npx for `npx -y @treeship/mcp`.
- A Treeship project: `treeship init` in the repo you open in Codex.

## What gets captured

Every Codex tool call routed through MCP produces:

- A signed **intent attestation** before the call (action label, args digest, no raw arguments).
- A signed **result receipt** after the call (tool name, elapsed time, exit code, output digest, no raw output).
- A **session event** in the timeline so the receipt page renders Codex's contribution alongside other agents in the session.

Codex's built-in tools that don't go through MCP (file reads/writes, shell exec) are not currently captured by this integration. For full per-tool coverage of Codex's built-ins, we'd need a hook story analogous to the [Claude Code plugin](../claude-code-plugin/) — which Codex does not yet expose.

## Provider attribution

Receipts identify the actor as `agent://codex` and (once `treeship session event --type agent.decision --provider openai --model <name>` is emitted at session start) display the OpenAI model name on the agent card. See the [Claude Code plugin's session-start hook](../claude-code-plugin/scripts/session-start.sh) for the pattern; an equivalent hook for Codex can land once Codex CLI exposes a session-start trigger.
