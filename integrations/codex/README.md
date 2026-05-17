# Treeship + Codex CLI

Codex has two Treeship paths:

1. **Skills** teach Codex how to use Treeship or how to work safely in this repo.
2. **MCP** captures MCP-routed tool calls into a Treeship session.

Codex CLI talks to MCP servers via TOML config in `~/.codex/config.toml`. The same [`@treeship/mcp`](../../bridges/mcp/) bridge that powers the Claude Code and Cursor integrations works here too: every MCP `callTool` is attested and appears in the session timeline when a Treeship session is active.

## Method 1: Install the Codex skills

Use the public Treeship skill when you want Codex to sign actions, verify chains, manage approvals, push receipts, or explain Treeship APIs:

```bash
npx skills add zerkerlabs/treeship --skill treeship --agent codex -g -y
```

Use the contributor skill when Codex is working inside this source repo:

```bash
npx skills add zerkerlabs/treeship --skill treeship-dev --agent codex -g -y
```

The contributor skill tells Codex to read `AGENTS.md` and `ONBOARDING.md`, preserve cryptographic invariants, keep CLI UX rules intact, and run focused validation.

Open a fresh Codex conversation after installing skills.

## Method 2: CLI (recommended for MCP)

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

## Method 3: Copy the MCP template

If you prefer to edit config by hand, append the contents of `config.toml` in this directory to your existing `~/.codex/config.toml`.

## Method 4: Codex plugin candidate

The repo includes a candidate Codex plugin package at [`plugins/treeship-dev`](../../plugins/treeship-dev/). It bundles the `treeship-dev` skill and a `.codex-plugin/plugin.json` manifest for local testing and future plugin submission.

Until that plugin is accepted into an official marketplace, the direct skill install is the stable path:

```bash
npx skills add zerkerlabs/treeship --skill treeship-dev --agent codex -g -y
```

Maintainers preparing submission should keep the plugin-bundled skill in sync with [`skills/treeship-dev/SKILL.md`](../../skills/treeship-dev/SKILL.md), review the manifest metadata, test in a fresh Codex session, and submit `plugins/treeship-dev/` through the current Codex plugin submission process.

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
