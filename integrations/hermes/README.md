# Treeship + Hermes Integration

Hermes integrates via the universal MCP bridge and a declarative skill file — there is **no Hermes-native plugin** (no in-process hooks, no compiled extension). Coverage is skill-driven + MCP-routed; if you need hook-based bypass-proof capture, that lives in the Claude Code, Kimi Code, or OpenClaw plugins.

Two integration methods for Hermes agents:

## Method 1: Skill file (instruction-based)

Copy the skill file to your Hermes skills directory:

```bash
cp -r treeship.skill ~/.hermes/skills/
```

Or install from the repo:

```bash
curl -sL https://raw.githubusercontent.com/zerkerlabs/treeship/main/integrations/hermes/treeship.skill/SKILL.md \
  -o ~/.hermes/skills/treeship.skill/SKILL.md --create-dirs
```

The Hermes agent reads the skill and follows the instructions to wrap commands, set env vars, and manage session lifecycle automatically.

## Method 2: MCP server (tool-call interception)

Add Treeship as an MCP server in your Hermes config:

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

This intercepts every MCP tool call and creates signed artifacts + session events automatically. The `TREESHIP_ACTOR` env is required — without it, Hermes events fall back to the generic `agent_name=mcp` in receipts instead of `hermes`.

## Prerequisites

```bash
curl -fsSL treeship.dev/install | sh
treeship init
npm install -g @treeship/mcp  # for Method 2
```

## Testing

```bash
# Start a session
treeship session start --name "hermes-test"

# Run Hermes with the skill active
hermes run "research the latest AI safety papers"

# Close and verify
treeship session close --summary "Tested Hermes integration"
treeship package verify .treeship/sessions/ssn_*.treeship
treeship session report
```

## Expected receipt contents

- Agent: hermes (or hermes-2 if TREESHIP_MODEL is set)
- Timeline: every wrapped command or MCP tool call
- Commands: full command strings with exit codes
- Provider: populated if TREESHIP_PROVIDER is set
