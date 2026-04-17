# Treeship + Hermes Integration

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
      TREESHIP_HUB_ENDPOINT: "https://api.treeship.dev"
```

This intercepts every MCP tool call and creates signed artifacts + session events automatically.

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
- Cost: populated if TREESHIP_COST_USD is set
