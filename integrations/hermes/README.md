# Treeship + Hermes Integration

Hermes integrates via the universal MCP bridge and a declarative skill file — there is **no Hermes-native in-process plugin** today. Coverage is skill-driven + MCP-routed; if you need hook-based bypass-proof capture, that lives in the Claude Code, Kimi Code, or OpenClaw plugins.

The target outcome is a **provable Hermes session**: Hermes has its own Treeship agent identity, MCP-routed tool calls are signed as `agent://hermes`, important shell commands are wrapped, and the final session report verifies offline.

## Prerequisites

```bash
curl -fsSL https://treeship.dev/install | sh
treeship init
npm install -g @treeship/mcp
```

## Method 1: Skill file (instruction-based)

Copy this integration skill into Hermes:

```bash
mkdir -p ~/.hermes/skills/treeship
cp integrations/hermes/treeship.skill/SKILL.md ~/.hermes/skills/treeship/SKILL.md
```

Or install from GitHub:

```bash
mkdir -p ~/.hermes/skills/treeship
curl -fsSL https://raw.githubusercontent.com/zerkerlabs/treeship/main/integrations/hermes/treeship.skill/SKILL.md \
  -o ~/.hermes/skills/treeship/SKILL.md
```

The Hermes agent reads the skill and follows the instructions to start/close sessions, wrap side-effectful shell commands, record approvals and handoffs, and avoid publishing secrets.

## Method 2: MCP server (tool-call interception)

Add Treeship as an MCP server in Hermes:

```bash
hermes mcp add treeship --command npx \
  --env TREESHIP_ACTOR=agent://hermes TREESHIP_HUB_ENDPOINT=https://api.treeship.dev \
  --args -y @treeship/mcp
```

Then ensure the MCP server env contains the Hermes actor:

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

`TREESHIP_ACTOR=agent://hermes` is required — without it, MCP receipts may fall back to a generic MCP identity instead of Hermes.

## Recommended setup

```bash
# Give Hermes its own key-bound identity for provable receipts.
treeship agent register --name hermes --own-key --tools mcp,terminal,file,git --description "Hermes Agent"

# Start a session before meaningful work.
treeship session start --name "hermes-test"
```

## Testing

```bash
# Run Hermes with the skill active and MCP configured.
hermes chat -q "Use Treeship to record a short non-secret test note, then stop."

# Close, verify, and optionally publish a report.
treeship session close --summary "Tested Hermes integration"
treeship verify last
treeship session report
```

## Expected receipt contents

- Agent: `agent://hermes`.
- Actor proof: key-bound/proven when Hermes has an `--own-key` identity and the MCP path signs with that actor.
- Timeline: MCP-routed tool calls plus explicit session events.
- Commands: side-effectful shell commands when run through `treeship wrap`.
- Approvals/handoffs: explicit artifacts when sensitive work or agent transitions happen.

## Honest coverage

Hermes skill coverage is not bypass-proof because it depends on the agent following instructions. Pair it with MCP for automatic MCP tool-call receipts and `treeship wrap` for shell commands. Use session reports and git reconcile as backstops for file-level evidence.
