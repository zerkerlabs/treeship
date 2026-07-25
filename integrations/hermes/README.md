# Treeship + Hermes Integration

Hermes integrates via the universal MCP bridge and a declarative skill file — there is **no Hermes-native in-process plugin** today. Coverage is skill-driven + MCP-routed; if you need hook-based bypass-proof capture, that lives in the Claude Code, Kimi Code, or OpenClaw plugins.

The target outcome is a **provable Hermes session**: Hermes has its own Treeship agent identity, MCP-routed tool calls are signed as `agent://hermes`, important shell commands are wrapped, and the final session report verifies offline.

## Prerequisites

```bash
curl -fsSL https://treeship.dev/install | sh
treeship init
npm install -g @treeship/mcp
```

## Fast path

Treeship `v0.15.0` and later can install the Hermes skill directly:

```bash
treeship add hermes
```

That writes:

```text
~/.hermes/skills/treeship/SKILL.md
```

and, when run inside a Treeship project, writes `./TREESHIP.md` so Hermes can see the project capture rules.

If you are smoke-testing with a temporary `HOME` on macOS, use a canonical temp path such as `/private/tmp/...`; `/tmp` is a symlink to `/private/tmp`, and Treeship refuses to write integration files through symlinked config paths.

## Method 1: Skill file (instruction-based)

Prefer the fast path above. Manual fallback:

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

`--args` must come last in the Hermes CLI command.

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

# Install the skill and project TREESHIP.md.
treeship add hermes

# Start a session before meaningful work.
treeship session start --name "hermes-test"
```

## Release smoke test

```bash
TMP=$(mktemp -d /tmp/treeship-v015-smoke.XXXXXX)
TMP_REAL=$(cd "$TMP" && pwd -P)
HOME_TMP="$TMP_REAL/home"
mkdir -p "$HOME_TMP" "$TMP_REAL/work"

curl -fsSL https://github.com/zerkerlabs/treeship/releases/download/v0.15.0/treeship-darwin-aarch64 \
  -o "$TMP_REAL/treeship"
chmod +x "$TMP_REAL/treeship"

cd "$TMP_REAL/work"
HOME="$HOME_TMP" "$TMP_REAL/treeship" init
HOME="$HOME_TMP" "$TMP_REAL/treeship" add hermes

test -f "$HOME_TMP/.hermes/skills/treeship/SKILL.md"
grep 'TREESHIP_ACTOR=agent://hermes' "$HOME_TMP/.hermes/skills/treeship/SKILL.md"
```

Expected:

```text
✓ Hermes Skill Harness configured
✓ ./TREESHIP.md written
```

## Provable Hermes session demo

```bash
treeship init
treeship agent register --name hermes --own-key --tools mcp,terminal,file,git --description "Hermes Agent"
treeship add hermes

hermes mcp add treeship --command npx \
  --env TREESHIP_ACTOR=agent://hermes TREESHIP_HUB_ENDPOINT=https://api.treeship.dev \
  --args -y @treeship/mcp

treeship session start --name "hermes: first verified session"
treeship wrap -- /bin/echo "hello from a provable Hermes session"
treeship session close
```

`session close` prints the `.treeship` package path. Verify it offline:

```bash
treeship package verify .treeship/sessions/<session-id>.treeship
```

Publish a report after Hub attach:

```bash
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
