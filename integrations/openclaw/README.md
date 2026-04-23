# Treeship + OpenClaw Integration

## Quick Install (recommended)

The Treeship setup script auto-detects OpenClaw and installs this skill:

```bash
curl -fsSL treeship.dev/setup | sh
```

This installs the CLI, runs `treeship init`, and copies `treeship.skill` to `~/.openclaw/skills/treeship/`.

## Manual Install

If you prefer to install manually:

```bash
# Install Treeship CLI
curl -fsSL treeship.dev/setup | sh

# Copy skill to OpenClaw skills directory
cp -r treeship.skill ~/.openclaw/skills/
```

Or per-workspace:

```bash
cp -r treeship.skill <workspace>/skills/
```

## Test the Integration

```bash
treeship session start --name "openclaw-test" --actor agent://openclaw
# Run your OpenClaw agent -- it reads the SKILL.md and follows the instructions
treeship wrap -- echo "Testing Treeship + OpenClaw"
treeship session close --headline "Tested OpenClaw integration" --summary "Verified skill installation and wrap command"
treeship verify last
```

## What's in the skill

- `SKILL.md` — Full instructions for using Treeship within OpenClaw sessions
- Covers: `treeship wrap --`, `treeship session start/close/report`, MCP bridge setup
- Updated for Treeship v0.9.4 (Rust core, 161 tests, Ed25519 DSSE)

## Resources

- Treeship docs: https://docs.treeship.dev
- Source: https://github.com/zerkerlabs/treeship
- OpenClaw docs: https://docs.openclaw.ai
