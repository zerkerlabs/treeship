# Treeship + OpenClaw Integration

## Install the skill

Copy to your OpenClaw skills directory:

```bash
cp -r treeship.skill ~/.openclaw/skills/
```

Or per-workspace:

```bash
cp -r treeship.skill <workspace>/skills/
```

## Prerequisites

```bash
curl -fsSL treeship.dev/install | sh
treeship init
```

## Test

```bash
treeship session start --name "openclaw-test"
# Run your OpenClaw agent -- it reads the SKILL.md and follows the instructions
treeship session close --summary "Tested OpenClaw integration"
treeship package verify .treeship/sessions/ssn_*.treeship
```
