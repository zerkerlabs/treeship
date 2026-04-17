---
name: treeship
description: Signed session receipts for every Hermes task. Portable, verifiable, shareable.
version: 0.7.2
author: Zerker Labs
homepage: https://treeship.dev
requires:
  bins:
    - treeship
  env:
    - TREESHIP_MODEL
---

# Treeship

Generate signed, verifiable session receipts for every Hermes task. Each receipt captures what happened, who did it, what changed, and provides cryptographic proof that the record is trustworthy.

## Setup

The `treeship` CLI must be installed and initialized:

```bash
curl -fsSL treeship.dev/install | sh
treeship init
```

## How to use

### At the start of every task

Before doing any work, start a Treeship session:

```bash
treeship session start --name "<task description>"
```

Set your model and cost information:

```bash
export TREESHIP_MODEL="hermes-2"
export TREESHIP_TOKENS_IN="<input tokens>"
export TREESHIP_TOKENS_OUT="<output tokens>"
export TREESHIP_COST_USD="<cost>"
```

### During the task

Prefix every shell command with `treeship wrap --`:

```bash
treeship wrap -- <your command>
```

Examples:

```bash
treeship wrap -- curl -sS https://api.example.com/data
treeship wrap -- python3 analyze.py --input data.json
treeship wrap -- npm test
treeship wrap -- git commit -m "implement feature"
```

### When the task is complete

Close the session with a meaningful summary:

```bash
treeship session close \
  --headline "<one sentence: what was accomplished>" \
  --summary "<what you did and what changed>" \
  --review "<what a reviewer should check>"
```

Then upload for a shareable URL:

```bash
treeship session report
```

### For handoffs to other agents

When delegating work to another agent:

```bash
treeship session event --type agent.handoff \
  --actor agent://hermes \
  --destination agent://claude-code \
  --meta '{"task_id": "<task_id>"}'
```

### For external API calls

When making outbound HTTP requests:

```bash
treeship session event --type agent.connected_network \
  --destination api.example.com \
  --agent-name hermes
```

## What gets captured

- Every wrapped command with exit code, duration, and output digest
- File operations (created, modified, deleted)
- Agent model, token counts, and cost per interaction
- Session narrative (headline, summary, review)
- Merkle root over all signed artifacts
- Ed25519 signatures on every artifact

## What does NOT get captured

- Commands run without `treeship wrap --` prefix
- Internal Hermes reasoning or inference steps
- Network connections unless explicitly emitted via `treeship session event`
- File reads unless the Treeship daemon is running (`treeship daemon start`)
