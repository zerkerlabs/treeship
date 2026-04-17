---
name: treeship
description: Signed session receipts for every OpenClaw task
version: 0.7.2
author: Zerker Labs
homepage: https://treeship.dev
openclaw:
  category: security
  tags: [attestation, receipts, verification, trust]
requires:
  bins:
    - treeship
  env:
    - TREESHIP_MODEL
---

# Treeship

Generate signed, verifiable session receipts for every OpenClaw task. Each receipt captures what happened, who did it, what changed, and provides cryptographic proof that the record is trustworthy.

## Setup

The `treeship` CLI must be installed and initialized:

```bash
curl -fsSL treeship.dev/install | sh
treeship init
```

## Primary workflow

### At the start of every task

Start a Treeship session with the task name:

```bash
treeship session start --name "<task description>"
export TREESHIP_MODEL="<your model>"
export TREESHIP_TOKENS_IN="<input tokens>"
export TREESHIP_TOKENS_OUT="<output tokens>"
export TREESHIP_COST_USD="<cost>"
```

### During the task

Every shell command MUST be prefixed with `treeship wrap --`:

```bash
treeship wrap -- <command>
```

Common patterns:

```bash
treeship wrap -- npm test
treeship wrap -- cargo build --release
treeship wrap -- git add -A && git commit -m "fix: resolve bug"
treeship wrap -- python3 script.py
treeship wrap -- curl -sS https://api.example.com/endpoint
```

### Sub-tasks

For sub-tasks within a larger task, continue using the same session. Do NOT start a new session. The receipt should capture the entire task as one unit.

### When the task is complete

Close with a meaningful summary:

```bash
treeship session close \
  --headline "<what was accomplished>" \
  --summary "<detailed description of what changed>" \
  --review "<what a reviewer should check before trusting this work>"
```

Upload for a shareable URL:

```bash
treeship session report
```

## Writing good summaries

**Good headline:** "Fixed JWT expiry bug that caused 401s after 24 hours"
**Bad headline:** "Fixed a bug"

**Good summary:** "Found the TTL was set to 24h instead of 7d in token.ts. Fixed the constant, added a regression test, and confirmed the fix in local tests."
**Bad summary:** "Fixed the bug."

**Good review:** "Verify the TTL change works with existing tokens in production."
**Bad review:** "Please review."

## What gets captured

| Data | How | Status |
|------|-----|--------|
| Shell commands | `treeship wrap --` | AUTO |
| File operations | File snapshot diff | AUTO |
| Model name | `TREESHIP_MODEL` env var | EXPLICIT |
| Token counts | `TREESHIP_TOKENS_IN/OUT` | EXPLICIT |
| Cost | `TREESHIP_COST_USD` | EXPLICIT |
| Session narrative | `--headline/--summary/--review` | EXPLICIT |
| Merkle proof | Automatic | AUTO |
| Ed25519 signatures | Automatic | AUTO |

## What does NOT get captured

- Commands run without `treeship wrap --`
- File reads (run `treeship daemon start` for atime detection)
- Network connections (use `treeship session event --type agent.connected_network`)
- Internal agent reasoning
