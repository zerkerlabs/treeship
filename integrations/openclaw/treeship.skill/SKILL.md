---
name: treeship
description: Signed session receipts for every OpenClaw task (v0.9.4)
version: 0.9.4
author: Zerker Labs
homepage: https://treeship.dev
openclaw:
  category: security
  tags: [attestation, receipts, verification, trust, mcp]
requires:
  bins:
    - treeship
  env:
    - TREESHIP_ACTOR
---

# Treeship

Generate signed, verifiable session receipts for every OpenClaw task. Each receipt captures what happened, who did it, what changed, and provides cryptographic proof that the record is trustworthy.

**Current version: 0.9.4** — Rust core, 161 tests passing, Ed25519 DSSE envelopes, offline verification.

## Quick Setup

One-liner (macOS/Linux):
```bash
curl -fsSL treeship.dev/setup | sh
```

Or via npm (inspectable, signed package):
```bash
npm install -g treeship
treeship init
```

The setup script auto-detects OpenClaw and installs this skill to `~/.openclaw/skills/treeship/`.

## Primary workflow

### At the start of every task

```bash
treeship session start --name "<task description>" --actor agent://openclaw
```

Optional: set model metadata for richer receipts:
```bash
export TREESHIP_ACTOR="agent://openclaw"
export TREESHIP_MODEL="<your model>"
```

### During the task

Every shell command MUST be prefixed with `treeship wrap --`:

```bash
treeship wrap -- npm test
treeship wrap -- cargo build --release
treeship wrap -- python3 script.py
treeship wrap -- curl -sS https://api.example.com/endpoint
```

For multi-step shell commands:
```bash
treeship wrap -- bash -c "git add -A && git commit -m 'fix: resolve bug'"
```

### Sub-tasks

For sub-tasks within a larger task, continue using the same session. Do NOT start a new session. The receipt should capture the entire task as one unit.

### When the task is complete

Close with a meaningful summary:

```bash
treeship session close \
  --headline "<one-line accomplishment>" \
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
| Exit codes | `treeship wrap --` | AUTO |
| Elapsed time | `treeship wrap --` | AUTO |
| File writes | File snapshot diff | AUTO |
| Model name | `TREESHIP_MODEL` env var | EXPLICIT |
| Actor URI | `TREESHIP_ACTOR` env var | EXPLICIT |
| Session narrative | `--headline/--summary/--review` | EXPLICIT |
| Merkle proof | Automatic | AUTO |
| Ed25519 signatures | Automatic | AUTO |

## What does NOT get captured

- Commands run without `treeship wrap --`
- Raw argument values (only SHA-256 digests)
- Raw output content (only SHA-256 digests)
- File reads (run `treeship daemon start` for atime detection)
- Internal agent reasoning
- Environment variable values

## MCP Bridge (automatic tool-call capture)

If `@treeship/mcp` is configured as your MCP server, every `callTool` invocation is automatically attested:
- **Intent attestation** (signed before the call): actor, tool name, args digest
- **Result receipt** (signed after): exit code, elapsed time, output digest
- **Session event**: timeline entry linking intent to result

No `treeship wrap --` needed for MCP tool calls. Configure via:
```bash
npx -y @treeship/mcp@latest setup
```

## Additional commands

```bash
treeship status              # show keys, recent artifacts, hub status
treeship verify last         # verify the most recent artifact
treeship verify <id>         # verify a specific artifact
treeship package verify <path>  # verify a .treeship package offline
treeship hub attach          # connect to treeship.dev Hub
treeship hub push <id>       # push artifact to Hub
treeship ui                  # interactive TUI dashboard
treeship doctor              # diagnostic check
treeship add                 # instrument AI agents in current project
treeship quickstart          # guided first-time setup
```

## Trust model

- **Local-first**: Everything works offline. Hub is optional.
- **Self-contained**: A receipt is a JSON file. Verifies without trusting Treeship infrastructure.
- **Privacy-aware**: SHA-256 digests of args/outputs, not raw content.
- **Deterministic**: Same content → same artifact ID always.
- **Open source**: Verifier is open source at github.com/zerkerlabs/treeship

## Verification

Verify any receipt locally (pure WASM, no network):
```bash
treeship verify art_<id>
treeship package verify .treeship/sessions/ssn_*.treeship
```

Or via web: https://treeship.dev/verify/<artifact-id>

## Resources

- Docs: https://docs.treeship.dev
- Source: https://github.com/zerkerlabs/treeship
- CLI help: `treeship --help`, `treeship <command> --help`
- Trust inventory: https://github.com/zerkerlabs/treeship/blob/main/TREESHIP.md
