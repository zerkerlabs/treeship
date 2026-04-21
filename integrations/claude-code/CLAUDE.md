# Treeship

This project uses Treeship for signed, verifiable session receipts. Treeship records what AI agents do during a coding session and produces cryptographic proofs you can verify offline.

Source: <https://github.com/zerkerlabs/treeship> · Apache 2.0 · npm: `treeship`, `@treeship/mcp`

## What `@treeship/mcp` captures

- Tool call names (e.g. `read_file`, `write_file`, `bash`)
- Arguments and exit codes
- Wall-clock duration per call

## What it does NOT capture

- File contents
- Environment variable values or secrets
- Anything outside the tool-call boundary

## When data leaves this machine

Only when one of these is run explicitly:

- `treeship session report`
- `treeship hub push <artifact>`
- `treeship session close` with `auto_push: true` configured

Otherwise receipts stay in `.treeship/sessions/`.

## Before starting any task

```bash
treeship session start --name "<task description>"
export TREESHIP_MODEL=claude-opus-4-6
```

## During work

Prefix every shell command with `treeship wrap --`:

```bash
treeship wrap -- npm test
treeship wrap -- cargo build
treeship wrap -- git commit -m "fix: description"
```

## When done

```bash
treeship session close \
  --headline "<one sentence summary>" \
  --summary "<what changed and why>" \
  --review "<what to verify>"
treeship session report
```

## Rules

- Always use `treeship wrap -- <command>` for shell commands
- Do not start a new session for sub-tasks -- use the same session
- Write specific headlines and summaries, not generic ones
- Close with a review note pointing out risks and edge cases
