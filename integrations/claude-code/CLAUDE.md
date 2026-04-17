# Treeship

This project uses Treeship for signed, verifiable session receipts.

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
