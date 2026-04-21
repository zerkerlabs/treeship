---
name: treeship-session
description: Use when the user finishes a meaningful unit of work (bug fix, feature, migration, refactor) and you need to close out the current Treeship session with a headline, summary, and review note that captures what actually happened.
allowed-tools: Bash
---

# Treeship session lifecycle

Treeship records every tool call this session into a portable, signed receipt. The receipt is the user's, not ours -- it stays on their machine in `.treeship/sessions/` until they explicitly publish it.

The Treeship Claude Code plugin starts a session automatically when work begins (via the SessionStart hook) and seals it automatically when the session ends (via SessionEnd). You normally don't need to touch the lifecycle commands.

You **do** need to close the session yourself, before SessionEnd fires, when:

- The user finishes a meaningful unit of work and you want the receipt to carry a real headline (not the generic auto-headline).
- The user explicitly asks for "the receipt" / "the proof" / "a session report" / "the verification URL".
- The user is about to share what just happened with a teammate, customer, or reviewer.

## Closing the session

Run, in order:

```bash
treeship session close \
  --headline "<one sentence: what the agent accomplished>" \
  --summary "<2-4 sentences: what changed and why>" \
  --review "<what to verify, edge cases, anything risky>"

treeship session report
```

`treeship session report` prints a session report URL on `treeship.dev`. That URL is the human-readable page containing the cryptographic receipt -- it's what the user shares. Anyone who opens it can verify the embedded receipt themselves with `treeship verify <url>`, no account required.

## Writing good headlines and summaries

The headline shows up in the report's title and in any future search. Treat it like a commit message:

- **Specific, not generic**: "Switch session storage from sqlite to LMDB to fix lock contention" beats "fix database stuff".
- **Past tense**: describes what was done, not what was planned.
- **One sentence**: under ~80 characters if possible.

The summary is for someone reading the report a week later. Cover what changed, why, and any non-obvious decisions.

The review note tells whoever opens the report what to look at first. Risks, edge cases, things you weren't sure about, things you decided to defer -- this is where they go.

## What stays local vs. what gets published

- `treeship session close` seals the receipt locally. Nothing leaves the machine.
- `treeship session report` is the only command that uploads. It produces the shareable URL.
- The user may have configured `auto_push: true` in `.treeship/config.yaml`, in which case `session close` itself publishes. Don't assume either way -- run `report` explicitly when the user wants a URL.

## When NOT to close

- Sub-tasks of the same conversation. Use one session per user-meaningful unit of work, not per agent step.
- The user has not actually finished. Wait for the explicit "ok we're done" / "now let's wrap up" signal.
