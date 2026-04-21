---
name: treeship-report
description: Use when the user asks for "the URL", "a shareable link", "the proof I can send to <someone>", or otherwise wants the current Treeship session published as a session report on treeship.dev.
allowed-tools: Bash
---

# Publish a Treeship session report

The **receipt** is the cryptographic artifact that lives in `.treeship/sessions/` after `treeship session close`. The **session report** is the human-readable page at `treeship.dev/receipt/<id>` that someone else can open in a browser. Publishing the report uploads the receipt to the Treeship hub and returns the URL.

This is the only step that sends data off the user's machine. Until they ask for a report (or have set `auto_push: true` in `.treeship/config.yaml`), every receipt stays local. The receipt is theirs -- publishing is opt-in, per session.

## The publish flow

```bash
# 1. Make sure the session is closed (skips silently if already sealed by SessionEnd)
treeship session close --headline "<headline>" --summary "<summary>" --review "<review>"

# 2. Upload the sealed receipt and print the report URL
treeship session report
```

The URL printed by `treeship session report` is what the user shares. It looks like `https://treeship.dev/receipt/art_f7e6d5c4b3a2`.

## Reinforce: the receipt is theirs

When you hand the URL back to the user, mention that:

- The page contains the receipt and renders the timeline of what happened.
- Anyone they share it with can verify the embedded receipt themselves with `treeship verify <url>`.
- If they want to take the report down, the receipt itself is still on their machine -- the hub copy is convenience, not authority.

This matters because Treeship is local-first. The user owns the source of truth; the hub is a publishing surface, not a custodian.

## When the user wants a report but no upload

Some users do not want anything on a hub. Two options:

1. Hand them the local receipt path (`.treeship/sessions/ssn_<id>.treeship`) -- they can attach the file directly to whatever they're sharing through.
2. Suggest `treeship package export ssn_<id> --bundle out.treeship` if they want a single self-contained file with the certificate and any referenced intents bundled in.

Either path produces a verifiable receipt without ever calling `treeship session report`.
