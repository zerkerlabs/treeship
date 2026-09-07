# treeship-commerce (Claude Code plugin)

One command and one skill for adding Treeship receipts to a shopping or merchant agent built on
[anthropics/commerce-agents](https://github.com/anthropics/commerce-agents). It mirrors the
reference's own `commerce-builder` plugin: the command reads your project (and the reference, when
it needs it) while it runs, and writes what it decided to the `## Commerce agent decision record`
in your `CLAUDE.md`. The plugin runs no code of its own; the receipts are written by the
`treeship-commerce` package it wires in.

## Install

```bash
claude plugin marketplace add zerkerlabs/treeship
claude plugin install treeship-commerce@treeship
```

## Command

| Command | Does |
|---|---|
| [`/add-treeship-receipts [shopping \| merchant \| both]`](commands/add-treeship-receipts.md) | Wraps the one executor every tool call passes through on your runtime; for a merchant agent, makes the operator's approval a signed single-use grant on its approval surface; for a shopping agent, signs the cart at checkout hand-off and adds the host's order receipt; adds the verify step to CI |

## Skill

| Skill | Rules for |
|---|---|
| [`treeship-commerce-receipts`](skills/treeship-commerce-receipts/SKILL.md) | What each receipt carries and never carries, the three seams, the approval scope and replay refusal, per-runtime differences, and what a receipt does not prove |

Docs: [treeship.dev/commerce/commerce-agents](https://treeship.dev/commerce/commerce-agents). Package: `pip install treeship-sdk treeship-commerce`.
