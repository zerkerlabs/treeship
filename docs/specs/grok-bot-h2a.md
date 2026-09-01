# Grok Bot harness: same A2A handshake, chat-native capture

**Status:** draft, not implemented — **harness note**, not the product
**Product spec:** [agent-to-agent-verification](./agent-to-agent-verification.md)
**Pairs with:** [protocol-integration](./protocol-integration.md), [per-actor-signing](./per-actor-signing.md), [agent-capability-cards](./agent-capability-cards.md), [agent-resolver](./agent-resolver.md), `skills/treeship/SKILL.md`, `@treeship/mcp`
**Last updated:** 2026-09-01 (retargeted: A2A is v1; H2A is the same gate with a human)
**Audience:** whoever wires Grok Bot as a Treeship peer (Claude / Codex / A2A servers use the same gate)

## The shift

The product is [agent-to-agent verification](./agent-to-agent-verification.md): fail closed before you act. Claude Code and Codex live in a repo. Grok Bot lives in a **thread**. This file is only how that gate is *captured* when one peer is Grok: the human (or the other agent) never types `curl | sh`; the bot has a terminal.

H2A verbs ("prove you", "receipt this chat") are the same `present` + `--challenge` table when the counterparty is a person. Grok ↔ Claude, Grok ↔ Codex, Grok ↔ Grok is not later. It is the default.

Do not clone pstack. pstack drives the Grok Bot *app* so gardeners can land PRs. Treeship is who is live and what they are allowed to hand you. If Lauren's team later exposes `control-grok.mjs`, wrap that CLI and attach it to the handoff — do not rebuild CDP, and do not wait on it to ship the gate.

## Runtime facts

Verified from <https://docs.x.ai/grok-bot/>, 2026-09-01. These are load-bearing; re-check before building.

| Fact | Quote | Consequence |
|---|---|---|
| Runs on xAI infra | "Each Bot runs on a persistent cloud VM with a browser, filesystem, and terminal." | Not the user's laptop. Nothing about the human's OS matters. |
| Real terminal | "It can use a browser, command line, files, and connected tools." | **The CLI is the confirmed lever.** |
| Durable path | Shared workspace is `/workspace`; "Treat temporary directories, **manually installed packages**, and uncommitted application state as replaceable." | Install *will* be wiped. Idempotent re-provision is mandatory, not polish. |
| One computer per account | "Every Bot on your account uses the same computer." "Files are visible to every Bot." | Identity is account-scoped. |
| No isolation, no vault | "Do not use separate Bots as a security boundary." "Files, browser sessions, and command line credentials on that computer are available across your Bot roster." | Any bot on the roster can sign as our actor. |
| Skills are prose | "a reusable set of instructions"; saved conversationally or by demo recording; invoked by typing `/`. | There is no `SKILL.md` install format to target. |
| Routines exist | Scheduled or event-triggered, requested conversationally. | The re-provision loop has a home. |
| MCP | Overview says "connectors/MCP where available." No config schema, install path, or per-server env var documented anywhere. | **Unverified. Do not design on it.** |

## Why Grok Bot is the first chat-native harness

- The *human* never opens a terminal. The *bot* has one. That distinction is the whole design: capture runs through the CLI the bot already drives, and nobody in the thread types an install line.
- Identity is an account, not a git root. Use `agent://grok` (or `agent://x/<handle>` once Proofmark has the binding). Do not create `.treeship/` in random download folders; the keystore belongs under `/workspace`.
- The lever is the CLI plus `/workspace`. MCP is a *bonus path*, not the plan, until someone confirms a user-supplied MCP server can actually be loaded. Ship the CLI path; add MCP the day it is verified.
- Lauren's post is the distribution channel. A working `/treeship prove` in a Grok Bot thread is the demo. A SKILL.md essay is not.

## What a Grok receipt can and cannot say

The account's computer holds one keystore that every bot on the roster can read, and there is no vault. Therefore:

- **Key-bound:** this account's Grok computer signed it. That is real and verifiable by a stranger.
- **Asserted, always:** *which* bot did it. No actor URI spelling changes this. Do not build per-bot attribution and do not market it.

Print that boundary rather than implying more. `coverage: cli-only, actor: account-scoped` is the honest header.

## Honest framing

Treeship still does not prove the model told the truth. A Grok reply that says "I deployed it" is unsigned prose. The receipt covers **commands that ran through us**, wraps the operator asked for, and the handshake. Coverage must be printed: `cli-only` until Grok Bot gives us native hooks.

A presentation without a challenge is not "prove you." The skill must not call `present` alone and tell the human they verified the live bot.

## Product shape (what the human sees)

Three slash-level moves, no more:

| Human says | What runs | Success looks like |
|---|---|---|
| *(nothing — first tool use)* | `session status`; if no session, `session start` + idempotent `onboard agent://grok --own-key` | Later receipts are `actor proof: proven (key-bound)` |
| `prove you` / `/treeship prove` | `present --challenge <nonce>` printed for the human; human (or their other ship) `verify-presentation --challenge` | `verified (key-bound, …)` / `CHALLENGE FAILED` |
| `receipt this` / `/treeship receipt` | `session close` + `session report` if hub attached, else `package verify` + local path | A URL or a `.treeship` path. Never "trust me." |

CLI stdout is JSON (`--format json`). Grok will paste it. Mixed human banners in the JSON stream are a bug (fixed for `wrap` in 0.25.1; keep that invariant).

## Non-goals (v1)

- Driving Grok Bot's own Electron UI (pstack / Feature Map).
- Requiring a git repo or project-local config.
- Auto-publishing every chat to the Hub.
- Calling this a "verification skill" (collides with Lauren's loop).
- Building a second handshake for chat. Grok ↔ human and Grok ↔ Claude are the same gate.

## Slices

### 1. Skill + MCP that provision Grok without a repo (build this week)

**Done when:** on a Grok Bot cloud VM with nothing installed, the bot can run one bootstrap command that leaves `treeship` on PATH under `/workspace`, a keystore under `/workspace`, and `agent://grok` onboarded `--own-key`. Re-running it after a package wipe restores the same identity rather than minting a second one. A tool call captured after that verifies `proven (key-bound)`.

The wipe case is the test that matters. "Treat manually installed packages as replaceable" means the happy path *is* the recovery path.

Files:

- `integrations/grok-bot/README.md` — the bootstrap command, the `/workspace` layout, and what to paste into a saved Grok skill. Prose, because that is what a Grok skill is.
- The saved-skill text itself: when to call which command, the human verbs, the coverage caveat. No changelog, no cargo, no `wrap -- npm test` as the happy path.
- A routine the human can install: re-run bootstrap on a schedule so a wipe self-heals.

Do not invent a Grok config format, and do not write a `treeship add grok-bot` detect path until a real config file is confirmed to exist.

### 2. `/treeship prove` is a real challenge

**Done when:** the skill/MCP mints a nonce, runs `present --challenge`, and prints **exactly** the one command the human (or their other Treeship) runs. A second present with the same nonce fails. Wrong nonce → `CHALLENGE FAILED`. The skill text forbids presenting without `--challenge` in response to "prove you."

### 3. `/treeship receipt` seals the thread

**Done when:** `session report` if hub attached, else local package path + `package verify` summary including the narrative WARN. Human can say "receipt this" mid-thread; close is explicit, not implicit on every message.

### 3b. Receipt the approvals (build this after 3; highest-value slice on this platform)

Grok Bot already runs an approval system: Auto Review, with "Require Approval" rules that stop matching actions, and Allow once / Deny / Always allow. Approval is required for sending messages, publishing, financial transfers, deletes, and production changes.

That is a human decision being made and then discarded. It is also the one claim on this platform that cannot be a self-report: the human is a second party.

**Done when:** an approved action carries a receipt naming what was approved, by whom, and when, and a denial is recorded as a denial. Reuse the Approval Use Journal. Follow #347's rule exactly -- record the human's answer, and never invent an approver. If the approval event is not observable through any supported surface, the slice is blocked; say so rather than inferring approval from the action having happened.

Why this outranks tool capture: "a human approved this deploy, here is the signed artifact" is stronger and more honest than "a tool ran," and it is the one thing here that grades above `captured`.

### 4. A2A is the default (same bytes as prove-you)

Grok Bot → Claude / Codex / another Grok: `verify-presentation --challenge` before accepting a handoff or inbound task. Proofmark handle binding (`agent://x/<handle>`) is the X-native name, not a substitute for `cert_issuer` + challenge. The skill refuses to treat another agent as trusted without the gate. Implementation lives in [agent-to-agent-verification](./agent-to-agent-verification.md) slice 1 (bridges) + slice 2 (this skill). Do not ship Grok H2A and park A2A.

### 5. Close-loop receipts (only if they give us a CLI)

If Grok Bot or pstack exposes `control-*.mjs doctor` / a test harness, `treeship wrap --` that command and attach the session to `agent://grok`. Until that CLI exists, do not fake close-loop.

## Acceptance (slice 1+2)

From a machine that is not this workspace:

```bash
# on the Grok Bot VM, from a saved skill:
#   bootstrap (idempotent), then a tool call that gets captured
treeship verify last --format json   # actor proof: proven (key-bound)

# simulate the documented package wipe, then re-run bootstrap:
#   same actor, same key, no second identity

# in Grok Bot: "prove you"  -> present --challenge <nonce>
# on a second, isolated ship with cert_issuer pinned:
treeship verify-presentation <file> --challenge <nonce>
```

The stranger's verdict must be stated, not assumed. With no prior pin, a stranger learns the presentation is internally consistent and chains to a root they have not yet decided to trust. That is not "verified." Only a counterparty who has pinned the ship key gets `verified (key-bound, anchored)`.

Fail if any of: asserted actor on captured calls after onboard; present without challenge advertised as proof; skill tells the user to `cargo install treeship-cli`; skill uses `wrap -- npm test` as the first example; bootstrap that is not idempotent across a package wipe; any copy implying per-bot attribution; `session report` publishing without an explicit confirm.

## Open questions (do not block slice 1)

- **Can a user-supplied MCP server be loaded at all?** Undocumented. Ship the CLI path regardless; this only decides whether MCP is added later.
- Can we read an X handle from the VM to set `agent://x/<handle>`? If not, `agent://grok` is the v1 URI.
- Are Auto Review approval events observable to a process on the VM? This gates slice 3b.
- Is there a thread ID a process on the VM can read? If not, `receipt this` seals a time window, not a thread, and must say so.
