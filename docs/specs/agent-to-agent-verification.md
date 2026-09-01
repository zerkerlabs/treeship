# Agent-to-agent verification

**Status:** draft — protocol exists; default-on enforcement does not
**Pairs with:** [protocol-integration](./protocol-integration.md), [per-actor-signing](./per-actor-signing.md), [agent-capability-cards](./agent-capability-cards.md), [agent-resolver](./agent-resolver.md), [agent-invitations-rooms](./agent-invitations-rooms.md), `docs/content/docs/concepts/agent-handshake.mdx`, `@treeship/a2a`, `@treeship/mcp`
**Implementation (Grok first, adapter for others):** [grok-bot-a2a](./grok-bot-a2a.md)
**Harness note (H2A verbs only):** [grok-bot-h2a](./grok-bot-h2a.md)
**Last updated:** 2026-09-01

## The shift

Treeship's design was never "a human checks a receipt URL." The TLS analogy is **two parties who have never met**, each with their own trust roots, no registry in the loop. That is agent → agent. Human → agent is the same handshake when one party is a person.

What is shipped today: `onboard`, `present`, `verify-presentation --challenge`, `attest handoff`, `@treeship/a2a` injecting receipt URLs, per-agent keys on the bridges. What is **not** shipped: refusing to *do the work* until the handshake passes. A2A today attests after the fact. The value prop is **fail closed before you act**.

## What A2A verification is

An inbound task, handoff, or tool call from another agent is accepted only if all of these hold on **this** machine, against **this** ship's pins:

| Check | Command / path | Fail closed means |
|---|---|---|
| Pin | `trust add --kind cert_issuer` (the other ship, not their leaf) | Unknown issuer → do not run |
| Presentation | `verify-presentation` | Bad chain / revoked card → do not run |
| Live | `--challenge <nonce>` you minted | Replay of a stolen file → `CHALLENGE FAILED`, do not run |
| Freshness | `--max-staple-age` | `STALE` → do not run (or run only if policy says so) |
| Mandate | handoff / grant names you as `--to` | Work for someone else → do not run |

Then you act, and you emit your own receipts + a handoff onward. The next agent repeats this. That is the product.

Human → Claude / Codex / Grok Bot is this table with the human minting the nonce. Do not invent a second protocol for people.

## What it is not

- **Lauren / pstack.** She closes a loop inside one team's app (`/control-app`, screenshots, Feature Map). That is how you *build* Grok Bot. A2A is how Grok Bot and Claude decide the other is real. Compose later: wrap `/control-app` and attach that session to the handoff. Do not wait on her CLI to ship A2A.
- **A receipt URL in A2A metadata.** `@treeship/a2a` already injects `treeship_receipt_url`. Fetching a URL and calling it verified is structural at best (known hub limitation). The receiver must `verify-presentation --challenge` locally.
- **`actor: agent://x` on a wrap.** That string is asserted until onboard + AgentCert. A2A without `proven (key-bound)` is a story, not a handshake.

## Default policy (the product)

Bridges (`@treeship/mcp`, `@treeship/a2a`) and harness skills (Claude, Codex, Grok Bot, Hermes) **must not execute inbound foreign work** unless `verify-presentation --challenge` exits 0. Local work the human started in this thread is not foreign. A handoff, an A2A task, an MCP call that arrived with another agent's card — that is foreign.

Opt-out is explicit: `TREESHIP_A2A_UNVERIFIED=1` (or `--allow-unverified`) and the receipt of the action records that the gate was skipped. Silent skip is a bug.

## Harnesses are peers, not the product

Same gate, different capture:

| Host | How the other agent shows up | What we attach |
|---|---|---|
| Claude Code | Plugin / MCP / slash | `agent://claude` (or project name), onboard on first session |
| Codex | Skill + MCP | `agent://codex` |
| Grok Bot | MCP + skill; thread-native, global ship | `agent://grok` or `agent://x/<handle>` |
| A2A server | Task + AgentCard | `attest card --from-a2a`; existing `@treeship/a2a` |
| Hermes / Cursor / OpenClaw | Already have skills | Flip the gate on; do not rewrite crypto |

Grok Bot is still the demo surface (X, Proofmark, Lauren's audience). It is not a different verification model.

## Slices

### 1. Fail closed in the bridges (this is v1)

**Done when:** `@treeship/a2a` inbound task path and `@treeship/mcp` path that accepts a foreign presentation both:

1. Mint a nonce.
2. Require `present --challenge` (or the presentation bytes + challenge response) from the caller.
3. `verify-presentation --challenge` against local trust roots.
4. Exit / return an error the calling agent can read (`CHALLENGE FAILED`, `STALE`, `untrusted issuer`) and **do not** run the task.
5. On success, run the task, attest as today, include the presentation artifact id as parent.

No new cryptography. Wire the commands that already exist.

Acceptance: two isolated ships, A and B. B has A's `cert_issuer` pinned. A hands B a presentation without a matching challenge → B refuses. A completes challenge → B runs and B's wrap/attest verifies `proven`. Replay of the same presentation+nonce → refuse.

### 2. Skills teach the gate (Claude, Codex, Grok Bot)

Each skill: if the user (or another agent) asks you to take work from `agent://…`, you do not start until slice 1 succeeds. Print the one command the *other* agent must run. Grok skill stays chat-native (`prove you` is H2A; `take this from agent://claude` is A2A). Same MCP tools.

### 3. Handoff is the A2A object

`attest handoff --from --to --artifacts` must name the presentation and the challenge nonce (or the verify-presentation artifact). A handoff without a live verify is `asserted` custody, and `verify` says so. Docs already describe agent-to-agent handoff; the CLI must make the weak form visible.

### 4. Close-loop as evidence on the handoff (optional)

If the sender ran a host verify CLI (pstack `/control-app`, `npm test`, Grok `doctor`), `wrap` that run and pass the session/package id in the handoff. Receiver may require it as policy. Not required for slice 1.

## Non-goals

- Rebuilding CDP / Feature Maps / `/swarm` / cloud-agent orchestration.
- A registry in the handshake (Hub is optional transport).
- Treating Proofmark "founding" or an X handle as a substitute for `cert_issuer` + challenge.
- Enforcing `invitation_authority` on rooms (still recorded, not enforced — do not pretend).

## Honest leftover

Slice 1 does not prove the sender's *task result* is true. It proves who is live, what card they hold, and that this ship chose to trust their issuer. Ground truth of the work is still wrap/session on each side. A2A verification is identity + mandate + liveness. That is the Treeship value prop. Do not sell it as Lauren's "keep going until the UI is green."
