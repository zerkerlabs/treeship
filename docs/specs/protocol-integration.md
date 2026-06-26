# Protocol Integration: provable agents by default (MCP, A2A)

**Status:** draft, not implemented
**Pairs with:** [per-actor-signing](./per-actor-signing.md), [agent-capability-cards](./agent-capability-cards.md), [capability-provenance](./capability-provenance.md), [agent-resolver](./agent-resolver.md), `bridges/mcp`, `bridges/a2a`
**Last updated:** 2026-06-25

## The shift

Everything in the [vision](./vision.md) is built: provable identity, capability cards graded by real provenance, revocation, a resolver, a transparency log. It is all reachable from the CLI. The last gap is **reach**: making the agents that already exist, the ones speaking MCP and A2A, emit provable, key-bound receipts and become resolvable **by default**, without their operator hand-running `treeship` commands.

This is distribution, not new cryptography. The cryptographic core is done.

## The good news: the wiring already exists

The bridges already shell out to the CLI and already pass an actor:

- `bridges/mcp/src/attest.ts` calls `treeship attest action --actor <agent>` (and `attest receipt`) for tool calls.
- `bridges/a2a/src/attest.ts` does the same for A2A tasks and handoffs, and `agent-card.ts` already builds an A2A `AgentCard`.

So **per-actor signing flows through them the moment the agent has a registered key.** `attest action --actor agent://x` already signs with the agent's own `AgentCert` key *if that key exists* (we shipped that). Today it does not exist, so the bridge's receipts are signed by the shared ship key and the `actor` is asserted. The integration is therefore not "rewire attestation", it is **provision the agent's identity** so the existing wiring produces provable output.

## What "provable by default" requires

When a bridge starts representing an agent, three things should happen once, automatically:

1. **Register a per-agent key** (`agent register --own-key`) so the agent's receipts are key-bound and its `actor` is `proven`, not asserted. (Per-actor signing, already shipped, does the rest.)
2. **Mint a capability card from the harness** (`attest card --from-harness`) so the agent's declared capabilities are *captured* from its real wired tools (the MCP server's tool list / the A2A AgentCard skills), not hand-typed.
3. **Publish** (`treeship publish`) so the agent is resolvable: anyone can `resolve --hub` it and `audit` its history.

After that, every receipt the bridge emits is provably the agent's, its capabilities are evidence-checkable, and it is resolvable, with zero extra operator action.

## Honest framing

The bridge makes an agent's receipts *provable*; it does not change *what Treeship proves*. Per-actor signing closes intra-workspace actor forgery, not host compromise (a compromised bridge holds the key). Capability cards are consistency over captured evidence, not completeness. The bridge inherits these contracts unchanged and must not imply more, the same discipline carried into every surface.

## Slices

1. **MCP: provision a per-agent key.** ✅ Shipped. On bridge startup, `agent register --own-key --quiet` for the agent it represents. `--own-key` is now idempotent (reuses an existing per-agent key, no pile-up or duplicate AgentCert pins across restarts) and `--quiet` skips the on-disk `.agent` package so nothing lands in the user's working directory. Result: the bridge's existing `attest action --actor` calls became key-bound and `actor`-provable (verify reports `actor proof: proven (key-bound)`) with no change to the attest path. Best-effort: a missing or uninitialized `treeship` is logged and swallowed, the bridge still starts (receipts fall back to the shared key).
2. **Operator-declared capability sets (`attest card --tools-json`).** ✅ Shipped, *revised from the original "auto-capture the bridge's tool list".* The runtime companion to `--from-harness`: an operator supplies an explicit capability list from a JSON file (`["tool", ...]` or `{ "tools": [...] }`), and each entry is stamped `declared` in `capability_provenance` with the file as its `source`. Honest and traceable: the card records *that* these are an operator's claim and *where* it came from, never presented as captured.

   **Why not auto-capture from the bridge** (the original plan): the `@treeship/mcp` bridge is its own MCP server exposing Treeship's *meta-tools* (`treeship_verify`, `treeship_attest_action`, `treeship_session_event`, ...), not the agent's domain tools. Capturing *those* into the agent's card would have Treeship attesting to its own presence, the "named vs. enforced" failure mode, one layer up: the attestation layer attesting to itself. So capture-at-bridge is wrong by construction here, not merely incomplete. The honest move is to let the operator *declare* (labeled as such), not to launder an operator claim into something that looks machine-verified.

3. **A2A: the AgentCard bridge.** ✅ Shipped. `attest card --from-a2a <AgentCard.json>` maps the agent's own published `skills` to `agent_card.v1` capabilities, stamped `discovered` with the AgentCard's `url` as source, a real provenance grade, distinct from `captured` (harness) and `declared` (operator), and weaker than receipt-`exercised`. Protocol-level `capabilities` (streaming, push) are excluded (transport, not domain). `verify-capability` and `resolve` count `discovered` in its own bucket, never lumped into `declared-only`. Separately, the `@treeship/a2a` middleware now provisions its actor's per-agent key on construction (idempotent, best-effort, `provisionAgentKey`), the slice-1 treatment for A2A, so its task/handoff receipts verify as `proven`. Net: an A2A agent's self-description becomes a key-bound, verifiable Treeship card, and its receipts are provably the agent's. A2A's AgentCard carries the agent's *own* declared skills, so it is a legitimate source, distinct from the meta-tools dead end in slice 2.
4. **Deferred: auto-discovery from the agent's own server.** When a bridge fronts an agent that exposes its real domain tools (a transparent proxy, not a meta-tools server), capture them, `treeship_*` excluded, and label the grade `discovered:<protocol>` (e.g. `discovered:mcp`), distinct from both `captured` (harness config) and `declared` (operator). Sourced from the agent's server, never from the bridge's own surface. The convenience layer sits cleanly on top of the declaration primitive once it has a correct source.
5. **ACP / others.** The register-key → declare/discover capabilities → publish pattern generalizes to any protocol whose bridge shells to the CLI.

## Open questions

1. **Key lifecycle in the bridge.** Where does the per-agent key live, in the operator's keystore (so it persists), and how is it rotated? Reuse the existing keystore; rotation reuses card `supersedes`.
2. ~~**Capturing tools per protocol.**~~ Resolved (slice 2): shipped `--tools-json` as the operator-*declared* companion to `--from-harness`. Auto-*discovery* (per-protocol, from the agent's own server) is deferred to slice 4 with its own `discovered:<protocol>` grade, kept distinct from declaration so the source of every capability stays legible.
3. **Where publish points, and publish stays explicit.** Default Hub vs operator-configured; reuse the existing `hub attach` connection; publish is a no-op (with a clear hint) when no hub is attached. **Decision:** `publish` is *not* run on bridge startup. A published card becomes a permanent public artifact a third party treats as ground truth; auto-publishing a claim on every boot is the wrong default. Publishing stays an explicit operator action.

## First slice to build

Slice 1: the MCP bridge registers a per-agent key (`--own-key`) for its agent on setup, idempotently. It is the smallest change with the largest effect, it turns every receipt the MCP bridge already emits from `actor: asserted` into `actor: proven (key-bound)`, with no change to the attestation path, because per-actor signing already does the work once the key exists. It is the cleanest possible demonstration that the whole stack we built reaches real agents.
