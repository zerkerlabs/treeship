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
2. **MCP: mint + publish a capability card from the wired tools.** Build the card from the MCP server's actual tool list via `--from-harness` (captured provenance), then `publish` so the agent resolves. Now an MCP agent is identity + capability + resolvable, automatically.
3. **A2A: the AgentCard bridge.** Map the A2A `AgentCard` (skills, capabilities) to a Treeship `agent_card.v1`, register the per-agent key, and stamp provenance. A2A already has a card concept; this makes it *verifiable* (key-bound + evidence-checked) rather than a descriptor.
4. **ACP / others.** The same three-step pattern (register key → capture card → publish) generalizes to any protocol whose bridge shells to the CLI.

## Open questions

1. **Key lifecycle in the bridge.** Where does the per-agent key live, in the operator's keystore (so it persists), and how is it rotated? Reuse the existing keystore; rotation reuses card `supersedes`.
2. **Capturing tools per protocol.** MCP exposes a tool list at handshake; A2A exposes skills in the AgentCard. `--from-harness` currently reads a Claude Code `settings.json`; it needs a path (or a small adapter) for "tools the bridge already knows at runtime" rather than a config file. Likely a `--tools-json` companion to `--from-harness`.
3. **Where publish points.** Default Hub vs operator-configured. Reuse the existing `hub attach` connection; publish is a no-op (with a clear hint) when no hub is attached.

## First slice to build

Slice 1: the MCP bridge registers a per-agent key (`--own-key`) for its agent on setup, idempotently. It is the smallest change with the largest effect, it turns every receipt the MCP bridge already emits from `actor: asserted` into `actor: proven (key-bound)`, with no change to the attestation path, because per-actor signing already does the work once the key exists. It is the cleanest possible demonstration that the whole stack we built reaches real agents.
