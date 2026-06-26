# Treeship Vision & Roadmap

**Status:** living document, the source of truth for "what's next"
**Last updated:** 2026-06-24

This file exists so the plan is *captured*, not re-derived each session. The thesis, what is shipped, and what is next all live here. Per-feature design lives in the linked specs; this is the map above them.

## The thesis: TLS for the agentic web

TLS answered "how do I know this website is who it claims to be?" Treeship answers the same for agents: **how do I know this agent is who it claims to be, that it is authorized to do what it is doing, and that what it did actually happened?** Every action, approval, handoff, and capability claim becomes a cryptographically signed artifact that verifies offline, against no infrastructure.

The discipline that makes this real, and distinguishes Treeship from a registry of claims, is one rule applied everywhere: **report provenance, never assume it.** Every fact carries how it is known, `captured` (the machine observed it), `checked` (a claim cross-verified against captured evidence), or `asserted` (a bare claim, labeled, never trusted silently). Identity, capability, behavior, and resolution all carry their grade.

## Shipped (live in 0.13.0 and after)

| Layer | TLS analogue | Status | Spec |
|---|---|---|---|
| Capability cards (`agent_card.v1`) | the certificate | ✅ | [agent-capability-cards](./agent-capability-cards.md) |
| Per-actor signing (provable `actor`) | the key binding | ✅ | [per-actor-signing](./per-actor-signing.md) |
| Revocation (`agent_card_revocation.v1`) | OCSP | ✅ | agent-capability-cards |
| Capability provenance (captured/exercised/discovered/declared) | mis-issuance control | ✅ | [capability-provenance](./capability-provenance.md) |
| Predicate registry (typed receipts) | — | ✅ | — |
| Browser verification (WASM, same verdict as CLI) | the lock icon | ✅ | — |
| Agent resolver (local + Hub + remote + transparency anchor + publish) | DNS + OCSP + CT lookup | ✅ | [agent-resolver](./agent-resolver.md) |
| Protocol integration (MCP + A2A bridges: provable receipts, `--from-a2a` cards) | TLS in the browser/server | ✅ | [protocol-integration](./protocol-integration.md) |

The core "TLS for agents" stack is functionally complete: an agent has a provable identity, a capability card graded by real provenance, revocation, and resolves over the network with offline re-verification including a transparency anchor. The load-bearing invariant throughout: **the Hub creates nothing; the client re-verifies every byte against its own trust roots and decides.**

## Frontiers

These are the next big chunks, from the original TLS-for-agents vision. Each gets a spec before any code, the same rhythm that produced the shipped work.

### 1. Transparency-log surface (Certificate Transparency for agents) — mostly shipped (0.14.0)

The queryable surface is live: `GET /v1/agents/log` + `treeship audit` give an append-only, monitorable history a third party can audit, with **omission detectable** against the agent's `evidence_anchor`, and `audit --watch` for continuous monitoring. The Merkle **consistency-proof primitive** (append-only, no-rewrite guarantee) is built and test-gated in `core`. Remaining: the slice-3 *plumbing* (Hub consistency endpoint + `audit` checkpoint-witnessing) on top of the primitive. Specs: [transparency-log](./transparency-log.md), [merkle-consistency](./merkle-consistency.md).

### 2. Protocol integration (the distribution flywheel) — shipped (slices 1–3)

Provision a per-agent identity inside the protocols real agents already speak so they emit provable, key-bound receipts **by default**. Shipped:
- **MCP** (slice 1): the `@treeship/mcp` bridge provisions a per-agent key on startup, so its receipts verify as `proven (key-bound)`, not `asserted`. The bridges already shell `--actor`, so per-actor signing flowed through the moment the key existed, provisioning, not rewiring.
- **Capability declaration** (slice 2): `attest card --tools-json`, an operator's explicit, honestly-labeled `declared` capability set. Deliberately *not* auto-captured from the MCP bridge, whose tools are Treeship's own meta-tools; capturing those would be the attestation layer attesting to itself.
- **A2A** (slice 3): `attest card --from-a2a` maps an agent's own `AgentCard.skills` to a key-bound, verifiable card with the new `discovered` grade; the `@treeship/a2a` middleware provisions its key too.

The provenance vocabulary is now coherent end to end: `captured` (harness) > `exercised` (receipts) > `discovered` (the agent's own descriptor) > `declared` (a bare assertion), each labeled, none laundered. **Deferred** (gated on demand, vocabulary already in place): slice 4 auto-discovery from an agent's *own* tool server (the transparent-proxy case, `discovered:<protocol>`), and slice 5 ACP/others. Publishing stays an explicit operator action, never on bridge startup. Spec: [protocol-integration](./protocol-integration.md).

## What is explicitly out of scope (for now)

- **Hosted registry / global naming**: the resolver works; global collision-free naming (ship-namespacing or DNS-delegation) is gated on a real buyer, not built speculatively.
- **Runtime enforcement**: Treeship proves; it does not block at runtime. Confinement is a separate layer's job (Guard). Provenance grades, never gates.
- **Standards / regulatory** (IETF, W3C, EU AI Act): pull, not push. Pursue once adoption creates demand, not before.

## How we work

1. A frontier becomes a **spec** in `docs/specs/` first; it lists slices and the load-bearing invariant.
2. Slices ship one PR at a time, each with its own `CHANGELOG.md` entry and, for user-facing features, a docs page.
3. The honest contract holds in every surface: report the strength of a claim, never overclaim.
