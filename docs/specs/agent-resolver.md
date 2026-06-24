# Agent Resolver: the Hub as DNS + OCSP for agents

**Status:** draft, not implemented
**Pairs with:** [per-actor signing](./per-actor-signing.md), [agent capability cards](./agent-capability-cards.md), the Hub Merkle log, `agent_card_revocation.v1`
**Last updated:** 2026-06-24

## The shift

Treeship can already, locally, give an agent a key, a signed capability card, a provable `actor`, and a revocation, all verifiable offline. What it cannot do yet is let a third party who holds nothing but an agent identifier **find** that agent's current key, card, and revocation status, and trust the answer without trusting the server that returned it.

That lookup is what DNS + OCSP are to TLS. This spec adds it: a resolver that turns `agent://alpha` into a verifiable bundle, built entirely on top of artifacts that were created and signed locally.

## The load-bearing invariant

> **The Hub creates nothing. It resolves and caches locally-created, locally-signed artifacts, and every artifact it returns re-verifies offline against its signature, its trust roots, and the transparency log. If the Hub is wrong, lying, or gone, the client still reaches the correct verdict from the bytes alone.**

Everything below is subordinate to this. The resolver is a convenience over portable proof, never a source of truth. Local-first and offline verification do not change. A resolution the client cannot independently re-verify is a bug, not a feature.

## Three planes

1. **Local plane (unchanged).** `treeship init` mints the keypair; hooks capture receipts; `attest card` mints capability cards; everything verifies offline. This is the deterministic-capture engine. Untouched.
2. **Resolver plane (new).** Publish and resolve. An agent publishes its identity certificate, current capability card, and any revocation to the Hub. Anyone resolves the agent URI to the current verifiable bundle. This is the global, by-URI form of the existing ship-scoped `GET /v1/ship/agents`.
3. **Transparency plane (exists, extended).** The Merkle log (`/v1/merkle/*`) is the Certificate-Transparency analogue. Resolution returns a transparency anchor so a resolved card is provably *in the log*, not merely asserted by the Hub.

## Provenance grades: deterministic capture, not "the model told me"

Every fact the resolver returns carries a grade. This is the property that separates Treeship from a registry of claims.

| Grade | Meaning | Source in code |
|---|---|---|
| **captured** | The machine observed it; no human or model in the loop. | keypair at `init`, hook-captured action receipts, harness-detected tool wiring (discovery reads the actual MCP / settings config) |
| **checked** | A claim, cross-verified against captured evidence. | a capability card's `tools`, confirmed by `verify-capability` against real receipts |
| **asserted** | A bare claim with nothing behind it. Labeled, never trusted silently. | a self-signed card, an `actor` label on a shared key |

The resolver returns the grade alongside the data. A caller never receives "agent X can do Y" without also receiving *how that is known*: captured, checked, or merely asserted. This is the network-layer continuation of `key-bound` vs `self-asserted` and `actor proof: proven` vs `asserted`.

### Closing the "LLM-told" gap on capabilities

Today `treeship attest card --tools file.*` is operator-declared, the weak, asserted grade. Discovery already reads what tools an agent actually has wired into its harness. A capability card should record the **provenance of each declared capability**: captured from the harness config, or operator-declared. A *strong* card is `declared ∩ captured-from-harness`, and resolution surfaces that split. Capabilities then get verifiably created from observed wiring, not self-report. (Schema follow-up: an optional `capability_provenance` block on `agent_card.v1`.)

## The resolver

### Endpoint

```
GET /v1/agents/{agent}
→ {
    "agent": "agent://alpha",
    "identity_cert": { ... },          // the AgentCertificate (or null)
    "current_card":  { ... },          // the latest non-revoked agent_card.v1 envelope
    "revocation":    { "status": "active" | "revoked", "by": "...", "at": "..." },
    "transparency":  { "merkle_root": "...", "checkpoint_index": N, "inclusion_proof": [...] },
    "provenance": {
      "key":          "captured",      // key-bound under AgentCert
      "capabilities": "checked",       // verify-capability passed against captured receipts
      "behavior":     { "receipts_observed": N, "out_of_scope": M }
    }
  }
```

Resolution is read-only and unauthenticated (resolving an identity is a public act, like a DNS query). It composes existing surfaces: artifact pull, the revocation scan, the Merkle proof endpoints. The existing `GET /v1/ship/agents` stays as the ship-scoped owner view; this is the global by-URI lookup.

### CLI

```
treeship resolve agent://alpha
```

Pulls the bundle, **re-verifies every artifact offline** (signature, trust roots, revocation authorization, Merkle inclusion), and prints the verdict with its provenance grade. The exit code reflects the local re-verification, not the Hub's word. `--json` emits the bundle. A resolver that disagrees with local re-verification is reported as a Hub fault, never silently trusted.

## What the Hub does not become

- **Not a certificate authority.** Identity still bottoms out in the local keypair and `AgentCert` / `Ship` trust roots. The Hub indexes; it does not bless.
- **Not a gate.** The resolver answers "who is this and what is known about it." It does not authorize actions at runtime; that is enforcement, a separate layer.
- **Not a source of truth.** Every byte it serves was signed elsewhere and re-verifies elsewhere. The Hub is a fast, convenient cache of portable proof.

## Slices

1. **`treeship resolve <agent>` + `GET /v1/agents/{agent}`** returning identity, current card, revocation status, and provenance grades, with mandatory client-side re-verification. The minimum that turns an identifier into a re-verifiable bundle.
2. **Transparency anchor in the bundle**: include the Merkle inclusion proof so the resolved card is provably logged, and have `treeship resolve` re-check it offline.
3. **`capability_provenance` on `agent_card.v1`**: record captured-from-harness vs operator-declared per capability; surface the split in resolution and in `verify-capability`.
4. **Publish flow**: `treeship agent publish` to push the identity cert + current card + revocations as a resolvable set (today these are individual `hub push`es).

## Open questions

1. **Naming and uniqueness.** `agent://alpha` is currently workspace-local. Global resolution needs a collision story: namespacing under the ship (`agent://<ship_id>/alpha`), or a claim-on-first-publish model. DNS-like delegation is the eventual shape; pick the minimum that avoids squatting.
2. **Freshness vs revocation.** OCSP-style: how stale may a resolved bundle be before a client must re-fetch revocation? Propose a short TTL on the revocation field plus an explicit `--fresh` that forces a revocation re-check.
3. **Privacy of the transparency plane.** A public "what has agent X done" view must remain a log of digests and commitments, not contents, consistent with the memory-proof safe-default rule. The resolver returns anchors and counts, never payloads.
4. **Multiple cards.** An agent may hold several non-revoked cards (different capability scopes). Resolution returns the set; `verify-capability` already evaluates one at a time.

## First slice to build

Slice 1: `treeship resolve <agent>` + `GET /v1/agents/{agent}`, returning the identity, the current card, the revocation status, and the provenance grades, with the client re-verifying everything offline. It is self-contained, it creates no new cryptography, and it makes the local-first invariant concrete on day one: the resolver hands you bytes, and your machine, not the Hub, decides whether to believe them.
