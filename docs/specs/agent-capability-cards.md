# Agent Capability Cards — design draft

**Status:** draft, not implemented
**Pairs with:** predicate registry (PR #127), `TrustRootKind::AgentCert` (`packages/core/src/trust`)
**Last updated:** 2026-06-23

## The shift

Treeship today proves what an agent *did* (action receipts). It does not yet let an agent prove what it *is* and what it *can do* in a form anyone can verify offline and cross-check against its behavior.

Other ecosystems describe this: A2A Agent Cards, NANDA AgentFacts. They are **unsigned descriptions**. This spec defines the signed version: a typed Treeship predicate, `agent_card.v1`, where a key attests an identity + capability set, and a verifier can check that the card is (a) signed by the key it names and (b) consistent with the agent's actual evidence receipts.

The one-line difference: **they describe an agent; a capability card proves who is making the claim and lets you check the claim against what the agent actually did.**

This is registry Layer 1 (Identity) + Layer 2 (Capability) realized as one signed artifact. The catalog/search/discovery surface is later and out of scope here. The card is the primitive.

## What's already in the box

- **Per-agent Ed25519 keys** and the DSSE/PAE signing path. A card is just another statement that gets signed.
- **`TrustRootKind::AgentCert`** — a ship issues a certificate to one of its agents. This is the existing primitive that binds an agent identity to a key. A capability card references the cert; it does not invent a new identity primitive.
- **Predicate registry (PR #127)** — `kind` → JSON Schema, validated at attest time. `agent_card.v1` is a new registry entry; no new machinery.
- **Evidence receipts** — every `treeship/action/v1` carries `actor` and `meta.tool`. These are what a card gets cross-checked against.

The card composes existing primitives. It introduces no new trust root and no new signature path.

## The predicate: `agent_card.v1`

Carried as the payload of a Treeship receipt with `kind = agent_card.v1`. Registered in the predicate registry, so a malformed card is rejected before signing.

```json
{
  "schema": "agent_card.v1",
  "agent": "agent://clinical-ai",
  "keyid": "key_9f8e7d6c",
  "owner": "human://dr.smith@hospital.org",
  "version": "1.2.0",
  "supersedes": "art_prevcard...",
  "capabilities": {
    "tools": ["file.read", "db.query", "api.call"],
    "models": ["claude-sonnet-4"],
    "model_fingerprint": "sha256:...",
    "can_delegate": true,
    "max_subagents": 3
  },
  "constraints": {
    "data_access": "phi-only",
    "requires_human_approval": true
  },
  "attestations": [
    { "kind": "audit", "ref": "art_auditreceipt...", "by": "human://auditor@firm" }
  ],
  "evidence_anchor": {
    "receipt_count": 1247,
    "latest_receipt_id": "art_f7e6d5c4...",
    "merkle_root": "mroot_a0be5b7f..."
  },
  "policy_ref": "policy://hospital/agent-baseline#v3"
}
```

Required: `schema`, `agent`, `keyid`, `version`, `capabilities`. Everything else optional. `capabilities.tools` is the field the evidence cross-check keys on.

### `evidence_anchor` (optional, recommended)

A commitment to the agent's receipt set at card-mint time: the count, the latest receipt id, and a Merkle root over the set. It is **asserted** (the agent computed it), so it does not change the trust model. But it earns its place twice:

- **Discoverability.** Without it, `verify-capability` has to scan all local receipts to find the ones signed by `keyid`. With it, the verifier knows the expected count and tip and can go straight to the set.
- **Post-hoc omission becomes detectable.** Because the agent committed to a Merkle root over its receipts, a reviewer can later prove a receipt was, or was not, in the committed set. Hiding an inconvenient action after the fact no longer matches the anchor. This is the same "register before you narrate" property as the boundary-proof committed diet, applied to an agent's own evidence.

The anchor strengthens the cross-check without claiming more than it proves: it commits the agent to a set; it does not prove the set is complete.

## The crux: identity binding (this is what makes it *proof*)

A card is only meaningful if the `agent`/`keyid` it names is the key that signed it. That is the whole game.

- **Self-signed card** = "the holder of `key_9f8e7d6c` claims to be `agent://clinical-ai` with these capabilities." The signature proves the *binding* (this key made this claim), not the truthfulness of the capabilities.
- **The actor-forgery gap closes here.** Today `actor` in an action receipt is a free string signed by the shared Treeship key. A capability card signed by the agent's *own* `AgentCert` key, plus actions also signed by that key, gives `actor → key` a cryptographic anchor instead of a label. Verification rule: a card is "key-bound" iff its `keyid` is the key in the envelope signature **and** that key is pinned under `AgentCert`.

This is the single most important property. Without the key binding, a card is just A2A with extra steps.

### Binding strength: both paths, but the distinction is load-bearing

A card can be signed two ways, and the difference is never hidden:

| Signed by | `key-bound` | What it proves about identity |
|---|---|---|
| The agent's **`AgentCert`** key (a ship certified `agent → key`) | **yes** | Strong. A third party (the ship) attested the binding. This closes the actor-forgery gap. |
| A **bare agent key** (self-signed) | **no (self-asserted)** | Weak. The key claims the identity; nothing backs it. Useful for the *capability* axis (the evidence cross-check runs on the key regardless), useless for the *identity* claim. |

The resolution to "allow both vs AgentCert-only": **allow both, but make `key-bound` a first-class field that `verify` always reports, and grant the plain status "verified capability card" only to AgentCert-bound cards.** Self-signed cards return a distinct, weaker status (`self-asserted`), never bare "verified."

Why not AgentCert-only from day one: the root of any certificate chain is self-signed by definition (someone has to be the first ship), and a solo developer has no ship yet. Forbidding self-signed cards forbids the on-ramp. The trap the analysis correctly identified, self-signed cards masquerading as the strong thing, is closed by making the distinction visible and refusing to call a self-asserted card "verified," not by banning the path.

## Proven vs asserted (keep Treeship's line)

| Field | Zone | Why |
|---|---|---|
| `keyid` ↔ envelope signature | **Proven** | The key that signed is the key named. Recomputable. |
| `agent`, `version`, `supersedes` | **Proven** (integrity) | Inside the signed payload; tamper-evident. |
| `capabilities.*`, `constraints.*` | **Asserted** | Anyone can *claim* a tool list. The card records the claim faithfully; it does not prove it. |
| `attestations[]` (audit/compliance) | **Proven only if** the referenced receipt is itself signed by an independent third-party key | A self-signed "I passed HIPAA" is asserted. An auditor-signed `endorsement`/`audit` receipt referencing this card is proven (different key, different incentive). |

The honest framing: a card proves *who claims what*. Truth of the capabilities comes from (a) third-party attestations with independent keys, and (b) the evidence cross-check below.

## The differentiator: cross-referencing evidence

A card declares `capabilities.tools`. The agent's action receipts record `meta.tool` actually used. A verifier can check consistency:

```
treeship verify-capability <card_id>
  -> key-bound: yes (AgentCert) | no (self-asserted)
  -> if evidence_anchor present: confirm the local receipt set matches the
     committed count / tip / merkle_root (omission or backfill is flagged).
  -> for every CAPTURED action receipt signed by card.keyid,
     assert meta.tool matches card.capabilities.tools, where a declared entry
     may be an exact tool (`file.write`) or a glob family (`file.*`).
  -> report: key-bound status, anchor match, in-scope actions,
     out-of-scope actions (capability violations).
```

A **"verified capability card"** = `key-bound: yes` **and** anchor matches (if present) **and** zero capability violations. A self-asserted card with clean evidence returns `self-asserted, consistent`, never bare "verified." This is the thing no descriptor format has: the claim is checkable against behavior, and the binding strength is never blurred.

Glob families (`file.*`, `db.*`) are supported in `capabilities.tools`, practical and low cost.

**Honest limit, stated up front:** this proves *captured* actions are within the declared set. It does **not** prove the agent took no action outside its card, that's the actions-outside-Treeship completeness gap, which no signature can close (Guard's runtime enforcement is the only thing that does). So the claim is "every action we have evidence for is in scope," a consistency check, not a completeness guarantee. Say so in the output.

## Versioning and revocation

- **Versioning:** cards are content-addressed (`art_...`) and chained via `supersedes`. A new card supersedes the old; the chain is the capability history.
- **Revocation:** a signed `agent_card_revocation.v1` (or a superseding card with `status: revoked`) signed by the same key or the issuing ship's `AgentCert` key. A consumer resolving a card checks for a later revocation in the chain. (Revocation predicate is a follow-up, not v1.)

## Boundary discipline (why this stays in Treeship's lane)

- The card **catalogs and proves**. It does not **enforce** a capability set, that is Guard's job (Guard can consume the card + `policy_ref` to block out-of-scope tools at runtime).
- The card does not **decide trust**. The consumer (an orchestrator, a human, Guard) decides whether the declared capabilities + attestations are sufficient. Treeship provides the verifiable inputs.
- No retrieval, no routing, no interception. Passive. This is registry Identity+Capability, nothing more.

## What this deliberately does NOT do

- Does not host a registry/catalog/search. That is a later, separately-scoped surface. The card works fully offline with zero servers.
- Does not enforce capabilities at runtime (Guard).
- Does not prove capability *truth* on its own (needs third-party attestation + evidence cross-check).
- Does not introduce a new identity primitive (reuses `AgentCert`).

## Decisions

1. **Both signing paths, with binding strength load-bearing.** AgentCert-bound = `verified`; self-signed = `self-asserted`, never bare "verified." The distinction is always reported. (See *Binding strength* above.) Resolved.
2. **Glob families in `capabilities.tools`.** Declared entries may be exact (`file.write`) or families (`file.*`). Resolved: yes.
3. **WASM verifier exposes the cross-check.** It is pure over local receipts, so it runs in the browser on the receipt viewer, not just the CLI. Resolved: yes.
4. **`evidence_anchor`** ships in v1 as an optional field (asserted; commits the agent to a receipt set so omission is detectable). Resolved: include it.

## Still open

- **Revocation predicate** (`agent_card_revocation.v1`) shape, and whether it ships in v1 or as a fast-follow. Leaning fast-follow: a card without revocation is still useful, and revocation needs its own resolution semantics (who can revoke, how a consumer discovers it).

## First slice to build

1. Register `agent_card.v1` in the predicate registry (one schema file + one entry). Additive, builds on PR #127.
2. `treeship attest card` to mint a self-signed or AgentCert-signed card.
3. `treeship verify-capability <card_id>` — the evidence cross-check, with the honest "captured, not exhaustive" framing in its output.

Steps 1–2 are a day; step 3 is the differentiator and the part worth getting right.
