# Treeship's trust model as a cyberlogic-style theory (first draft)

**Status:** first draft, by the Treeship authors, *not* cyberlogic experts. Written to
seed a collaboration with SRI CSL ([Cyberlogic]: Shankar & Ruess) and to produce the
predicate language for `present --zk`. The formalization below is deliberately explicit
so it can be *corrected* by people who know the logic; where it is likely wrong or loose,
it says so.
**Pairs with:** [private-verification](./private-verification.md), [registry-topology](./registry-topology.md)
**Last updated:** 2026-07-10

## Why write this

Treeship's verifier already behaves like a proof checker over signed statements: a
counterparty pins some keys it trusts, receives a bundle of signed attestations, and
*derives* a verdict ("this agent is certified under a ship I trust, its card is
key-bound, it is not revoked, it is anchored"). Cyberlogic is the logic for exactly this
shape of reasoning: principals make statements, and trust conclusions are *derivations*
from those statements plus the verifier's trust assumptions. Making the correspondence
formal buys two things:

1. **A mechanized soundness theorem.** The failure class both the 0.19 audit and the ZK
   audit found by hand — *a surface reporting `verified` from attacker-controlled input
   without a backing signature* — becomes a property the verifier is proven never to
   violate, rather than one we hunt for manually.
2. **A predicate language.** The `present --zk` predicates ("action conforms to policy",
   "spend under limit", "certified by some trusted issuer") become formulas with precise
   meaning, so the statement a ZK proof establishes is the same object the trust logic
   reasons about.

## Cyberlogic in one paragraph

In [Cyberlogic], principals make signed assertions and evidence is first-class: the
judgment *K says φ* means principal *K* has attested formula *φ*, and a verifier reasons
forward from the `says` assertions it is willing to trust. It is close in spirit to the
"says" calculus of authentication logics (Lampson–Abadi–Burrows–Plotkin) but with
constructive evidence — a derivation *is* the proof object. Treeship's signed envelopes
are the `says` assertions; the verifier's trust policy is the set of trust assumptions;
the chain walk is proof search. *(SRI: this paragraph is the part most likely to be
imprecise; please correct the reading of `says` and of what counts as evidence.)*

## Principals and the signing primitive

Principals range over: ships (operators) `S`, agents `A`, humans `H`, the hub `Hub`, and
the verifier `V` itself. Keys are principals too (a key `K` is what actually signs).

The one primitive that grounds everything:

    Signed(K, m)     — "the bytes m carry a valid Ed25519 signature under key K"

This is not an assumption; it is *checked* (strict Ed25519 over the DSSE PAE of `m`). We
then read a signed statement as a `says`:

    Signed(K, m) ∧ m conveys φ   ⊢   K says φ

Everything else is derivation from `K says φ` facts plus trust assumptions. Crucially,
`K says φ` is derivable *only* through `Signed(K, ·)` — there is no other introduction
rule. This is the whole safety idea: the logic cannot conclude anyone said anything
without a checked signature.

## Trust assumptions (the verifier's pinned roots)

The verifier's trust store contributes axioms, one per pinned root, scoped by kind
(least privilege, per the 0.19 split):

    Trusts(V, K, cert_issuer)      — V will believe K's agent-certification statements
    Trusts(V, K, hub_checkpoint)   — V will believe K's transparency checkpoints
    Trusts(V, K, revoker)          — V will believe K's revocations
    Trusts(V, K, hub_org)          — V will believe K's global-claim promotions
    Trusts(V, K, session_host)     — V will believe K's session-hosting statements

A root of one kind grants exactly one power; nothing is derivable across kinds.

## The verifier's inference rules (mapped to the code)

Each rule is the logical reading of an actual check in `packages/core/src/verifier`
and `capability`. `⊢` is "the verifier derives".

**Certification (agent_cert.v1, chain to a pinned ship).**

    Trusts(V, S, cert_issuer) ∧ (S says Cert(A, K_A, [t0,t1])) ∧ now ∈ [t0,t1]
      ⊢  KeyOf(A, K_A)

The subject key `K_A` comes only from the ship's signed statement, never from the wire.

**Key-bound card.**

    KeyOf(A, K_A) ∧ (K_A says Card(A, tools_sd))
      ⊢  KeyBound(A, Card)

A card whose signer is not the certified key is `SelfAsserted`, a strictly weaker
judgment that never upgrades to `KeyBound`.

**Mandate conformance (nonce binding).**

    (H says Approval(nonce, scope)) ∧ (K_A says Action(a, approvalNonce = nonce))
      ∧ a ∈ scope
      ⊢  Authorized(A, a)

This is the provable core the private-verification first-principles section names:
possession of a signed mandate plus conformance. `a ∈ scope` is checked, not assumed.

**Revocation (authority required, fail-closed).**

    (K says Revoke(Card)) ∧ (Trusts(V, K, revoker) ∨ K = K_A)
      ⊢  Revoked(Card)

An unauthorized revocation derives nothing (it is ignored, not honored).

**Transparency anchoring.**

    Trusts(V, K, hub_checkpoint) ∧ (K says Checkpoint(root, size))
      ∧ Includes(root, receipt)                       -- Merkle inclusion, re-checked
      ⊢  Anchored(receipt)

**Selective disclosure (capabilities).** With the card committing to `tools_sd`:

    KeyBound(A, Card) ∧ Card carries tools_sd
      ∧ Discloses(A, [salt, t, true]) ∧ digest([salt,t,true]) ∈ tools_sd
      ⊢  HasCapability(A, t)

The verifier learns `HasCapability(A, t)` for exactly the disclosed `t`, and nothing
about the undisclosed digests. This is `core::capability::disclosed_tools` read as a rule.

## The soundness theorem to mechanize

The property that turns manual red-teaming into a theorem:

> **For every judgment the verifier can conclude — `Verified`, `KeyBound`, `Authorized`,
> `Anchored` — every derivation bottoms out in `Signed(K, ·)` facts for keys `K` that are
> either pinned in `Trusts(V, ·, ·)` or transitively certified from a pinned key. There
> is no derivation of any positive judgment whose leaves are all attacker-supplied
> unsigned bytes.**

Contrapositive, which is the bug class: there is no way to reach `Verified` from
wire-controlled input without a checked signature under a trusted (or trust-chained) key.
Each historical audit finding was a *rule that violated this* — a surface that concluded a
positive judgment from an unverified `keyid` string, an unsigned `parent_id`, a
self-referential Merkle recomputation. Mechanizing the theorem makes such a rule
unprovable by construction: it would have a derivation with an ungrounded leaf.

*(This is the deliverable where SRI's formal-methods depth is the point: stating the
theorem precisely and discharging it against the rule set above, ideally in a proof
assistant, is CSL's discipline, not ours.)*

## The `present --zk` predicates as formulas

The ZK layer proves a formula about *withheld* values while revealing nothing. Each
predicate below is a cyberlogic formula; the ZK proof establishes it, the disclosure
layer's salted commitments are the opening of the existential witness.

    -- "I have some capability covering action a", hiding which:
    ∃ t.  HasCapability(A, t) ∧ Covers(t, a)

    -- "spend is under the mandate limit", hiding amount and limit:
    ∃ amt, lim.  Commit(amt) ∈ Card ∧ (H says Limit(lim)) ∧ amt ≤ lim

    -- "certified by some issuer V trusts", hiding which (anonymity):
    ∃ S.  Trusts(V, S, cert_issuer) ∧ (S says Cert(A, K_A, _))

    -- "at least N clean sessions", hiding the sessions:
    (#{ s : Session(A, s) ∧ Class(s) = countersigned ∧ Clean(s) }) ≥ N

The existential is exactly what a ZK proof hides: the verifier learns the formula holds
without learning the witness (`t`, `amt`/`lim`, `S`, the session set). A plain selective
disclosure, by contrast, would reveal the witness. That is the formal statement of the
"prove without revealing" vs "reveal this field" distinction.

## What this draft is for, and next steps

- **For us:** it names the verifier's rules in one place and states the soundness property
  the whole product leans on, so new rules (the ZK ones) are added against a stated
  invariant rather than by feel.
- **For SRI:** it is the concrete artifact to correct. The likely-wrong parts are the
  reading of cyberlogic's `says`/evidence, whether the soundness theorem is best stated as
  a grounding property or a non-interference property, and what a mechanization target
  (proof assistant, model) should be.
- **Next:** turn the four `present --zk` formulas into the shared statement contract that
  targets both the SIEVE IR (a prover) and this logic (a meaning), per the
  private-verification build order.

## References

- **[Cyberlogic]** — Shankar & Ruess, *Cyberlogic*, SRI CSL.
  https://www.csl.sri.com/people/shankar/hcss03.pdf
- Lampson, Abadi, Burrows, Plotkin, *Authentication in Distributed Systems: Theory and
  Practice* — the "says" calculus this draft borrows notation from.
