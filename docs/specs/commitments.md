# Commitments: proving what an agent promised, and whether it kept it

**Status:** draft. Two pieces have since shipped independently, and
`blocked.v1` is emitted for refused approval mints only. See "What changed
since this was written" below. The general out-of-scope action refusal path and
slices 2-4 are unbuilt.
**Pairs with:** [workflow-declarations](./workflow-declarations.md) (#107, the authorization graph), `boundary.v1`, per-actor signing, the transparency log
**Last updated:** 2026-06-29

## The shift

Treeship today proves **what an agent did**: every action, approval, and handoff is a signed receipt, and the [transparency log](./transparency-log.md) makes the whole history tamper-evident and append-only. That is real, and it shipped in 0.15.0.

But a trace of what happened is, in the words of a sharp critic on the agent-commerce boards, *"a flight recorder with no contract."* It proves the agent wrote a file; it does not prove the agent wrote the file it **promised** to write. The recurring ask from people thinking hard about agent commerce (six protocols, UCP through x402, that prove intent, communication, tooling, checkout, authorization, and settlement, but never execution) is the next layer:

| Layer | Question it answers | Status |
|---|---|---|
| Prove-after (receipts) | What did the agent do? | shipped (0.15.0) |
| Prove-before, authorization ([#107](./workflow-declarations.md)) | What was the agent **allowed** to do? | draft |
| **Commitment (this spec)** | What did the agent **promise**, and did the receipt **satisfy** it? | this spec |

A **commitment** is a signed statement of obligation, made *before* execution: the goal, the allowed actions, the expected outcome, and the failure condition. After execution, `verify` answers the one question the whole thread converged on: **does the receipt satisfy the commitment?**

## The honest contract (state it or this over-promises)

A commitment plus its receipts proves the agent **did what it promised, within what it was allowed**. It does **not** prove:
- that the promise was the *right* promise (that is the requester's judgment), or
- that the outcome is *semantically correct* (the oracle gap: a receipt faithfully attests a tool's output even if the tool returned a lie).

Treeship makes the promise **non-repudiable** and its fulfillment **checkable**. Whether the outcome is *good* is the domain layer's job. The output says so, the same discipline carried through every Treeship surface: report the strength of a claim, never overclaim.

## Two principles the design takes from the field

The agent-commerce discussion independently re-derived Treeship's architecture. Two points are load-bearing here:

1. **Refusals are part of the proof surface.** "A receipt that only records successful settlement is success theater." The action an agent *declined* to take, the tool call it considered and rejected, the checkout it abandoned, are evidence too. So a refusal is a first-class, signed artifact, not the silent absence of a success receipt.
2. **Keep the issuer separated; never flatten into one score.** The obligation is signed by the authority *before* (a `boundary`-class decision). The consequence is signed by the runtime *after* (an action/receipt). The agent's own reasoning is signed by the agent, admissible as testimony, not as evidence. A high "Boundary" with a null "Consequence" reads as *"the agent was allowed to do X and did nothing,"* a distinct outcome, not success and not failure. This maps directly onto per-actor signing (the runtime signs, not the agent) and the existing predicate split.

## What already exists to build on

This is a container over primitives Treeship ships, not new crypto:

| Existing primitive | Role |
|---|---|
| `boundary.v1` predicate | already records `decision` / `outcome` / `policy`, the obligation/boundary receipt. A refusal is a `boundary` with `decision: deny`. |
| `action_in_scope` (`capability/mod.rs`, `statements/action_v2.rs`) | already detects when an action falls outside an approval scope, the refusal trigger. Note: this spec originally named it `check_scope_violation`, which does not exist under that name -- there are two `action_in_scope` functions, one per scope model. |
| Per-actor signing (0.13+) | the runtime signs the refusal/consequence; the agent cannot forge what it never held. |
| Predicate registry | the commitment is a typed predicate (`commitment.v1`), validated at attest time. |
| **`blocked.v1` predicate** | **already exists**, with nine fields (`reason_class`, `refused_kind`, `approver`, `actor`, `irreversibility`, `description`, `quarantine_receipt`, `evidence_digest`, `reevaluate_when`) and a `scope_violation` reason class. `packages/cli/src/commands/attest.rs::record_approval_refusal` emits it when a gate refuses an approval mint. No general runtime path emits it for an attempted out-of-scope action. Slice 1 is therefore *extending the existing emit wiring*, not designing a new predicate. |
| Transparency log + checkpoints | the commitment is checkpoint-anchored, so a verifier can prove it existed **before** the execution trace. |
| Approval Use Journal | a commitment can require approval-use-bound actions; the nonce binding already works. |

## Slices

1. **Signed refusal receipts (the "no-send predicate").** The predicate and one narrow emit path already exist: refused approval mints produce `blocked.v1`. The remaining slice wires the action boundary. When an action would violate an approval scope (`action_in_scope` returns false), the runtime emits a signed `blocked.v1` recording the attempted action, the policy/scope that denied it, the reason, and a null consequence. `verify` surfaces refusals as a distinct, attested outcome, *attempted X, denied by policy Y*, neither a pass nor a fail.
2. **Commitment receipt + satisfaction check.** `treeship commit` signs a `commitment.v1` before execution: `{ goal, allowed_actions, expected_outcome, failure_condition, expires_at, authority }`. After execution, `verify` cross-checks the action receipts against it and reports **satisfied** (the expected outcome is present and in scope), **violated** (an action outside `allowed_actions`, or the failure condition tripped), or **unfulfilled** (the commitment expired or the expected outcome never appeared). The commitment is checkpoint-anchored so its pre-existence is provable.
3. **Commitment/policy hash in the session header.** Hash the active commitment (and policy) set at session start and reference it in every receipt, so an auditor can answer *which version of the rule governed this action*. Small; builds on `policy_ref`.
4. **Compose with the #107 authorization graph.** The commitment names the *obligation* (promised outcome); #107's workflow names the *allowed path* (authorized action set, with `deviation`/`gap`). Together they answer the full question: *was every authorized action taken, the promise kept, and nothing unauthorized done?*

## Outcome predicate: start narrow

`expected_outcome` and `failure_condition` should be **typed and machine-checkable, not prose** (the field's repeated lesson: typed over narrative). Start with a small, bounded vocabulary and grow only on demand:
- a required **receipt kind + count** (e.g. "at least one `memory.write.v1` to subject S"),
- a required **post-state digest** ("the artifact at URI U has content hash H"),
- **caps**: max total cost, max wall-clock, expiry.

A bounded result enum, `satisfied | violated | unfulfilled | refused`, is the public verdict. Prose may explain; it is never the primary record.

## Out of scope (deliberately)

- **The settlement signal (proceed / pause / unwind).** Receipts as *input to an enforcement decision* is the next layer up (Guard). The field is explicit, and so are we: **receipts report state; policy decides settlement; the two must not be the same issuer.** A commitment is the input a Guard decision runs against, so commitments come first; enforcement stays a separate layer on top.
- **Semantic correctness / the oracle.** A receipt + an independent external-state anchor is truth; a receipt alone is not. We bind to anchors (Merkle roots, timestamp attestations) where we can and label the boundary where we cannot.

## First slice to build

Slice 1, signed refusal receipts. It reuses `action_in_scope` and the existing `blocked.v1` predicate, needs no new commitment container, and on day one lets `verify` show the refusals alongside the actions, turning "success theater" into an honest account of what the agent did *and chose not to do*. It is the smallest change that makes the strongest point.

## What changed since this was written

Written 2026-06-29 and reviewed 2026-08-15. Two of its ideas arrived from other
directions, which is worth recording so nobody builds them twice:

- **A narrow `blocked.v1` emit path** shipped for approval-mint gates. `record_approval_refusal` records a signed refusal when the CLI declines to mint an approval. It does not yet cover an attempted action rejected by `action_in_scope`, so slice 1 remains partial rather than absent.
- **"A high Boundary with a null Consequence"** -- the case this spec calls out
  as *"the agent was allowed to do X and did nothing"*, distinct from both
  success and failure -- shipped as `AuthorityUse` (#297). It reports `granted`,
  `exercised`, `dormant` and `out_of_scope` as separate sets, so unused
  authority is visible rather than collapsing into a pass.
- **Binding a promise to its execution** shipped in narrower form for
  action/v2 mandates (#298): `objective_hash` was signed and never compared, so
  a delegated grant could silently change the objective mid-chain. `verify`
  now rejects an objective that changes across a chain
  (`GrantChainError::ObjectiveChanged`) and reconciles a mandate against its
  leaf grant's scope, audience and objective.

Neither is the commitment container this spec describes. Both are the same
insight applied where a signed field already existed and was going unchecked,
and both narrow what slice 2 still has to do.

One correction to the spec's own premises: it lists `check_scope_violation` as
an existing primitive. No such function exists. The real ones are two
`action_in_scope` implementations, one per scope model. A spec that sends an
implementer looking for a function that was never written costs more than one
that admits it needs to find the right entry point.
