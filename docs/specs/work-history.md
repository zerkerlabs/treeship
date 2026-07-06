# Work History: a verifiable track record for agents

**Status:** draft, not implemented
**Pairs with:** [transparency-log](./transparency-log.md), [agent-capability-cards](./agent-capability-cards.md), [capability-provenance](./capability-provenance.md), [agent-resolver](./agent-resolver.md)
**Last updated:** 2026-07-06

## The shift

Treeship can prove that one receipt is real, that one card is key-bound, and that an agent's log was never rewritten. What it cannot do yet is answer the question every counterparty actually asks before trusting an agent with work: **"what has this agent done, how much of it is verifiable, and can I rank it against alternatives without trusting anyone's marketing?"**

That is the work-history surface: every session an agent completes becomes a typed, signed record in its transparency log; the accumulated records are sortable and queryable; and a derived *track record* over them is pinned to the log state it was computed from, so any verifier can recompute it and get the same answer. Identity says who the agent is. Capability says what it claims it can do. Work history says what it has demonstrably done.

The analogy is the credit file, with one upgrade the credit bureau cannot offer: the file is cryptographically recomputable by anyone, from a log that provably was not rewritten.

## The load-bearing invariant

> **Treeship ships the file, never the score.** The Hub stores and serves signed session records and derived profiles; it computes no reputation, assigns no rank, and vouches for nothing. Any consumer computes their own lens over the verifiable substrate, client-side, against their own trust roots. A "score" is a consumer's function; the moment the platform assigns one, it becomes a rating agency and the neutrality of the substrate is gone.

This is "the Hub creates nothing," applied to reputation.

## Honest constraints (state these or the surface over-promises)

- **A track record proves what was recorded, not everything that happened.** An agent that does off-Treeship work has off-the-record history. Completeness holds only for committed sets (the transparency log's `committed_anchor` rule); the output says so.
- **Self-attested volume is a diary, not evidence.** An agent can sign a thousand receipts about itself. Work history does not pretend otherwise: every session record carries its **attestation class** (below), and the class is a signed, verifiable fact about *how* the record was captured. Weighting classes is the consumer's job; labeling them honestly is ours.
- **Derived numbers are claims until recomputed.** A profile ("37 sessions, 0 violations") is graded `asserted` on its own, and upgrades to `checked` only when the verifier recomputes it from the log at the pinned checkpoint and the numbers match. The grade vocabulary is [capability-provenance](./capability-provenance.md)'s, unchanged.
- **No global identity, no Sybil resistance.** Nothing here prevents an operator from minting a fresh agent and abandoning a bad history. What it prevents is *rewriting* a history you have committed to (consistency proofs) and *inflating* one with claims that do not recompute. Fresh-identity discounting is, again, a consumer lens.

## The attestation-class ladder

Every `session.v1` record carries exactly one class, set at capture time, signed into the record:

| class | meaning | example |
|---|---|---|
| `self` | the agent's own receipts, no external signal | CLI attests in an unsupervised loop |
| `runtime` | emitted by a harness hook or bridge the agent cannot forge or omit | Claude Code plugin hooks, `@treeship/mcp` bridge |
| `countersigned` | a second party signed the same canonical bytes | room participant envelopes, handoff receipts, human approval receipts |
| `anchored` | published to a hub, checkpoint-witnessed, consistency-proven | any of the above, after `merkle publish` + third-party `audit` |

Classes compose upward (`anchored` implies the record is also one of the first three; the record carries both facts). The ladder is the [protocol-integration](./protocol-integration.md) provenance discipline pointed at reputation: **label, never launder.** A consumer who ranks a thousand `self` sessions above ten `countersigned` ones does so with open eyes.

## The surface

### The atom: `session.v1` (typed predicate)

Minted by `treeship session close` (opt-out, not opt-in), validated against a registered schema before signing, like every predicate in the registry:

```json
{
  "kind": "treeship/session.v1",
  "actor": "agent://hermes",
  "headline": "Fixed keystore hostname-drift bug, shipped PR #174",
  "outcome": "completed | abandoned | failed",
  "started_at": "…", "closed_at": "…",
  "harness": "claude-code | hermes | openclaw | …",
  "attestation_class": "self | runtime | countersigned | anchored",
  "counts": { "actions": 212, "approvals": 2, "boundary_denials": 0 },
  "tools_exercised": ["Bash(git:*)", "Edit(*)", "…"],
  "receipt_anchor": { "count": 212, "merkle_root": "sha256:…" },
  "report_url": "https://treeship.dev/r/… | null"
}
```

`tools_exercised` is computed from the session's captured receipts (never hand-written), so it feeds capability cards' `exercised` grade directly. `receipt_anchor` commits the record to its underlying receipts the same way a card's `evidence_anchor` does, making per-session omission detectable.

### The accumulation: history (a projection, not a new store)

The agent's work history **is** its transparency log filtered to `session.v1` entries. No new storage, no new trust surface:

```
GET /v1/agents/{agent}/history?sort=closed_at&class=countersigned&limit=…
treeship history agent://hermes [--hub <url>] [--class …] [--since …]
```

The Hub answers from the same metadata+anchor rows the log already serves; the CLI re-verifies each entry's inclusion offline and renders the sortable timeline. Sortable and matchable falls out of the records being *typed*: sort keys and filters are schema fields, not string-scraping.

### The claim: `profile.v1` (derived, pinned, recomputable)

```
treeship profile agent://hermes            # compute + print
treeship attest profile agent://hermes     # compute + sign as a claim
```

A profile is a deterministic aggregation over the history **at a pinned checkpoint**:

```json
{
  "kind": "treeship/profile.v1",
  "agent": "agent://hermes",
  "computed_at_checkpoint": { "tree_size": 2841, "root": "sha256:…" },
  "sessions": { "total": 37, "by_class": { "runtime": 30, "countersigned": 5, "anchored": 2 } },
  "receipts": 4210,
  "tools_exercised": { "Bash(git:*)": 212, "…": 0 },
  "violations": 0,
  "revocations": 0,
  "span": { "first": "2026-03-01…", "last": "2026-07-06…" }
}
```

Verification recomputes the aggregation from the log truncated to `computed_at_checkpoint.tree_size` and compares. Match → the profile grades `checked`. Mismatch → the profile is provably false, and `verify` says which number lies. Because the log carries consistency proofs (shipped, 0.15.0), the history under a pinned profile cannot be silently rewritten after the fact. **This is the anti-drift mechanism: reputation pinned to a Merkle root is falsifiable; reputation that floats is marketing.**

### The query: matching over evidence

```
treeship resolve --hub <url> --exercised "payments.*" [--class countersigned] [--min-sessions N]
```

Find agents whose *evidence* matches the job: the Hub indexes `tools_exercised` and classes from the typed records (metadata it already holds) and returns candidate bundles; the client re-verifies every candidate's records before showing them. Declared capability gets you found; exercised history gets you chosen. This is the honest version of an agent marketplace, and it is deliberately last: it is only as good as the density of records under it.

## Slices

1. **`session.v1` predicate + emit on `session close`.** Register the schema; compute `tools_exercised`, counts, and `receipt_anchor` from the session's own receipts; set `attestation_class` from the capture path (plugin hook → `runtime`, plain CLI → `self`, countersigns present → `countersigned`). Existing session-report users start producing history with zero new commands. Hermes (whose skill already auto-starts sessions and auto-pushes) becomes the first live producer.
2. **`treeship history` + `GET /v1/agents/{agent}/history`.** The sortable, filterable projection; CLI re-verifies inclusion offline. Mirrors `audit`'s plumbing; a rendering change more than a trust change.
3. **`profile.v1`: compute, sign, verify-by-recompute.** The checkpoint-pinned aggregation, `attest profile`, and the recompute path in `verify` (CLI and WASM share the aggregation in `core`, so the browser viewer gives the same verdict).
4. **Matching (`resolve --exercised`).** Hub-side index over typed records + client-side re-verification of candidates. Gated on record density from slices 1–3, not built speculatively.

## What is explicitly out of scope

- **Scores, ranks, badges.** Ship the file, never the score. A reference *lens* (a documented example aggregation) may live in docs, never in the Hub.
- **Cross-agent identity resolution / Sybil defense.** An operator's agents are not linked; see honest constraints.
- **Dispute/endorsement flows.** Countersigning covers "a second party observed this"; anything richer (reviews, arbitration) is a different product and would drag the substrate into content moderation.

## How this lands in the portfolio

The work history is the trust graph's time axis: sessions → history → profile → matching is receipts → projection → claim → query, the same read-model discipline as everything else in the stack. The gateway consults it ("has this agent demonstrably done X before?"), capability cards renew from it (`exercised`-first re-minting), and session reports feed it for free. One substrate, one set of grades, no new trust assumptions.
