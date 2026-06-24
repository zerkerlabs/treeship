# Transparency Log Surface: Certificate Transparency for agents

**Status:** draft, not implemented
**Pairs with:** [agent-resolver](./agent-resolver.md), the Hub Merkle log, capability cards' `evidence_anchor`
**Last updated:** 2026-06-24

## The shift

Treeship already anchors artifacts in a Merkle log and can verify that one card is *in* the log ([resolver slice 2](./agent-resolver.md)). What it cannot do yet is answer the question Certificate Transparency answers for web certs: **"show me everything this agent has done, and let me confirm nothing was hidden."**

That is the transparency-log surface: an append-only, queryable, monitorable history of an agent's receipts, each provably in the log, with **omission detectable**. It turns "I can verify this one proof you handed me" into "I can audit the whole history myself."

## The load-bearing invariant (unchanged)

> The Hub serves metadata and Merkle anchors. It does not vouch for completeness or content. The client re-verifies every entry's inclusion proof against its own trust roots, and detects omission against the agent's own committed anchor. The Hub being wrong, lying, or gone does not change the client's verdict.

## Honest constraints (state these or the surface over-promises)

- **A log of digests and commitments, not contents.** Each entry is `{ artifact_id, kind, actor, action, timestamp, digest, merkle_anchor }`, never the payload. This is the memory-proof safe-default rule applied to the public surface: prompts, memories, and private content never enter it.
- **Completeness is detectable for committed sets, not absolute.** Treeship cannot prove an agent recorded *everything it ever did*. It can prove that the receipts the agent **committed to** (via a card's `evidence_anchor`: a count, a tip, a Merkle root) are all present and unaltered, so post-hoc omission or backfill of a committed set is visible. Absolute completeness is a runtime-capture property, never a log property. The output says so.
- **Append-only is the Merkle tree's property, not a promise the Hub makes.** A consistency check between two checkpoints (old root is a prefix of new root) is what proves no history was rewritten; that is slice 3.

## The surface

### Query (Hub)

```
GET /v1/agents/{agent}/log?since=<cursor>&limit=<n>
→ {
    "agent": "agent://deployer",
    "entries": [
      { "artifact_id": "art_…", "kind": "action", "actor": "agent://deployer",
        "action": "file.write", "timestamp": "…", "digest": "sha256:…",
        "merkle_anchor": { "checkpoint_index": 42, "leaf_index": 17 } | null },
      …
    ],
    "next_cursor": "…",
    "committed_anchor": { "receipt_count": 120, "merkle_root": "sha256:…" } | null
  }
```

Read-only, unauthenticated (auditing an identity is public). Reuses the receipt scan and `db.GetProof`. `committed_anchor` is the latest `evidence_anchor` off the agent's current card, the number to check observed history against.

### Audit (CLI)

```
treeship audit agent://deployer                       # local store
treeship audit --hub https://api.treeship.dev agent://deployer   # over the network
```

Pulls the history, **re-verifies each anchored entry's Merkle inclusion offline**, prints the timeline, and runs the completeness check: does the observed, anchored receipt set match the agent's `committed_anchor`? Reports `complete (120/120 committed receipts present)` or `OMISSION: committed 120, observed 118`.

## Slices

1. **History query + `treeship audit` (local + remote).** `GET /v1/agents/{agent}/log` returns the metadata+anchor entries; `treeship audit` pulls and renders the timeline, re-verifying each anchored entry's inclusion. The minimum that makes an agent's history auditable by a third party. (Local half mirrors `resolve`'s offline path.)
2. **Completeness check against `committed_anchor`.** Compare the observed anchored set to the agent's committed `evidence_anchor`; flag omission/backfill. This is the property that makes the log *worth* auditing.
3. **Consistency proof (append-only).** Verify that a later checkpoint extends an earlier one (no history rewritten), the true CT property. Reuses the Merkle consistency primitive.
4. **Monitor mode.** `treeship audit --watch` (or a scheduled check) that re-runs completeness/consistency and alerts on divergence, the "monitors catch anomalies" piece of the vision.

## Open questions

1. **Cursoring at scale.** A busy agent has thousands of receipts; the query needs a stable cursor (by `signed_at` + `artifact_id`) and the Hub needs the receipt scan indexed by actor (today it is a full scan, fine for slice 1, an index is the scale follow-up).
2. **What "the agent's history" means across machines.** Receipts an agent signs on machine A vs B are distinct sets; the log is per-Hub. Cross-machine aggregation is a resolver-naming question, deferred with it.
3. **Privacy of the actor graph.** Even metadata (who handed off to whom, when) is information. The surface should expose only what the operator published; nothing is in the log that was not explicitly pushed (`treeship publish` / `hub push`).

## First slice to build

Slice 1: `GET /v1/agents/{agent}/log` + `treeship audit`, returning the metadata+anchor timeline and re-verifying each anchored entry's inclusion client-side. It is additive, reuses the resolver's scan + the Merkle verify we already ship, and on day one turns "verify this one proof" into "audit the whole history," with the honest "digests not contents, committed-set not absolute" framing built into the output.
