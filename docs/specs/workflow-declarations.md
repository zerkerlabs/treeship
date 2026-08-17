# Workflow declarations: proving the allowed path

**Status:** design, golden report fixtures written; no verifier or mint command yet
**Pairs with:** [commitments](./commitments.md), [agent-invitations-rooms](./agent-invitations-rooms.md), `action/v2`, approval-use binding, Merkle consistency
**Last updated:** 2026-08-17

## The question

Treeship proves what captured actions occurred and whether individual actions were authorized. It does not yet answer a workflow-level question:

> Did the observed run follow the path that an authority declared before execution?

A commitment names the promised outcome. A workflow declaration names the allowed path. They remain separate because an agent can follow an allowed path without fulfilling its promise, or fulfill a promise after deviating from the allowed path.

## Load-bearing invariant

> **A graph database may be a disposable query index, never the authority.**

The authority is a signed `workflow.v1` declaration plus signed receipts, checkpoint inclusion, and consistency proofs. Any graph view is a deterministic projection over those portable objects. Treeship does not require or ship a graph database.

Treeship is the proof layer for workflows, not an orchestrator. LangGraph, Temporal, Claude Code, gstack, MCP, A2A, and other runtimes continue to execute work. Treeship verifies the evidence they produce.

## Three graphs, three jobs

1. **Declared graph.** What an authority allowed before execution: nodes, edges, and bounded loops.
2. **Observed graph.** What the available evidence says happened during one run. Reconstructed from attempts and receipts, not trusted from a runtime's narrative.
3. **Evidence graph.** Why each observed node and transition is believed: signatures, parent links, approval uses, handoffs, artifact references, checkpoint inclusion, and trust roots.

The declared graph is immutable once signed. A changed workflow is a new artifact. The observed graph uses repeated attempts with explicit iteration numbers. It never mutates the declared graph or turns a loop into a parent cycle.

## Honest contract

Workflow verification proves only what its evidence supports:

- It can check that a signed declaration existed earlier in the same append-only log than the run evidence.
- It can check that observed, signed actions fit declared nodes, tools, actors, capabilities, edges, and loop limits.
- It can identify a declared step for which the run supplies no evidence.
- It cannot prove an uncaptured action never happened.
- It cannot infer semantic success from a tool's self-reported success.
- It cannot upgrade an adapter's transition claim merely because the adapter signed it.
- It does not enforce the workflow. Guard or the runtime may use this declaration for enforcement, but Treeship reports conformance after the fact.

A clean report means: every action in the evidence set fit the declaration, no required evidence was missing, and declared limits held. It does not mean the evidence set is absolutely complete.

## Report first

The golden fixtures in [`fixtures/workflow-conformance/`](./fixtures/workflow-conformance/) define the first report contract before implementation:

| Fixture | Required result |
|---|---|
| `valid.json` | a complete checked path has no deviation, gap, or exceeded limit |
| `deviation.json` | `inspect -> qa` is an undeclared-edge **deviation** |
| `gap.json` | a completed run with no required terminal has a **gap** |
| `loop-cap.json` | three back-edge traversals exceed a limit of two |
| `asserted-edge.json` | a path touching adapter-only evidence grades `asserted`, not `checked` |
| `not-preexisting.json` | signed timestamps alone grade pre-existence `asserted` |
| `authority-deviation.json` | a tool outside its node's allowed set is an authority deviation |

These are design fixtures, not cryptographic vectors. Their `art_*` and `chk_*` values are readable placeholders. Implementation tests must construct and verify real envelopes and checkpoints rather than treating these placeholder IDs as proof.

## Minimal `workflow.v1`

`workflow.v1` is a registered predicate carried by the existing signed `receipt.v1` envelope. This reuses predicate validation, DSSE signing, artifact IDs, storage, and Merkle publication. It does not introduce another signature format.

```json
{
  "kind": "workflow.v1",
  "schema_version": "1",
  "workflow_id": "claude-gstack-qa",
  "authority": "human://operator",
  "entry_node": "inspect",
  "terminal_nodes": ["finish"],
  "nodes": [
    {
      "id": "inspect",
      "executor": { "actor": "agent://claude-code" },
      "allowed_tools": ["Read", "Grep"]
    },
    {
      "id": "qa",
      "executor": { "capability": "qa.browser" },
      "allowed_tools": ["gstack.qa"]
    }
  ],
  "edges": [
    { "from": "inspect", "to": "qa", "when": "always" },
    { "from": "qa", "to": "finish", "when": "on_pass" },
    { "from": "qa", "to": "inspect", "when": "on_fail" }
  ],
  "loops": [
    {
      "id": "repair",
      "back_edge": { "from": "qa", "to": "inspect" },
      "max_iterations": 2,
      "budget": { "max_actions": 30 }
    }
  ]
}
```

Only fields the first verifier checks belong in v1.

### Nodes

- `id` is unique and non-empty.
- `executor` contains exactly one of `actor` or `capability`.
- `allowed_tools` is the closed tool set for evidence attributed to that node. Existing Treeship wildcard matching may be reused; no second matching language is introduced.

Input/output schemas, redaction rules, retry policy, idempotency, and generalized effect constraints are deferred. They enter a later version only with a verifier fixture that needs them.

### Edges

- `from` and `to` name declared nodes.
- `when` is one of `always | on_pass | on_fail | on_refused`.
- Arbitrary expressions are not accepted in v1. A condition the verifier cannot independently evaluate does not belong in a conformance declaration.

### Entry and terminals

`entry_node` and `terminal_nodes` are required. Without them, the verifier cannot distinguish an intentionally partial run from a completed run missing its beginning or end. A completed run that does not end at a permitted terminal reports a gap.

### Loops

A loop names one declared back edge. `max_iterations` counts verified traversals of that back edge, not an adapter's claimed iteration number. `budget.max_actions` counts captured signed actions attributed to attempts in that loop.

V1 does not use cyclic parent relationships. Agent parentage remains a hierarchy. Repeated work creates a new attempt carrying `{ node_id, attempt, iteration }`.

## Declaration pre-existence

A workflow hash identifies content but proves no ordering. A signed timestamp is also only the signer's assertion.

Pre-existence grades `checked` only when the verifier can establish all of the following:

1. The signed workflow artifact is included in checkpoint of tree size `N`.
2. The first run artifact is included at zero-based leaf index `>= N` in a later checkpoint.
3. A valid consistency proof shows that the later checkpoint extends the declaration checkpoint.
4. Both checkpoint signatures satisfy the verifier's own trust roots.

This proves log order, not trusted wall-clock time. Without that chain, the declaration may still be signed and useful, but pre-existence grades `asserted`.

## Deriving the observed path

The verifier orders node attempts from cryptographically checked causal evidence where possible. It derives each transition between consecutive attempts. It does not need an `edge_taken.v1` statement in the first slice.

Useful evidence includes:

- signed parent artifact links,
- approval grant and use binding,
- signed handoffs,
- artifact references,
- key-bound action receipts,
- evaluator receipts,
- Merkle order under trusted checkpoints.

A session event or adapter statement may help group evidence into an attempt, but it does not become stronger merely by naming a node or edge.

## Edge and path provenance

Each derived edge inherits the weakest grade of the evidence needed to establish it:

| Grade | Meaning |
|---|---|
| `checked` | The verifier reconstructed the transition from signed, bound evidence and its trust policy accepted the relevant keys. |
| `captured` | A configured runtime hook observed the transition, but no independent binding lets the verifier recompute it. |
| `asserted` | The runtime or adapter reported the transition without supporting captured evidence. |

The path grade is the weakest edge grade. A valid declared edge supported only by an adapter claim is therefore `asserted`, never bare "verified".

"Signed" and "independent" are not synonyms. If the adapter that is under review minted the tool receipt, the receipt proves what that adapter asserted. The report names that provenance rather than laundering it into independence.

## Report vocabulary

Workflow conformance reuses the existing vocabulary:

- **Deviation:** observed evidence outside the declared graph or node authority, such as an undeclared edge, wrong actor, or out-of-scope tool.
- **Gap:** evidence required to complete the declared path is absent, such as a completed run with no permitted terminal.
- **Commitment outcome:** `satisfied | violated | unfulfilled | refused`, reported by commitment verification rather than collapsed into path conformance.
- **Provenance:** `checked | captured | asserted`.

Path, authority, commitment, and provenance remain separate axes. One must not hide another.

The initial machine report has this shape:

```json
{
  "run_id": "run_...",
  "workflow_ref": "art_...",
  "pre_existence": { "grade": "checked" },
  "path": {
    "grade": "checked",
    "deviations": [],
    "gaps": []
  },
  "authority": { "deviations": [] },
  "loops": [
    {
      "id": "repair",
      "iterations": 1,
      "max_iterations": 2,
      "limit_exceeded": false,
      "budget_exceeded": false
    }
  ]
}
```

There is deliberately no single workflow score. Consumers may decide that any deviation, gap, or exceeded limit is fatal, but the substrate reports the file rather than assigning reputation.

## Validation rules

Minting refuses a declaration when:

- node IDs are empty or duplicated,
- entry or terminal IDs do not exist,
- an edge references an unknown node,
- `when` is outside the closed vocabulary,
- an executor has neither or both of `actor` and `capability`,
- a loop references an undeclared edge,
- two loops claim the same back edge,
- `max_iterations` is zero,
- `max_actions` is zero when present.

The verifier refuses vacuous input. A declaration needs at least one node, one terminal, and a non-empty evidence set before any path can grade `checked`.

## First dogfood

The first end-to-end workflow is a Claude Code and gstack QA loop in this repository:

```text
inspect -> change -> qa -> finish
                    |
                    +-- on_fail -> change, at most 2 times
```

Existing Claude Code hooks and Treeship receipts provide the evidence. No LangGraph or Temporal adapter is required for the first verdict. The deployment repair example waits until this smaller loop produces trustworthy reports.

## Slices

1. **Golden reports and minimal declaration spec.** The fixtures in this directory and this document. No runtime behavior yet.
2. **Pure conformance reducer.** Parse a validated declaration plus already-verified observations and reproduce every golden report. No signing or CLI surface in this slice.
3. **Signed, checkpoint-anchored declaration.** Register `workflow.v1`, mint it through `receipt.v1`, publish its checkpoint, and bind a run's first receipt to the declaration artifact.
4. **Claude Code and gstack dogfood.** Group existing evidence into node attempts and verify the real QA loop.
5. **External adapters.** Add adapters only after the report distinguishes checked, captured, and asserted paths end to end.

`edge_taken.v1`, generalized workflow execution, optimization, graph databases, and automatic graph rewriting are explicitly deferred.
