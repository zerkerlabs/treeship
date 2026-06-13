# Verifiable Workflow Declarations — design draft

**Status:** draft, not implemented
**Audience:** Treeship maintainers, prospective integrators
**Last updated:** 2026-05-18

## The shift

Treeship today is **prove-after**:

1. An agent does something.
2. The action is signed into an artifact.
3. A verifier reads the artifact later and confirms the action happened.

Trust is retrospective. We learn what happened by reading a signed trace.

This spec describes the **prove-before** layer: a workflow is declared as a verifiable structure *before* any agent runs, signed by an authority, and every action verifies against the declaration at execution time.

| Layer | Question it answers |
|---|---|
| Prove-after (today) | What did the agent do? |
| Prove-before (this spec) | What is the agent **authorized** to do? |
| Both together | Was every authorized action taken, with nothing unauthorized? |

The unlock: agents you can audit *before* they run, not just after. That changes the conversation for compliance, multi-agent orchestration, and any workflow where "we'll check the receipt later" is too late.

## What we're building

A new artifact type `treeship/workflow/v1` that declares a workflow structure as a signed object:

- **Nodes** — action types the agent is allowed to perform (`tool.call`, `agent.handoff`, `human.approval`, custom). Each node carries its own constraints (tool whitelist, model whitelist, cost cap, parameter shape).
- **Edges** — allowed transitions between nodes. The workflow forms a directed graph (probably a DAG for v1, with a roadmap to cyclic via bounded iteration).
- **Constraints** — workflow-level invariants: max total cost, max wall-clock time, expiry timestamp, signing authority's identity.
- **Signing authority** — an Ed25519 keypair (could be human, org, or parent agent) that signs the workflow declaration. The verifier checks this against the configured trust roots (`treeship trust` from v0.10.3).

At execution time, every action attestation gains an optional `workflow_node_id` field. The verifier walks the trace against the declared workflow and reports each transition as:

- **`authorized`** — the action matches the declared node and the transition from the prior node is on a declared edge
- **`deviation`** — the action does not match (wrong type, wrong constraints, no edge from prior node)
- **`gap`** — the workflow declared a node that was never executed (incomplete)

The final session receipt's verifier output gains a `workflow_conformance` row alongside the existing rows (`merkle_root`, `inclusion_proofs`, `leaf_count`, `timeline_order`).

## Composition with existing primitives

This is not a new trust primitive built from scratch. It's a structure that composes pieces Treeship already ships:

| Existing primitive | Role in a workflow declaration |
|---|---|
| **Approval Use Journal** (`v0.9.9`) | An edge in the workflow can require an approval-use-bound action. The nonce-binding semantics already work. |
| **Agent Identity Certificates** (`v0.9.8`) | A node can require the executing agent's certificate to match a declared identity. The cert-issuer trust check already works. |
| **Harness Manager** (`v0.9.8`) | A workflow can require a minimum coverage level for the executing harness. The coverage taxonomy already exists. |
| **Merkle checkpoints** (`v0.10.3+`) | The workflow declaration itself is checkpoint-anchored, so a verifier can prove the declaration existed before the execution trace. |
| **Trust roots** (`v0.10.3`) | The workflow's signing authority pubkey must appear in the verifier's trust store, kind `WorkflowAuthority` (new kind). |
| **Canonical signing** (`v0.10.4`) | The workflow declaration uses the same canonical-with-version-bound pattern as the v3 checkpoint canonical. No new crypto invariants. |

Concretely: a workflow node that says "this agent calls `tool.call:Bash` with an approval-use-bound nonce, executed under a `verified`-coverage harness, signed by an agent whose certificate issuer is in trust roots" is *already expressible* in Treeship's existing vocabulary. What's missing is the **container** that names this combination as one declared, signed unit.

## What we're explicitly NOT building yet

To keep v1 honest and shippable:

- **No conditional branching language.** v1 is a DAG of static node types with edges. "If the model returns X, take edge A; else edge B" is roadmap, not v1. v1 verifiers see the actual execution trace; they don't simulate branches.
- **No loops.** Bounded iteration (`do step N up to K times`) is roadmap. v1 trees terminate.
- **No remote workflow registry.** The declaration is a local artifact you can push to the Hub like any other. A registry of "known workflows" sits at a layer above this spec.
- **No mid-execution mutation.** Workflows are immutable once signed. A new workflow declaration is a new artifact. (Mutable workflows with re-sign semantics are roadmap.)
- **No automatic workflow inference from observed traces.** "Here's the workflow your agent actually ran" reverse-engineered from a session is interesting but separate. v1 only verifies traces against declared workflows.
- **No new crypto.** Same Ed25519, same DSSE envelope, same canonical pattern. The whole point is composition.
- **No CLI for workflow authoring beyond a YAML loader.** `treeship workflow declare workflow.yaml` produces a signed artifact. Visual authoring tools sit at a separate layer.

## Four open questions for you to decide

These are the hard calls. Each one shapes the rest of the spec.

### Q1: workflow → trace binding direction

When the verifier finds that the trace doesn't match the declared workflow, who's failing?

- **(a) Trace fails** — "your agent did something not in the workflow; refuse the receipt." Strict. Treats the workflow as policy.
- **(b) Workflow fails** — "the declaration doesn't match what really happened; the workflow was wrong." Permissive. Treats the workflow as a hint.
- **(c) Both recorded** — verifier outputs `workflow_conformance: deviating(N actions outside declared workflow)`, lets the consumer of the verification decide what to do with it.

Recommendation: **(c)** for v1, with strict mode opt-in via `--strict-workflow`. Matches the `--strict` pattern that's already in `treeship verify package`.

### Q2: workflow scope unit

Is a workflow a **session-scoped** declaration ("this session's agent must follow this workflow") or a **per-action** declaration ("this specific tool call is authorized")?

- **(a) Session-scoped** — one workflow covers the whole session. Simple. Matches how humans think about "the agent's job."
- **(b) Per-action** — every action carries its own workflow context. Composable. More like capability tokens.
- **(c) Both** — sessions carry a default workflow, individual actions can override or sub-declare.

Recommendation: **(a) for v1.** Per-action is interesting but it's effectively a different primitive. Start with session-scoped; revisit.

### Q3: privacy of declared workflows

A workflow declaration leaks structure. "Agent will call `kubectl exec` if approval-use-nonce-X is presented" tells the world what the org is about to do. Is that:

- **(a) Public by default** — workflow declarations are always plaintext in the receipt
- **(b) Hashed by default** — only the workflow's content-hash is in the receipt; the structure is private; verifier needs the full declaration out-of-band
- **(c) Configurable** — declaration carries a `disclosure: {public, hashed}` field per node

Recommendation: **(b)** for v1. Mirrors how Treeship already treats action inputs (hash, not raw). Verifiers who legitimately need to check conformance can fetch the declaration separately under the existing trust-root mechanism. Public workflows are an opt-in for compliance reporting where the workflow IS the disclosure.

### Q4: failure mode when execution deviates

If at action 7 of a 10-action workflow the agent does something not in the declaration, what should:

- **The agent's CLI do?** Refuse to sign the deviation, sign it but flag it, sign it transparently?
- **The session receipt say?** Show the deviation explicitly, omit it, mark the receipt as `unconformant`?
- **The verifier report?** Pass with warning, fail closed, fail strict?

Recommendation:
- **CLI:** sign transparently (Treeship's primary job is honest recording, not enforcement)
- **Session receipt:** explicit `deviations: [...]` list in the verifier output
- **Verifier:** warn by default, fail under `--strict-workflow` (consistent with Q1c)

This treats the workflow declaration as *evidence of intent* rather than as *enforcement*. The CLI doesn't refuse to do its job; the verifier surfaces the gap. Loud and honest beats silent and enforced.

## Implementation phases

If the four questions above settle, the build is small:

**Phase 1: declaration + standalone verify (1-2 days)**
- New crate module `packages/core/src/workflow/`
- `Workflow` struct + canonical signing (mirror `Checkpoint::canonical_for_signing` from v0.10.4 lane A)
- New CLI: `treeship workflow declare <yaml>` produces the signed artifact, `treeship workflow show <id>` prints it, `treeship workflow check <workflow-id> <artifact-id>` checks one action

**Phase 2: trace conformance (3-5 days)**
- New verifier row `workflow_conformance` in `verify_receipt_json_checks`
- Walk the receipt's timeline against the declared workflow, record `authorized` / `deviation` / `gap` per node
- Session receipt JSON shape gains the new row (backwards compat via `#[serde(default)]`)
- WASM verifier mirror

**Phase 3: integration with existing primitives (1 week)**
- Workflow nodes can carry approval-use constraints (already a separate signed structure)
- Workflow nodes can require harness coverage minimums
- Workflow nodes can pin executing agent's certificate identity
- All three of these compose; the workflow is the container

**Phase 4: language + UX (separate scope, not estimated here)**
- YAML schema documentation
- Examples library
- Workflow authoring helpers
- Visual representation in receipt rendering
- "Suggested workflow" inference from existing traces (the reverse problem)

## What to look at before committing to this

1. Read `packages/core/src/statements/approval_use.rs` to confirm the approval-binding semantics map cleanly onto workflow edges.
2. Read `packages/core/src/agent.rs` for agent certificate identity matching.
3. Read `packages/core/src/session/package.rs:verify_package` to understand where the new `workflow_conformance` row would slot in.
4. Decide if `treeship trust` needs a new `WorkflowAuthority` kind, or if workflows reuse the existing kinds (`HubCheckpoint`, `Ship`, `AgentCert`).
5. Sanity-check Q3 (privacy) against any existing customers' expectations — if anyone is already imagining workflows as public "show your work" artifacts, the default matters.

## How this lands

Recommend cutting **v0.11.0** for the first workflow-declarations release, not a v0.10.x patch. Reasons:
- The shift from prove-after to prove-before is the kind of conceptual change that deserves a minor version bump.
- The trust-root mechanism gains a new kind (`WorkflowAuthority`); that's a real schema addition.
- The session receipt JSON gains a new verifier row; that's a wire-format change (backwards-compat, but still a wire change).

v0.10.x can keep landing tactical polish (drift closure, discovery page, README rewrite, etc.). v0.11.0 is when workflow declarations become a real product.

## Open questions for the author of this spec

Things I deliberately didn't try to answer because they sit above the schema-design layer:

- **Who authors workflows in practice?** Humans writing YAML? Agents declaring their own intent before execution? An org-level policy system that emits workflows for every agent it dispatches?
- **What's the discovery story?** "Here's a workflow library you can pick from" is implied but not specified.
- **How does this interact with the Room Sessions spec?** A multi-agent room could have one workflow per agent, or one shared workflow with per-agent sub-trees. The Room Sessions spec should be read alongside this one.
- **Is there a "workflow that proves the agent can't do something"?** Negative declarations (sandbox-style) are valuable but adversarially complex. Not v1.

These are product/strategy questions, not schema questions. They want a separate conversation.

---

*If this direction is right, the next move is to settle Q1–Q4 and let me draft Phase 1 in a fresh PR.*
