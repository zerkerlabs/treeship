# Memory-Provenance Binding: the why-believed axis

**Status:** design spec, not implemented — but deliberately written against shipped primitives; every section is marked SHIPPED (exists today) or NEW (must be built)
**Pairs with:** [work-history](./work-history.md), [capability-provenance](./capability-provenance.md), [transparency-log](./transparency-log.md), the [memory-providers contract](../content/docs/integrations/memory-proofs.mdx)
**Interop target:** IETF `draft-rampalli-scitt-capsule-provenance-binding` / `draft-mih-scitt-agent-action-capsule` (real drafts; note SCITT architecture itself is still `draft-ietf-scitt-architecture-22`, not an RFC — build a bridge, not a dependency)
**Last updated:** 2026-07-16

## The shift

Treeship's receipts today are a record of an agent's **hands**: commands wrapped, tools called, files touched, approvals consumed, work handed off. They answer *what did it do* and *was it allowed to*. They do not answer the question that decides whether an autonomous action was sane: **what did the agent believe when it acted, and where did that belief come from?**

Every consequential agent failure mode of the next few years lives on that third axis. Prompt injection is a *belief-supply-chain* attack. Stale-memory action is a *freshness* failure. Cross-session poisoning is a *lineage* failure. None of them are visible in a tool-call log, because the tool call itself is well-formed — the corruption happened upstream, in what the agent knew.

The industry framing (the Rampalli binding draft) names three orthogonal questions per action:

| Axis | Question | Owner |
|---|---|---|
| **why-believed** | What was the agent's knowledge state, from which sources, in which trust state? | the memory provider (zmem.sh, or any provider) |
| **may** | Was this action authorized, by whom, in what scope? | Treeship — **SHIPPED** (Approval Authority) |
| **did** | What actually happened, including what was blocked? | Treeship — **SHIPPED** (artifacts, sessions, receipts) |

Treeship already owns two of the three axes with primitives stronger than the drafts propose (the draft's "may" axis is an HMAC over a shared session secret; ours is Ed25519-signed, scoped, single-use, journal-replay-protected). This spec defines the third axis and — the actual product — the **binding**: the moment a memory provider's attested ledger state is committed into a Treeship artifact so that all three axes verify as one record.

## The load-bearing invariant

> **Availability, never influence.** The binding proves *what was available to the agent and in what trust state* — never *what shaped its output*. Influence attribution requires attention-level introspection no production inference API exposes. Any wording that lets a verifier read "these memories were consulted" as "these memories caused this action" is an overclaim, and the verifier output must say so explicitly, the same way `structural-pass` refuses to be read as authenticity.

This is the same honesty rule as `package verify`'s narrative warning and work-history's "proves what was recorded, never everything that happened" — applied to cognition.

## Honest constraints (state these or the surface over-promises)

- **The memory provider is the memory authority; Treeship is the proof authority.** Treeship proves that a specific provider key attested a specific ledger state and quarantine verdict at a specific time. It does not prove the memory is semantically true, the provider's ranking was good, or the quarantine policy was wise.
- **Completeness is not cryptographic.** An agent with an uninstrumented memory path has off-the-record beliefs. The binding covers providers that attest; the receipt must not imply total knowledge-state capture.
- **A dirty check that never ran looks like a clean check that never ran.** Quarantine gating is only meaningful when the enforcement point (approval issuance) *requires* the check for the relevant action classes. Fail-closed: no check ⇒ no grant, and the denial is itself a signed artifact.

## Part 1 — The provider ledger contract (NEW: zmem.sh)

Extends the published [memory-providers contract](../content/docs/integrations/memory-proofs.mdx) (URIs, digests, lifecycle verbs — already the skeleton) with the pieces a verifier needs.

### 1.1 Append-only ledger with unbackfillable classification

Every memory event is appended, never mutated, with fields that **cannot be reconstructed later** — these are schema-P0, required before the first byte of production data:

| Field | Values / shape | Why unbackfillable |
|---|---|---|
| `source_class` | `user_intent` \| `tool_response` \| `environmental` \| `external_document` \| `agent_inference` \| `operator_policy` | Trust state at write time is unknowable retroactively |
| `retrieval_cause` | `agent_initiated` \| `operator_injected` \| `system_prefilled` | Distinguishes the agent asking from the operator injecting — the memory supply-chain attack surface |
| `cross_session_lineage` | parent `entry_id` when a memory was seeded from another session's memory | The long-game injection path; invisible once sessions accumulate |
| `content_digest` | `sha256:<hex>` — digests, never raw content | Existing rule from the providers contract |
| `quarantined` | boolean, defaulted by source class | See 1.2 |

Default quarantine by source class: `tool_response` and `external_document` are **quarantined at write**; `agent_inference` requires an explicit trust grant; `user_intent`, `environmental`, `operator_policy` are clean by default. Operators may override per-namespace; overrides are themselves ledger events.

### 1.2 Chain root

`memory_chain_root = base64url(SHA-256(canonical({domain_id, seq, merkle_root, timestamp})))` over an RFC 6962-style incremental Merkle tree of ledger entries. Treeship-core already implements the tree, inclusion proofs, and consistency proofs (**SHIPPED** in `treeship-core::merkle`) — zmem should consume the crate or the WASM build rather than re-implement, which also guarantees verifier parity for free.

Canonical form: same discipline as Treeship statements — a fixed, documented canonical serialization. Do not claim RFC 8785/JCS unless it actually is.

### 1.3 Provider endpoints

- `GET /chain-root?seq=N` → the root + seq + (when anchored) the transparency receipt.
- `POST /quarantine-check` → `{action_id, triggering_memory_ids, chain_root, decision_seq}` in; `{clean, quarantined_triggers[], staleness_flags[], chain_root_confirmed}` out — **signed with the provider's per-agent key** (see 2.2), not an HMAC.
- `GET /provenance/{chain_root}` → inclusion proofs + triggering-entry metadata for Class-2 verification. Authenticated; responses are sensitive (they reveal what an agent read) and verifiers must not persist them beyond the verification decision.

## Part 2 — The binding (mostly SHIPPED primitives, composed)

### 2.1 Memory operations are ordinary attested actions — SHIPPED

Providers attest reads, writes, and lifecycle transitions with the existing CLI/SDK surface, exactly per the providers contract:

```bash
treeship attest action \
  --actor agent://codex --action memory.inject \
  --subject memory://zmem/default/task-preferences \
  --input-digest sha256:... --output-digest sha256:... \
  --meta '{"memory_provider":"system://zmem","memory_chain_root":"<root>","retrieval_cause":"agent_initiated"}'
```

The `memory_chain_root` in `meta` is the per-action commitment. Nothing new to build; the convention just becomes normative.

### 2.2 Provider identity — SHIPPED (per-agent keys, not a new trust kind)

The provider onboards like any agent: `treeship onboard zmem` mints a per-provider key pinned under `agent_cert`, so every quarantine attestation and chain-root commitment verifies **`proven (key-bound)`** on any counterparty's machine after one `trust add`. This deliberately replaces the draft's session-secret HMAC with the existing, stronger primitive, and gives cross-org federation for free: federating provenance = exchanging provider keys via `keys export` / `trust add`, the mechanism counterparties already use.

### 2.3 Quarantine attestation travels as a typed receipt — SHIPPED machinery, NEW predicate

```bash
treeship attest receipt --system system://zmem --kind memory.quarantine-check \
  --payload-file check-result.json
```

NEW work: register a `memory.quarantine-check.v1` predicate schema (fail-closed validation like `session.v1`): `{action_id, chain_root, decision_seq, clean, quarantined_triggers[], staleness_flags[]}`. The consuming action references this receipt as its parent or in `meta.quarantine_receipt`.

### 2.4 Approval issuance is the quarantine gate — SHIPPED gate, NEW hook

The enforcement point is not a new authorization layer; it is the existing one. High-privilege actions already require a scoped approval (`--allowed-actor/--allowed-action/--allowed-subject`, `--max-uses`, journal replay protection). The binding adds one rule:

> For actions in a consequential irreversibility class (2.5), approval minting **requires** a fresh, clean, key-bound `memory.quarantine-check` receipt covering the triggering memories. Dirty or missing check ⇒ the grant is refused, and the refusal is emitted as a signed **blocked artifact** (2.6) with reason `quarantine_triggered`.

`attest action --approval-nonce` then binds action → approval → quarantine check → chain root into one verifiable chain, using only the existing chain semantics.

### 2.5 Irreversibility classes — NEW

`two_way` | `one_way_recoverable` | `one_way_consequential` | `one_way_terminal`, declared on approvals (extending the scope vocabulary) and stamped into action meta. Consequential+ triggers the quarantine requirement; terminal additionally requires a human approval (`--approver human://…` — SHIPPED).

### 2.6 Blocked actions become signed artifacts — NEW

Today a denied approval or a pre-hook block is an event, not evidence. NEW: a `blocked.v1` statement — actor, intended action, reason class (`policy_threshold_exceeded` | `quarantine_triggered` | `scope_violation` | `operator_revocation` | `human_escalation_pending`), evidence digest, re-evaluation condition — signed and chained like any artifact. Negative space becomes verifiable: "the guardrail fired" stops being a narrative.

### 2.7 Effect status ladder + confirmed-effect invariant — NEW

Actions gain `effect_status`: `planned → dispatched → confirmed → failed → reverted`, with the core-enforced invariant (same style as the empty-receipt rule): **`confirmed` requires a `response_digest` over the actually observed response; `planned` must not carry one.** This is what separates "the payment was attempted" from "the payment's result was observed" in a dispute. The MCP bridge's existing intent-before/receipt-after pair (**SHIPPED**) maps directly: intent = `planned`, result receipt = `confirmed`/`failed`.

### 2.8 Epoch identity — NEW (small)

`epoch_id = <model_version>:<policy_digest>:<runtime_variant>` stamped into statement meta, with an epoch-rotation event when any component changes mid-session. Unbackfillable; cheap; answers "which configuration of this agent did this."

### 2.9 Anchoring honesty — SHIPPED rule, applied

A binding may claim `anchored` only when the chain root itself carries a transparency receipt (provider publishes roots via the existing `merkle publish` path or its own log). Local-only roots are `chained`. Same non-overclaim rule as `replay-hub-org`: Treeship physically refuses to print the stronger claim without the evidence.

### 2.10 Joint attestation — SHIPPED pattern, NEW statement type

Where the binding itself must be tamper-evident (not just each side), reuse the session-countersign machinery (`SessionParticipantStatement`: two envelope signatures, issuer key matching): a `provenance-binding.v1` statement signed by the agent key **and** countersigned by the provider key.

## Part 3 — Verification

**Class 1 (offline, artifact bytes only):** signatures verify; chain intact; approval binding + scope + replay rows (SHIPPED); quarantine receipt present, schema-valid, key-bound to a pinned provider key; `memory_chain_root` committed; effect invariant holds; blocked artifacts well-formed. Deterministic; never consults a network, model, or clock heuristic.

**Class 2 (provider-API-dependent):** resolve the chain root via `GET /provenance/…`; re-derive `clean` from the triggering entries' quarantine flags; verify inclusion + consistency proofs (append-only). A contradiction is an overclaim finding; an unreachable provider is `unverifiable`, never assumed false.

**Verdict wording (normative):** `memory state: attested (available, not influence)` — the availability/influence distinction appears on the verdict line itself, per the load-bearing invariant.

## Part 4 — What this binding does NOT prove

- Not **influence** — which memories shaped the output (research frontier, 2–4 years out; revisit if inference APIs expose attribution).
- Not **semantic truth** of any memory, nor quality of the provider's retrieval or policy.
- Not **completeness** of the agent's knowledge state — only instrumented providers appear.
- Not **safety** — a signed record of an action taken on clean memory can still be a bad action. Policy judges; the binding evidences.

## Part 5 — Interop bridge (export, not rewrite)

Treeship's core stays DSSE/Ed25519/content-addressed. For AAC/SCITT consumers, define an **export mapping** (the `receipt export` pattern): Treeship artifact → AAC capsule with `org.zerker.provenance` extension (`authz_ref` → approval artifact URI, `memory_chain_root`, `quarantine_attested`), COSE_Sign1 re-signature at the bridge boundary, SCITT registration optional. Namespace is `org.zerker.` throughout. Track `draft-ietf-scitt-architecture` maturity; do not depend on it pre-RFC.

## Part 6 — Build sequence

| Phase | Work | Status |
|---|---|---|
| 0 | Schema P0s frozen: `source_class`, `retrieval_cause`, `cross_session_lineage`, `irreversibility_class`, `epoch_id`, `effect_status` — before first production byte | decision, not code |
| 1 | zmem: append-only ledger + chain root (consume `treeship-core::merkle`) + memory.* attestation via existing CLI/SDK | NEW (zmem) on SHIPPED (treeship) |
| 2 | `memory.quarantine-check.v1` predicate + provider onboarding (`onboard zmem`) + chain-root-in-meta convention | small NEW |
| 3 | Approval-gate hook (2.4) + irreversibility classes (2.5) + blocked artifacts (2.6) | NEW (treeship core/CLI) |
| 4 | Effect ladder + confirmed-effect invariant (2.7); epoch identity (2.8) | NEW (treeship core) |
| 5 | Provenance read API + Class-2 verifier support; joint attestation type (2.10) | NEW |
| 6 | AAC/SCITT export bridge; cross-org federation (provider-key exchange + chain-root format attestation) — the enterprise surface no standard specifies | NEW, later |

Phases 1–2 ship on today's Treeship with no envelope changes. That is the point of building the third axis on a system that already owns the other two.

## Open questions

1. Freshness semantics: is `staleness_flag` provider-judged (TTL policy) or verifier-judged (bound like `--max-staple-age`)? Lean verifier-judged, consistent with the trust model.
2. Should `blocked.v1` artifacts enter the Merkle log by default (discoverable negative space) or opt-in (blocked-action metadata can itself be sensitive)?
3. Sub-session chain-root cadence: per-decision snapshots first; streaming checkpoints only when a real workload demands sub-session resolution.
4. Does `agent_inference` source class need lineage to the producing action's artifact id (belief ↔ receipt cross-link)? Probably yes; cheap if done at write time.
5. **The mint/consume freshness gap.** The quarantine check is fresh at approval *minting*; the use journal reserves at *consumption*, and beliefs can change between the two. `--expires` and `--max-uses 1` bound the window but do not close it. Proposed: bind `decision_seq`/chain root into the grant, and re-check at consume time for `one_way_terminal` (the journal already intercepts consumption, so the hook point exists).
6. **Provider-unavailable degradation.** Fail-closed is normative, but "provider down ⇒ no consequential grants" needs an operational escape: an operator override that is itself a signed artifact with reason `quarantine_check_unavailable_override` — the bypass becomes evidence, never silence.
7. **Bridge must wrap, never restate.** The AAC/SCITT export carries the original DSSE envelope inside the capsule payload (agent signature verifiable end-to-end); the COSE_Sign1 signature is the bridge's countersignature, not a replacement. A re-signing bridge would reintroduce a trusted intermediary. Note the bridge must implement genuine RFC 8785 for capsule-id computation — real work, not a serialization detail.
