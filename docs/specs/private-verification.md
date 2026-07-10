# Private verification: selective disclosure and zero-knowledge proofs

**Status:** draft, partly implemented (the selective-disclosure primitive ships in
`core::disclosure`). Supersedes the experimental `zk-circom` Groth16 path.
**Pairs with:** [transparency-log](./transparency-log.md), [registry-topology](./registry-topology.md), [protocol-integration](./protocol-integration.md)
**Last updated:** 2026-07-10

## Why this document exists

This spec covers how an agent proves properties of its credentials and history to a
counterparty **while revealing as little as possible**. There are two mechanisms, and
they are deliberately not the same thing:

- **Selective disclosure (not zero-knowledge).** Reveal *this* field, hide the rest.
  Plain hashing plus the existing Ed25519 signature (the SD-JWT construction, ported to
  DSSE): the signed payload commits to salted per-claim digests, the holder reveals the
  claims it chooses, the verifier re-hashes and checks membership. The revealed field is
  shown in the clear; only the *other* fields are hidden. Cheap, standard, verifies
  anywhere including the browser. Shipped in `core::disclosure`.
- **Zero-knowledge proofs.** Prove a *property* of a value while revealing *nothing*
  about the value, or compress a large verification into a small proof. This is the only
  part that uses ZK tech, and it is needed only for a specific set of statements (below).

**When ZK is actually used** (selective disclosure cannot do these): a range or
threshold over a hidden number ("payment <= limit", hiding both); set membership without
revealing which member ("some capability covers this action"; "certified by some issuer
you trust", i.e. anonymity); a computation over hidden records ("N sessions, 0
violations", hiding the sessions); and a succinct proof that a whole chain verifies.
Everything else — presenting a capability, showing a subset of a mandate, revealing a
chosen field — is selective disclosure, no ZK.

The two share one foundation: the salted commitments the disclosure layer puts in the
signed payload are the *same* values a ZK proof opens. So selective disclosure is not a
detour from ZK; it is the layer ZK builds on.

### The ZK layer's history and rebuild

Treeship shipped an experimental ZK layer (Circom/Groth16 circuits, a RISC Zero zkVM
path) behind `--features zk`, hidden from help and excluded from release binaries. In
July 2026 we put that layer through the same scrutiny a skeptical cryptographer would
apply: *what is the precise formal statement each proof establishes, and does it equal
the statement the docs claim?* It did not pass. The Groth16 circuits had no phase-2
ceremony (forgeable by construction), the `valid` signal was an output never asserted
to be 1, three of four circuits left the artifact binding unconstrained, and the
verifier checked a proof only against its own recorded public signals. None of this
shipped in a release binary, but the docs described capabilities the code did not have.

The ZK rebuild's organizing principle is one sentence:

> **Make the proven statement equal the claimed statement, or shrink the claim.**

Everything below states formal statements first and treats circuits, proof systems,
and code as implementations of those statements, never the other way around.

## The load-bearing invariant

> **A ZK proof in Treeship establishes a statement *about a specific signed
> artifact*, and the verifier supplies the policy. The proof is worthless unless the
> verifier (a) independently verifies the artifact's classical signature, (b) reads
> the value the proof commits to out of the *signed* bytes, and (c) supplies the
> predicate it wants checked rather than trusting one named in the proof.**

A proof detached from a locally verified artifact proves nothing about that artifact.
A proof of "conforms to a policy of the prover's choosing" is vacuous. Both failure
modes were present in the experimental layer; this invariant forecloses them.

## Honest constraints (state these or the surface over-promises)

- **ZK does not close the intent gap.** No proof system can prove that a formal
  mandate correctly captures an informally expressed human intent. That binding is a
  recorded human signature on the mandate artifact, not a cryptographic claim. ZK
  proves conformance *to the signed mandate*, nothing upstream of it.
- **Proof soundness is bounded by capture provenance.** A proof that a trace conforms
  to a mandate says nothing if the agent fabricated the trace. The trustworthiness of
  the *inputs* (per-agent keys, attestation class, countersignature) is a separate and
  larger problem than the proof, and it is where most of Treeship's engineering lives.
  ZK is disclosure control over already-captured, already-signed evidence, not a
  substitute for it.
- **What is feasible is the policy check, not the inference.** Proving an LLM forward
  pass in zero knowledge is not practical in 2026. Every statement in this spec is a
  predicate over an action *trace*, never over model execution.
- **A trusted setup is a trust assumption and must be named.** Any non-interactive
  succinct proof we verify in the browser either uses a transparent system (no setup)
  or names the exact ceremony it relies on. "We ran setup locally with zero
  contributions" is not an acceptable answer and was the fatal flaw of the old path.

## The two verification topologies

Treeship already verifies in two distinct settings, and they want different proof
systems. This is the structural fact that organizes the design.

**Track A — asynchronous, publicly verifiable.** The receipt travels with the work;
anyone verifies it later, offline, in a browser, without contacting the prover. This is
the transparency-log and `treeship.dev/verify/<id>` model. It *requires* a
non-interactive, succinct proof that the WASM verifier can check in well under a second.

**Track B — interactive, designated-verifier.** An agent proves a property to a
specific counterparty who is online now. This is challenge mode (the live key-control
handshake) and `present` / `verify-presentation`. The verifier is present, so the proof
may be interactive, which unlocks a strictly better toolset.

The same signed artifact and the same committed value feed both tracks. Only the proof
system over that commitment differs.

## The binding mechanism (shared by both tracks)

The root cause of the old layer's non-binding was trying to relate SHA-256/JSON/DSSE
bytes to a circuit *after* signing. Invert it: bind at signing time.

A statement MAY carry an optional `zk_commitment` field: a commitment, under a
ZK-friendly hash (Poseidon over BN254, or the transparent system's native hash), to a
canonical tuple of the sensitive fields the proof will reason about (for a policy
proof: the action; for a spend proof: the amount; etc.).

Because `zk_commitment` is a field of the statement, it is inside the DSSE PAE bytes
that get signed. Two consequences:

1. **Binding is free and classical.** The WASM verifier already verifies the DSSE
   signature. Once it does, `zk_commitment` is a verified value bound to that exact
   artifact id. The ZK proof only ever needs to open *that commitment*; it never needs
   to see artifact bytes, parse JSON, or compute SHA-256 in-circuit.
2. **It is a dispatch field, so it is bound into the canonical.** Per the AI-assisted
   development policy §6, adding `zk_commitment` requires binding it into the canonical
   signing bytes and a regression test that mutates it on a signed envelope and asserts
   verification fails.

The off-circuit commitment MUST be computed by a native implementation test-vectored
against the in-circuit hash (the old SHA-256 "Poseidon" placeholder is deleted). A
commitment the circuit cannot reproduce is the single most catastrophic bug class here.

## The formal statements

Each proof type is specified as: public inputs (what the verifier sees), private
witness (what stays hidden), the relation R, and the verifier's independent
obligations. Implementations prove exactly R and nothing weaker.

### Statement 1: policy conformance

    Public:  C   (zk_commitment, read from the signed artifact by the verifier)
             D   (policy digest, computed by the verifier from the policy IT requires)
    Witness: a   (the action)
             r   (commitment opening)
             P   (the allowed-action set)
    Relation R:  C = Commit(a; r)  AND  D = Hash(P)  AND  a in P
    Verifier obligations:
      1. verify the artifact's Ed25519 signature; abort if invalid
      2. read C from the signed statement (never from the proof file)
      3. compute D from the policy the verifier itself holds
      4. check the proof for R; membership (a in P) is an ASSERTED constraint,
         not an output signal

Note what changed from the old circuit: `valid` is not an output the prover can set to
0; `a in P` is a hard constraint, so a proof exists only if the action actually
conforms. The policy is the verifier's, pinned via D. The artifact binding is C, which
came from the signed bytes.

### Statement 2: spend-limit conformance

    Public:  C   (zk_commitment over the amount, from the signed artifact)
             L   (limit, supplied by the verifier or read from a signed mandate)
    Witness: amount, r
    Relation R:  C = Commit(amount; r)  AND  amount <= L
    Verifier obligations: as above; L must come from a signed mandate artifact or the
    verifier's own argument, never from prover-supplied metadata.

### Statement 3: chain integrity (Track A, the zkVM statement)

    Public:  root_id, tip_id   (derived INSIDE the guest, committed to the journal)
             pubkey_digest
    Witness: the full ordered chain of signed envelopes
    Relation R, checked in-guest over the signed PAE bytes only:
      - for each artifact: artifact_id == "art_" + hex(sha256(PAE)[..16])   (re-derived)
      - for each artifact: Ed25519.verify(pubkey, PAE, sig)
      - for i>0: parent_id (EXTRACTED FROM THE SIGNED PAYLOAD) == previous.artifact_id
      - approval nonce binding: action.approvalNonce == approval.nonce where present
      - on any violation: ABORT (no proof is produced), never a "false" flag
    Verifier obligations: check the receipt against the guest image id pinned at
    compile time; read root_id/tip_id from the journal.

The guest re-derives ids and extracts linkage from signed bytes, so a lying host cannot
fabricate a chain out of individually valid signatures. Violations abort rather than
setting a journal flag, so no consumer can present a "chain_intact: false" receipt as
success.

## Proof systems, mapped to the tracks

### Track A: non-interactive, WASM-verifiable

The statement is the chain-integrity relation (Statement 3), proved by the **RISC Zero
zkVM** (STARK-based, transparent, no trusted setup). Two options for browser
verification, in preference order:

1. **STARK verified directly in WASM.** Fully transparent, no setup anywhere. Cost:
   larger receipt (~hundreds of KB) and slower verify. Ship this if WASM verify time is
   acceptable, because it assumes nothing.
2. **STARK wrapped in Groth16 for browser verify.** The zkVM receipt is wrapped into a
   ~200-byte SNARK verified by one pairing check in WASM (the ark path the old design
   reached for, now used correctly). This reintroduces a trusted setup, but it is *RISC
   Zero's* published multi-party ceremony, named and relied upon explicitly, not one we
   ran. Ship this only if option 1's verify cost is prohibitive, and document the
   ceremony dependency in the verifier output.

Either way the WASM verifier's ZK job is: (1) verify the DSSE signature [already
implemented], (2) read `zk_commitment` from the verified bytes [trivial], (3) verify the
proof and check its public input equals that commitment / the journal ids [the new
code]. No unbound proof is ever reported as `verified`; the AUD-09 `bound` semantics
already in `core-wasm/src/zk.rs` become the contract, not a warning.

### Track B: interactive, designated-verifier

The statement is policy or spend conformance (Statements 1-2) over potentially large
private traces, proved to a live counterparty. The right tool is **VOLE-based
interactive ZK** (the SIEVE-program family: QuickSilver, Mac'n'Cheese, Wolverine):
no trusted setup, and proving/verification costs that scale to large statements far
more cheaply than general-purpose SNARK circuits. Interactivity is free here because
challenge mode already has both parties online.

This track is the natural site of a research collaboration (see below) and is not a
solo build.

## The ZK presentation: authenticated selective disclosure between agents

The existing `present` / `verify-presentation` flow is authenticated *full* disclosure
plus liveness: the verifier receives the whole capability card, the certificate chain,
revocations, and a Merkle staple, and challenge mode proves the presenter controls the
key live. Nothing is hidden. The ZK layer's product payoff is the strict upgrade to
authenticated *selective and predicate* disclosure: an agent proves a property of its
signed credentials to a counterparty **without revealing the underlying values**.

This is not a new subsystem. It rides the presentation machinery, and the
`zk_commitment` mechanism is what makes it compose: because every sensitive value is
committed inside the signed PAE bytes, a ZK presentation is three steps the verifier
already trusts.

1. Verify the DSSE signature on the credential envelope. The commitment `C` is now
   authentic and bound to that exact artifact (already implemented in the verifier).
2. The presenter supplies a ZK proof that opens `C` for a stated predicate.
3. The verifier learns only that the predicate holds, and nothing else about the value.

### The predicate menu

Each row is a statement an agent can present without revealing the hidden column. The
mechanism column determines cost and sequencing; the first row needs no ZK at all and
is the shippable first step.

| Predicate presented | Hidden | Mechanism |
|---|---|---|
| card grants capability C | the other capabilities | Merkle path over a committed capability set (no ZK) |
| can perform action A (A→capability mapping private) | which capability, the set | ZK set-membership |
| payment amount <= mandate limit | the amount and the limit | ZK range proof |
| certified by *some* issuer in the verifier's trust set | which issuer (anonymity) | ZK set-membership over the trust set |
| >= N sessions of class X with 0 violations | the sessions themselves | ZK over the pinned `profile.v1` aggregation |
| action A conforms to mandate policy P | A and P | ZK set-membership (Statement 1) |

The history-threshold row is the elegant one: a `profile.v1` is already a deterministic
aggregation over the log's first `tree_size` leaves at a pinned checkpoint, so proving
the aggregate in ZK reuses the exact function the plaintext profile already recomputes,
with the leaves as private witness.

### Interactive vs non-interactive is the transferability choice

- **Non-interactive (Track A).** A transferable, publicly checkable proof attached to a
  presentation or receipt; anyone verifies it later in a browser. Use the zkVM (optional
  Groth16 wrap). This is the "proof travels with the credential" mode.
- **Interactive, designated-verifier (Track B).** A proof that convinces only the
  counterparty who participated — non-transferable, which is a privacy *feature* for
  agent-to-agent presentation (the verifier cannot re-sell the proof) and needs no
  trusted setup. Challenge mode already performs a nonce exchange; that transcript is the
  natural envelope for a VOLE-ZK proof. The surface is
  `present --challenge <nonce> --zk <predicate>` and `verify-presentation --zk`.

### The CLI surface

    treeship present --zk <predicate> [--challenge <nonce>]
    treeship verify-presentation --zk <predicate>

`<predicate>` names a menu entry and its public parameters (e.g.
`capability:covers(payments.charge)`, `spend:<=,mandate:<id>`, `issuer:in-trust-set`,
`history:sessions>=10,class=countersigned,violations=0`). The verifier supplies the
public side of the predicate (the policy, the limit source, the trust set) exactly as in
the Statement specs; the presenter never gets to choose it. A predicate the verifier did
not ask for is not a proof of anything the verifier cares about.

The honest first step is the no-ZK capability-disclosure row: the signed card commits to
salted digests of its capabilities, and `present` reveals a chosen subset while hiding the
rest. It demonstrates selective disclosure end to end, ships without any ceremony, and is
the base the predicate proofs build on. (Implemented in `core::disclosure` and
`core::capability::{commit_tools, disclosed_tools}`.)

### Card model and storage (decided)

Selective disclosure follows the SD-JWT issuance/presentation split, applied to the
capability card:

- **The signed card commits to digests, not raw tools.** `capabilities.tools` in the
  signed payload is replaced by `capabilities.tools_sd` (the sorted digest list from
  `commit_tools`). A plain Ed25519 signature commits to the whole payload, so the raw
  tools must be *out* of the signed bytes for hiding to be possible.
- **Disclosures live in a sidecar, not the signed receipt.** The `[salt, tool, true]`
  openings are stored beside the card in the card store (`.treeship/agents/<card>.disclosures.json`).
  They are holder state, not secrets (they cannot forge, only open); a presentation
  explicitly chooses which to attach. The signed artifact never contains them.
- **Full by default, selective opt-in.** Capabilities are meant to be discoverable, so
  `resolve`, `verify-capability`, and a plain `present` attach *all* disclosures — the
  full tool set is visible, identical to today. `present --disclose <subset>` attaches
  only the chosen openings, for the direct agent-to-counterparty case where an agent
  proves it has one capability without revealing the others. `present`/`verify-presentation`
  are "no registry in the loop", so selective presentation needs no hub involvement.

Build sequencing consequence: the `present` / `verify-presentation` path is local and
fully self-contained, so it lands first. The discoverable path (the hub serving
disclosures alongside a resolvable card, `resolve --hub`, and the browser WASM
`verify_capability` reading them) touches the Go hub and the WASM bundle and is a
deliberate follow-on with integration testing, not part of the first `present` slice.

## What the WASM verifier must end up doing

The verifier is the constraint, so the target end-state is stated explicitly:

- `verify_envelope`, `artifact_id`, `digest`, `verify_merkle_proof` — unchanged.
- `verify_zk_proof` — replaced. Input: a proof plus the signed envelope it concerns.
  Steps: verify the envelope signature; extract `zk_commitment`; verify the proof;
  assert the proof's public commitment equals the extracted value and (for policy
  proofs) equals the verifier-supplied policy digest. Output includes an explicit
  `bound: true|false` and, when a wrapped-SNARK path is used, the named setup dependency.
- The published `@treeship/core-wasm` build MUST enable whatever feature the real
  verifier needs. The current release build ships a stub that returns "ZK verification
  not enabled"; a docs claim of browser ZK verification is false until that changes.

## Deletion list (do before building)

The rebuild starts by removing what cannot be made honest cheaply, so no reader or
auditor mistakes it for shipping capability:

- The Groth16 self-setup path (`zk-circom/src/prover.rs` local `snarkjs groth16 setup`).
- The SHA-256 "Poseidon" placeholder (`zk-circom/src/utils.rs`).
- The dead second guest (`zk-risc0/guest/`), the dead `CircuitRegistry`, and the
  placeholder Merkle code.
- The "broken-by-design" checkpoint-mutation path in the daemon.
- Every docs claim enumerated in the internal ZK audit that the code does not back.

`zk-circom` is marked research-only and is not reintroduced to a release path until it
proves a statement in this spec under a named, real setup or a transparent system.

## The SRI collaboration surface

This spec is also the technical basis for a proposed collaboration with SRI CSL. The two
bodies of work Stéphane identified each have a concrete role, and much of the preparatory
work is ours to do solo — which is what makes the collaboration attractive (SRI joins a
working system with a ready integration point and a drafted formal theory, not a
whiteboard).

### First principles (the critique, stated)

The design follows an argument that a skeptical cryptographer (SRI CSL's assessment of a
competitor's ZK claims) laid out. It is worth stating in full, because every constraint
below is a consequence of it, not a preference.

The intent-to-proof pipeline has five stages:

    human intent -> NL utterance -> formal statement -> signed message -> proof of conformance

1. **Only the last stage is cryptographically provable.** What a proof can establish is
   that an agent *possesses a signed mandate* and its recorded actions *conform* to that
   mandate. That is the whole provable claim. [SIEVE], [SD-JWT], and the zkVM all operate
   here and nowhere else.
2. **The natural-language-to-formal arrow is not provable by any proof system.** No
   circuit proves that a formal statement faithfully captures an informally expressed
   human intent. Claiming to prove "end to end intended behavior" across this arrow is a
   category error, not an engineering gap. Treeship closes it with a *recorded human
   signature* on the mandate artifact, which is evidence, not proof.
3. **A signature establishes key possession, not meaning.** Whoever holds the key
   *probably* meant the message; the trust root is ultimately social and physical, not
   mathematical. This is the honest boundary already in Treeship's design: the trust root
   is the machine, and root access breaks the guarantees.

Three extensions sharpen it: **capture provenance dominates proof soundness** (a proof
over a fabricated trace proves nothing, so the trustworthiness of the inputs — attestation
class, countersignature, external-transcript capture — is the larger problem); **the
feasible ZK statement is the policy check, never model execution** (proving an LLM forward
pass in ZK is not practical, so every statement here is a predicate over a trace); and the
**formalization gap is legally unnecessary to close** (contract law binds what you signed,
not what you privately meant, so a signed mandate plus a tamper-evident action record is
exactly the evidence [EU AI Act Art. 12] and [AB 316] require).

These are not future work; they are rules the design already obeys, recorded so nothing
regresses: every statement is a predicate over a signed mandate and trace; the intent gap
stays a human signature; a signature is key possession only; capture provenance is
invested in continuously; and no statement proves model execution.

### Cyberlogic (Shankar, Ruess): two deliverables

[Cyberlogic] is SRI's logic for reasoning about attestations: principals make signed
statements ("K says P") and trust conclusions are *derivations* over those statements.
That is a description of Treeship's verifier, not a metaphor for it. Two deliverables:

1. **Formal semantics of the trust model, and a mechanized verifier-soundness proof.**
   Write Treeship's verifier as a cyberlogic theory: statements are attestations
   ("principal K says P"), pinned trust roots are axioms, and the chain walk, nonce
   binding, and revocation authority are inference rules. The payoff is specific: the
   failure class both the 0.19 audit and the ZK audit found by hand — a surface reporting
   `verified` from attacker-controlled input without a backing signature — becomes a
   *theorem the verifier is mechanically proven never to violate*. This is the formal
   version of the red-teaming already done manually, and it is CSL's home discipline.
2. **The predicate language for `present --zk`.** The disclosure-menu predicates
   ("action A conforms to policy P", "spend <= limit", "certified by some trusted
   issuer") are expressed as cyberlogic formulas, so the same formula that has precise
   meaning is the one the ZK proof establishes. Cyberlogic becomes the shared interface
   between the mandate layer and the proof layer.

   *Solo now:* draft Treeship's trust model as a cyberlogic-style theory ourselves, as
   the artifact that seeds the collaboration and directly produces the predicate language.

### SIEVE-lineage VOLE-ZK: the Track B prover in a ready socket

The [SIEVE] program (DARPA, co-led at SRI) produced VOLE-based ZK systems (Wolverine,
QuickSilver, Mac'n'Cheese, Line-Point ZK) and a standardized circuit IR. These are the
interactive, no-trusted-setup, designated-verifier prover for `present --zk` over the
challenge transcript — the SRI connection is not a cold outreach but the team that built
this class of system. Two decisions make it plug in rather than co-design:

- Build the `present --zk` / `verify-presentation --zk` surface **proof-system-agnostic**,
  implemented with the Track A zkVM first: same predicate in, same bound-to-`zk_commitment`
  interface out. The SIEVE prover later implements an interface that already exists and is
  already tested.
- Express the Statement specs in a form that targets **both** the SIEVE IR and the
  cyberlogic formulas, so the specs are the shared contract: cyberlogic gives them
  meaning, the SIEVE IR gives them a prover, Treeship gives them bound inputs.

### The split

Cyberlogic supplies the statement language and the soundness semantics; Treeship supplies
the trustworthy inputs, the deployed verifier, and the proof-system-agnostic socket;
SIEVE-class ZK supplies the interactive disclosure prover. What is solo-buildable now: the
Merkle disclosure MVP, `zk_commitment`, Track A, the agnostic `present --zk` interface,
and the first-draft cyberlogic theory. What is joint: the mechanized soundness proof, the
VOLE-ZK Track B integration, and the finalized predicate language.

## Build order

1. Deletion list + docs truth pass (no new capability claimed; removes forgeable and
   false surface). Safe, immediate.
2. `zk_commitment` at signing time: native ZK-friendly hash test-vectored against the
   circuit hash; canonical binding + mutation regression test. Foundation for both tracks
   and for the ZK presentation.
3. Merkle-committed capability set + `present --disclose <capability>`: the no-ZK
   selective-disclosure first step. Reveals one capability plus its path, hides the rest;
   ships without a ceremony and demonstrates the presentation direction end to end.
4. The formal statement specs above become the acceptance criteria for tests: every
   statement gets an adversarial test that a violating witness, a mutated public input,
   an unbound proof, and a verifier-policy mismatch are all rejected. These land before
   any command is unhidden.
5. Track A: harden the zkVM guest to Statement 3 (in-guest id re-derivation, payload
   linkage, nonce binding, abort-on-violation), wire `verify` into the CLI with a
   compile-time image-id pin, switch to accelerated crates, and add the WASM verify path.
   Build the `present --zk` / `verify-presentation --zk` surface proof-system-agnostic,
   implemented with the zkVM first, then the first transferable predicate proof
   (spend-range or policy-membership) attached to a presentation.
5b. Solo research-prep (parallel, no code dependency): draft Treeship's trust model as a
   cyberlogic-style theory, and express the Statement specs in a form that targets both
   the SIEVE IR and cyberlogic formulas. These seed the collaboration and produce the
   predicate language.
6. Track B (joint with SRI): the SIEVE designated-verifier prover against Statements 1-2
   and the interactive `present --zk` predicate proofs over the challenge transcript;
   the mechanized verifier-soundness proof in cyberlogic; the finalized predicate
   language.

## References

External work this spec builds on or maps to. Cited inline as `[Name]`.

- **[Cyberlogic]** — Shankar & Ruess, *Cyberlogic*, SRI CSL. A logic for reasoning about
  attestations and trust as derivation over signed statements.
  https://www.csl.sri.com/people/shankar/hcss03.pdf
- **[SIEVE]** — DARPA SIEVE program (Securing Information for Encrypted Verification and
  Evaluation), co-led at SRI. Produced VOLE-based zero-knowledge systems (Wolverine,
  QuickSilver, Mac'n'Cheese, Line-Point ZK) — interactive, designated-verifier, no
  trusted setup — and a standardized circuit intermediate representation (the SIEVE IR).
- **[SD-JWT]** — IETF, *Selective Disclosure for JWTs (SD-JWT)*,
  draft-ietf-oauth-selective-disclosure-jwt. The salted-per-claim-digest construction the
  selective-disclosure tier ports onto Treeship's DSSE payloads.
- **[RISC Zero]** — the RISC Zero zkVM: STARK-based, transparent (no trusted setup),
  general-purpose proving over a RISC-V guest. Track A's non-interactive prover.
- **[DSSE]** — Dead Simple Signing Envelope (in-toto / Sigstore). Treeship's envelope
  format; the signature the selective-disclosure digests live inside.
- **[EU AI Act Art. 12]**, **[AB 316]** — the regulatory regimes that require a signed
  mandate plus a tamper-evident action record (and do *not* require proving intent),
  which is why the formalization gap is legally unnecessary to close.
