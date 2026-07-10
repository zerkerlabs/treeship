# Zero-knowledge verification, rebuilt statement-first

**Status:** draft, not implemented. Supersedes the experimental `zk-circom` Groth16 path.
**Pairs with:** [transparency-log](./transparency-log.md), [registry-topology](./registry-topology.md), [protocol-integration](./protocol-integration.md)
**Last updated:** 2026-07-10

## Why this document exists

Treeship shipped an experimental ZK layer (Circom/Groth16 circuits, a RISC Zero zkVM
path) behind `--features zk`, hidden from help and excluded from release binaries. In
July 2026 we put that layer through the same scrutiny a skeptical cryptographer would
apply: *what is the precise formal statement each proof establishes, and does it equal
the statement the docs claim?* It did not pass. The Groth16 circuits had no phase-2
ceremony (forgeable by construction), the `valid` signal was an output never asserted
to be 1, three of four circuits left the artifact binding unconstrained, and the
verifier checked a proof only against its own recorded public signals. None of this
shipped in a release binary, but the docs described capabilities the code did not have.

This spec is the rebuild. Its organizing principle is one sentence:

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

This spec is also the technical basis for a proposed collaboration with SRI CSL,
combining two of their bodies of work with Treeship's deployed capture layer:

- **Cyberlogic (Shankar, Ruess)** as the formal semantics of the mandate and
  attestation layer. Treeship statements already behave as cyberlogic utterances
  ("principal K says P"); the verifier's trust policy as trust axioms; chain
  verification as proof checking. Formalizing that correspondence gives the mandate
  layer real semantics without pretending to close the intent gap.
- **SIEVE-lineage VOLE-ZK** as the Track B disclosure mechanism, in the
  designated-verifier model that matches Treeship's present/verify-presentation flow.

Cyberlogic supplies the statement language, Treeship supplies the trustworthy inputs
and the deployed verifier, and SIEVE-class ZK supplies selective disclosure over the
conformance derivation. Track A (the zkVM/browser path) is buildable now without the
collaboration; Track B is the joint research track.

## Build order

1. Deletion list + docs truth pass (no new capability claimed; removes forgeable and
   false surface). Safe, immediate.
2. `zk_commitment` at signing time: native ZK-friendly hash test-vectored against the
   circuit hash; canonical binding + mutation regression test. Foundation for both tracks.
3. The formal statement specs above become the acceptance criteria for tests: every
   statement gets an adversarial test that a violating witness, a mutated public input,
   an unbound proof, and a verifier-policy mismatch are all rejected. These land before
   any command is unhidden.
4. Track A: harden the zkVM guest to Statement 3 (in-guest id re-derivation, payload
   linkage, nonce binding, abort-on-violation), wire `verify` into the CLI with a
   compile-time image-id pin, switch to accelerated crates, and add the WASM verify path.
5. Track B: open the SIEVE designated-verifier collaboration against Statements 1-2.
