# AI-assisted development policy

This policy applies to ALL contributors to Treeship, whether human or AI agent.
It exists because AI-generated code can pass review and tests while still failing
in production, under load, or under adversarial inspection. The policy targets
those failure modes specifically.

Treeship is a cryptographic trust layer. Its job is to produce signed artifacts
that hold up to adversarial inspection by people who do not trust us. That makes
the bar higher than for normal software: a verifier that returns `Ok` for the
wrong reason is worse than a verifier that crashes, because nobody investigates
a green check. Most of the rules below come from real bugs caught in the v0.10.x
audit waves, where a less rigorous fix would have shipped a forgery vector.

---

## What we do not accept

Every item below names a specific failure mode and the kind of patch that
produces it. Reviewers (human and AI) are expected to refuse PRs that exhibit
these patterns, even if tests pass.

### 1. Silent fallbacks on encoding, decoding, or signing failures

`serde_json::to_vec(x).unwrap_or_default()` in a path that produces signed bytes
is a forgery vector. Empty bytes verify against themselves: two unrelated
artifacts that both hit the failure case will cross-validate. The same applies
to `.unwrap_or(0)` on a sequence number, `.unwrap_or(Vec::new())` on a hash
input, or any `.ok()` that drops an error in a path that produces or consumes
signed material.

Concrete example, from the v0.10.4 audit: four `serde_json::to_vec(...)
.unwrap_or_default()` sites in `approval_use.rs` were silently signing the
sha256 of an empty byte string when encoding failed. The case is unreachable
under the current schema, but the failure mode is catastrophic in shape, so the
fix replaced all four with explicit panics carrying a "report bug" message.

Rule: in any signing, verifying, hashing, or canonical-bytes path, the function
must either return `Result` and surface the error, or panic with an actionable
message. It must not produce a default value that downstream code treats as
valid signed input.

### 2. Verifier loops that pass vacuously on empty input

A `for sig in envelope.signatures` loop that returns `Ok(())` when there are
zero signatures is a verifier that accepts unsigned envelopes. The bug isn't in
the loop; it's that the precondition (at least one signature) was never
checked.

From the v0.10.3 audit: `Verifier::verify` returned `Ok` on envelopes with an
empty signature list. `bundle::import` wrote every envelope to storage without
verifying signatures. Both shipped a `chain_linkage = pass` row to the UI for a
check the verifier never actually performed.

Rule: every verification function must explicitly assert its preconditions
(non-empty signatures, algorithm in allow-list, signer in trust roots) before
the verification loop. Add a regression test that constructs the empty case and
expects `Err`.

### 3. Lock-acquisition fall-through

`if let Ok(_lock) = file.try_lock_exclusive_timeout(50ms) { ... write ... }`
that proceeds to write whether the lock was acquired or not is a concurrency
bug that silently corrupts data. The compiler is happy because `try_lock`
returned a `Result`; the bug is that the `Err` branch wrote anyway.

From the v0.10.3 audit lane F: `session/event_log.rs::append` fell through a
lock-acquisition timeout and wrote events without holding the lock, colliding
`sequence_no` values under Claude Code's PostToolUse hook concurrency. The fix
uses blocking `lock_exclusive()` and tightens the locked region to a closure.

Rule: any code that acquires a file lock, mutex, or semaphore for a write path
must (a) handle the acquire-failure branch explicitly, and (b) include a
multi-thread test that asserts the invariant the lock is protecting.

### 4. TOCTOU between permission check and read

Opening a file twice, once to `stat` permissions and once to `read` contents,
allows an attacker with write access to the directory to swap the file
between the two opens. The attacker presents an owner-only file to pass the
gate, then races a loose-perm file with attacker-controlled bytes into place
before the read.

From the v0.10.4 audit: `Store::signer()` in `keys/mod.rs` and
`TrustRootStore::open()` in `trust/mod.rs` both had this shape. The fix is
single-open: open once, `fstat` the descriptor, read from the same descriptor.
The path is never re-resolved after the open, so the inode is pinned.

Rule: any security-sensitive file read must open the file exactly once and run
all checks (permission, ownership, size, magic bytes) on the same descriptor.
No re-opens. No path re-resolution between check and use.

### 5. Mixed randomness sources without justification

`thread_rng()` for security-sensitive randomness (key generation, nonces, salts,
challenge tokens) is wrong. `thread_rng` is seeded once and reseeds rarely; in
some build configurations it can be predicted from a process snapshot. The
right source for security material is `OsRng`, which goes directly to the OS
CSPRNG on every call.

From the v0.10.4 audit P1: `keys/mod.rs` had a mix of `thread_rng` and `OsRng`
calls in the same module. The fix unified all security-sensitive randomness on
`OsRng` and annotated each remaining `thread_rng` site with an inline rationale
(test-only, non-security).

Rule: every RNG call in a security-sensitive path uses `OsRng` (or an explicit
CSPRNG wrapper). Every non-`OsRng` call in or near `packages/core/src/keys`,
`packages/core/src/attestation`, `packages/core/src/merkle`, or
`packages/core/src/trust` must carry an inline comment explaining why it is
safe.

### 6. Wire-controllable fields not bound into the canonical signing bytes

If a field appears in the JSON envelope, gets read by the verifier, and
participates in dispatch (algorithm selection, version selection, display, or
trust decisions), it MUST be bound into the canonical signing bytes. Otherwise
an attacker can take a legitimately signed envelope, mutate that field on the
wire, and still verify.

From the v0.10.3 audit: `merkle_version` was added as a dispatch field for the
RFC 9162 leaf/internal-node domain separation fix, but the v1 canonical did not
bind it. An attacker could flip `merkle_version: 2 → 1` on a v2-signed
checkpoint and force verification through the v1 hashing path.

From the v0.10.4 follow-up: `algorithm`, `zk_proof`, and `canonical_version`
were the same bug class on the same struct. The v3 canonical binds all of them,
including a downgrade-by-relabel binding on `canonical_version` itself.

Rule: when adding a field to a signed struct, the PR must (a) decide explicitly
whether the field participates in dispatch or display, (b) bind it into the
canonical bytes if so, and (c) add a regression test that mutates the field on
a signed envelope and asserts verification fails. Reviewers must check this.

### 7. Toolchain or build-config files that silently change behavior on
contributor machines

A `rust-toolchain.toml` without an explicit `targets =` list silently breaks
cross-compile for contributors who try to build wasm or musl targets without
running `rustup target add` manually. The contributor sees a compile error far
from the cause and assumes their setup is broken.

A `.rustfmt.toml` or `clippy.toml` that diverges from CI's effective config
silently produces formatting churn or false-positive lint failures on local
runs.

From the v0.10.4 retro: `rust-toolchain.toml` was added without `targets =
["wasm32-unknown-unknown"]`, breaking wasm builds for new contributors until
the omission was caught and documented.

Rule: any build-config file added at repo root must (a) be the same config CI
uses, and (b) include every target, component, and lint setting required to
build every artifact this repo ships. If it can be omitted on local runs, it
should be omitted in CI too.

### 8. Tests that pass for the wrong reason

A test that asserts `result.is_ok()` after a verification call is not a test of
verification; it is a test that the call did not panic. If the verifier returns
`Ok` for an unsigned envelope, that test passes. The test must assert the
specific invariant: signature count, signer identity, payload digest match,
trust-root membership.

Common shapes that are not real tests:

- `assert!(parse(input).is_ok())` for a parser that returns `Ok` on any input.
- `assert_eq!(actual, actual)` where both sides come from the same computation.
- Mocking the function under test, then asserting the mock was called.
- A roundtrip test (`encode` then `decode`) that passes when both functions
  share the same bug.

Rule: every new test must, on a first read, make it obvious what would fail it.
If you cannot construct a minimal mutation of the system under test that makes
the test fail, the test is not testing anything.

### 9. Fabricated test vectors

Test fixtures that were "computed" by running the system being tested and
pasting the output back into the test are not test fixtures. They lock in
whatever the code did the day they were generated, including bugs.

A real test vector either (a) comes from an external authority (DSSE spec
examples, RFC 9162 reference vectors, ed25519-dalek test suite), or (b) is
hand-computed from first principles in a comment next to the test.

From the cross-SDK contract suite: every vector in `tests/cross-sdk/` has its
provenance recorded — which signer generated it, which version, which corpus
seed. Adding a vector requires showing the work, not pasting the bytes.

Rule: any test fixture larger than ~32 bytes must include a comment showing
where the bytes came from. If they came from the code under test, the test
is theater and must be rewritten with a real reference.

### 10. Commenting out broken code or skipping failing tests

`// TODO: re-enable after fix` on a `#[ignore]`d test or commented-out
assertion is a way of shipping the bug while suppressing the alarm. The test
was telling you something; turning it off does not fix it.

The acceptable patterns:

- Delete the test and write a regression test for what you actually intended.
- File a tracked issue, link it in the `#[ignore = "issue #123"]` annotation,
  and assign it a milestone.
- If the test was wrong, fix the test and explain in the commit message why
  the previous assertion was incorrect.

Rule: a PR that adds `#[ignore]` without a linked issue number, or comments out
an assertion without explaining why in the diff, does not land. A PR that adds
a `// TODO: fix this` to suppress a known bug does not land.

### 11. Scope drift and theater commits

A "fix typo" commit that also reformats 400 lines, renames three variables,
and inlines a helper function is not a typo fix. It hides real changes from
review.

A "refactor for clarity" PR that touches a security-sensitive code path
without changing behavior is asking reviewers to assume the refactor is
behavior-preserving without giving them a way to check. In a crypto codebase,
that is a bad trade.

Rule: one logical change per commit. Mechanical reformatting goes in its own
commit. Refactors of security-sensitive code (anything under
`packages/core/src/attestation`, `keys`, `merkle`, `trust`, or `verifier`)
require either a behavior-preserving proof (same test vectors pass before and
after) or an explicit behavior-change note in the PR.

### 12. Premature abstractions and speculative generality

A trait with one implementation, a generic parameter with one concrete type, or
a config option with one value is not an abstraction; it is dead code that
makes the codebase harder to read.

The right time to introduce an abstraction is when there are at least two
concrete cases AND the cost of the duplication is real. The wrong time is when
you are guessing about future requirements.

Rule: new traits, generics, or config knobs must point at the concrete second
caller in the PR description. "We might want to support X" is not a second
caller. "Hub also needs this for Y, see PR #N" is.

---

## What we expect

### Read the existing code before changing it

`AGENTS.md` §11 lists the read order for the core. Read those files before
proposing changes to attestation, signing, or verification. Most "obvious"
refactors in those files break a cryptographic invariant that is not obvious
from the diff.

### Cite the failure mode in commit messages

Commit bodies should explain WHY (the bug, the attack, the user impact) more
than WHAT (the diff already shows that). A commit message that says "fix bug"
is not reviewable. A commit message that says "approval signing fell back to
empty bytes on serde encode failure; two artifacts that both hit the failure
would cross-validate; replaced with panic carrying report-bug message" is
reviewable.

### Add regression tests next to the bug fix

Every security or correctness fix lands with a test that fails before the fix
and passes after. The test name should describe the bug, not the function.
`record_digests_never_match_empty_bytes_sha256` is a good test name because the
name itself documents the invariant.

### Run the cross-SDK contract suite when touching wire formats

`./tests/cross-sdk/run.sh` is the contract test for anything that affects the
receipt format or either SDK. CI runs it across `{ubuntu, macos} × {Node 20,
22} × {Python 3.11, 3.12}`. If your change might affect cross-language
consumers, run it locally before pushing.

### Prefer explicit errors over silent recovery

`Result<T, E>` over `Option<T>` when the failure carries information. `panic!`
with an actionable message over `unwrap_or_default()` when the failure is
unreachable but catastrophic in shape. `eprintln!` warnings over silent
fallthrough when an environment override is honored.

### Document on-disk and wire-format invariants in the code

If a struct's byte layout is signed, the layout comment lives on the struct.
If a field is bound into a canonical signing format, the binding lives in a
comment on the field. The contract that a verifier enforces is described in
the verifier's doc-comment, not only in `AGENTS.md`.

---

## How we enforce

This policy is currently enforced by review, not by CI. That is a known gap;
adding automated checks for the patterns above is on the roadmap. In the
meantime:

- PRs that touch `packages/core/src/{attestation,keys,merkle,trust,verifier}`
  get extra review attention for the patterns in §1–§6.
- PRs that add `#[ignore]`, comment out assertions, or change cryptographic
  invariants without an explanation are blocked at review.
- Audit waves (v0.10.3, v0.10.4) sweep the codebase for new instances of the
  bug classes above. The next audit will check for new uses of
  `unwrap_or_default()` in signed-bytes paths and new TOCTOU shapes in
  permission-sensitive file reads.
- The release preflight (`scripts/check-release-versions.py` and friends)
  enforces version invariants; future preflights will add policy-pattern
  checks.

A reviewer (human or AI) who waves through a PR that violates this policy is
contributing the failure mode. "I didn't notice" is the failure mode the policy
exists to prevent.

---

## Examples

### Example A: silent unwrap (refused)

```rust
// Refused: empty bytes verify against themselves.
let signing_bytes = serde_json::to_vec(&payload).unwrap_or_default();
sign(&signing_bytes)
```

```rust
// Accepted: unreachable today, but if the schema ever introduces a fallible
// field (e.g. f32/f64 with NaN), the failure surfaces loudly instead of
// silently producing a forgery vector.
let signing_bytes = serde_json::to_vec(&payload).unwrap_or_else(|e| {
    panic!("approval canonical encode failed; please report a bug. err: {e}")
});
sign(&signing_bytes)
```

### Example B: verifier loop (refused)

```rust
// Refused: returns Ok for an envelope with zero signatures.
pub fn verify(&self, env: &Envelope) -> Result<(), Error> {
    for sig in &env.signatures {
        self.verify_one(env, sig)?;
    }
    Ok(())
}
```

```rust
// Accepted: explicit precondition + regression test.
pub fn verify(&self, env: &Envelope) -> Result<(), Error> {
    if env.signatures.is_empty() {
        return Err(Error::ZeroSignatures);
    }
    for sig in &env.signatures {
        self.verify_one(env, sig)?;
    }
    Ok(())
}
```

### Example C: wire-controllable dispatch field (refused)

```rust
// Refused: merkle_version controls dispatch but is not bound into the
// canonical, so an attacker can flip 2 -> 1 on the wire and force the v1
// hashing path on a v2-signed checkpoint.
fn canonical_for_signing(&self) -> String {
    format!("v2|{}|{}|{}", self.index, self.root, self.tree_size)
}
```

```rust
// Accepted: merkle_version is bound, regression test mutates it on a signed
// envelope and asserts Err.
fn canonical_for_signing(&self) -> String {
    format!(
        "v3|{}|{}|{}|{}|{}",
        self.canonical_version,
        self.merkle_version,
        self.index, self.root, self.tree_size,
    )
}
```

### Example D: TOCTOU on a sensitive file (refused)

```rust
// Refused: two opens. An attacker can swap the file between them.
check_key_file_perms(&path)?;
let bytes = std::fs::read(&path)?;
```

```rust
// Accepted: single open. fstat on the descriptor. Read from the same
// descriptor. Inode is pinned.
let mut file = std::fs::File::open(&path)?;
check_open_key_file_perms(&file)?;
let mut bytes = Vec::new();
file.read_to_end(&mut bytes)?;
```

### Example E: test that fails for the wrong reason (refused)

```rust
// Refused: passes when verify() returns Ok for any reason, including for
// envelopes with zero signatures or untrusted issuers.
#[test]
fn verifies() {
    let env = build_envelope();
    let v = Verifier::new();
    assert!(v.verify(&env).is_ok());
}
```

```rust
// Accepted: asserts the specific invariant. The test name documents the
// invariant. A future reader can tell at a glance what would break the test.
#[test]
fn rejects_envelope_with_zero_signatures() {
    let env = build_envelope_with_no_sigs();
    let v = Verifier::new();
    assert!(matches!(v.verify(&env), Err(Error::ZeroSignatures)));
}
```

---

## When this policy applies

Every PR. Every commit. Every doc change that touches code semantics. Every
test added or removed. By every contributor — human, Claude Code, Codex,
Cursor, OpenClaw, Hermes, or any other agent that opens a PR against this
repo.

The policy applies to:

- Code you write
- Tests you add, modify, or remove
- Docs that describe code behavior (a docs change that describes the wrong
  invariant is as dangerous as a code change that violates it)
- Commits you make
- PRs you open or review

When in doubt, prefer the policy over speed. A slower PR that respects the
policy is cheaper than a fast PR that ships a forgery vector and has to be
revoked via the `.well-known/treeship/revoked.json` channel.
