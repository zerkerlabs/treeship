# Merkle Consistency Proofs (transparency-log slice 3)

**Status:** draft, NOT implemented — deliberately deferred to a careful, dedicated build
**Pairs with:** [transparency-log](./transparency-log.md), `packages/core/src/merkle/tree.rs`
**Last updated:** 2026-06-24

## What this is

The append-only guarantee for the transparency log: a proof that a later checkpoint (tree of size *n*) **extends** an earlier one (size *m ≤ n*), i.e. the first *m* leaves are unchanged and only appends happened. This is what makes "nothing was rewritten" cryptographic rather than trust-on-faith. Inclusion proofs (which we have) prove an entry is *in* a tree; consistency proves the tree's *history was not rewritten*.

## Why it is deferred, not rushed

Two real obstacles surfaced when scoping it, both worth stating plainly:

1. **The tree shape is not textbook RFC 6962.** `MerkleTree::compute_root` builds the tree **level by level, promoting the unpaired last node** at each level. RFC 6962's MTH recurses on a split at the largest power of two `< n`. These *coincide for many sizes*, but coinciding for the sizes you happen to test is not a proof they coincide for all `n`. A consistency-proof algorithm copied from RFC 6962 may verify wrongly for some sizes. The algorithm must be **derived for this exact construction** (or the construction proven equivalent to RFC 6962 first), not assumed.
2. **A wrong consistency verifier fails open.** It returns "consistent" for a rewritten log. Per the repo policy, that is worse than not shipping it. This primitive earns careful, dedicated implementation with fresh attention, not a tail-of-session bolt-on.

## API (core)

```rust
impl MerkleTree {
    /// Generate a consistency proof from this tree (size n) to an earlier
    /// size m. Prover side; needs all leaves.
    pub fn consistency_proof(&self, old_size: usize) -> Option<Vec<String>>;
}

/// Verify, offline, that the tree of `new_size`/`new_root` extends the tree of
/// `old_size`/`old_root`: the proof reconstructs BOTH roots and they match.
pub fn verify_consistency(
    version: u8,
    old_size: usize, old_root_hex: &str,
    new_size: usize, new_root_hex: &str,
    proof: &[String],
) -> bool;
```

## The test plan is the safety net

Because the tree is non-standard, the validating test is **round-trip against the existing, tested `compute_root`** (the ground truth for this shape):

- For many `(m, n)` with `1 ≤ m ≤ n` and varied `n` (powers of two, odd, n-1, etc.): build a tree of `n` leaves, take `root_m = compute_root(leaves[0..m])` and `root_n = compute_root(leaves[0..n])`, generate the consistency proof, and assert `verify_consistency(.., m, root_m, n, root_n, proof)` is **true**. A wrong algorithm yields reconstructed roots that do not match `compute_root` and the test fails, that is what makes it safe.
- **Tamper rejection**: mutate any proof element, `old_root`, or `new_root` → must be **false**.
- **Edge cases**: `m == n` (empty proof), `m == 0`, `m == 1`, `n` a power of two.
- Cross-check a handful of `(m, n)` against an independent reference implementation before trusting it in production.

## Then the rest of slice 3 (after the primitive)

1. **Hub**: a consistency endpoint between two checkpoint sizes (and per-dock checkpoint handling, since checkpoints are ship-scoped, the resolver/audit needs the agent's dock context to pick the right checkpoint chain).
2. **CLI**: `treeship audit` witnesses checkpoints (pins the last-seen `{index, size, root}` per hub) and, on re-audit, fetches the consistency proof and verifies the new checkpoint extends the witnessed one, reporting `consistent (extends checkpoint #k)` or `DIVERGENCE — history rewritten`.

## First slice to build

The **core primitive** (`consistency_proof` + `verify_consistency`) with the round-trip + tamper + edge-case tests above, behind no network or CLI surface. It is self-contained, fully testable offline, and the one piece that must be exactly right. Everything else (Hub endpoint, `audit` witnessing) is plumbing on top and comes after the primitive is proven.
