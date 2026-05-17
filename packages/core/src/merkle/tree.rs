use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

/// Errors raised by Merkle primitives and tree construction.
///
/// Currently only one variant: an unknown `merkle_version` byte. Kept as
/// an enum so future version-specific validation can be added without
/// breaking the public signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MerkleError {
    /// The supplied `merkle_version` is neither v1 nor v2 (the only
    /// recognised versions). Surfaces at `MerkleTree::with_version`,
    /// at every callsite that constructs a tree from a receipt, and
    /// at proof verification.
    UnknownVersion(u8),
}

impl std::fmt::Display for MerkleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownVersion(v) => write!(
                f,
                "unknown merkle_version {} (expected {} or {})",
                v, MERKLE_VERSION_V1, MERKLE_VERSION_V2,
            ),
        }
    }
}

impl std::error::Error for MerkleError {}

/// Direction of a sibling in the Merkle proof path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Direction {
    Left,
    Right,
}

/// One step in an inclusion proof path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStep {
    pub direction: Direction,
    /// Hex-encoded hash of the sibling node.
    pub hash: String,
}

/// Merkle tree algorithm identifier for forward/backward compatibility.
pub const MERKLE_ALGORITHM_V1: &str = "sha256-duplicate-last";
pub const MERKLE_ALGORITHM_V2: &str = "sha256-rfc9162";

/// Merkle format version byte. Distinguishes pre-domain-separation hashing
/// (v1, used through v0.10.2) from RFC 9162 domain-separated hashing (v2,
/// default from v0.10.3 onward).
///
/// - `1` — legacy: `sha256(artifact_id)` for leaves, `sha256(L || R)` for
///   internal nodes. No domain separation. Vulnerable to second-preimage
///   confusion between leaf and internal nodes when the artifact ID happens
///   to be 32 or 64 bytes. Retained ONLY so v0.10.2-and-earlier receipts
///   continue to verify during the deprecation window.
/// - `2` — RFC 9162: `sha256(0x00 || artifact_id_bytes)` for leaves,
///   `sha256(0x01 || L || R)` for internal nodes. Leaf and internal
///   pre-images cannot collide.
///
/// v1 verification is scheduled for removal in v0.13.0.
pub const MERKLE_VERSION_V1: u8 = 1;
pub const MERKLE_VERSION_V2: u8 = 2;

/// Default merkle version used by `#[serde(default = ...)]` so receipts
/// produced before the field existed deserialize as v1 (the pre-domain-
/// separation hashing that was in effect at the time).
pub fn default_merkle_version_v1() -> u8 {
    MERKLE_VERSION_V1
}

// ── Domain-separated hash primitives ─────────────────────────────────
//
// These are crate-internal so the version dispatch lives in one place.
// Tests can reach them through `#[cfg(test)]` re-exports if they need
// to pin a byte-identical output.

/// v1 (legacy) leaf hash: `sha256(artifact_id_bytes)`. No domain prefix.
pub(crate) fn hash_leaf_v1(artifact_id: &str) -> [u8; 32] {
    Sha256::digest(artifact_id.as_bytes()).into()
}

/// v1 (legacy) internal node hash: `sha256(left || right)`. No domain prefix.
pub(crate) fn hash_internal_v1(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// v2 leaf hash per RFC 9162: `sha256(0x00 || artifact_id_bytes)`.
pub(crate) fn hash_leaf_v2(artifact_id: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(artifact_id.as_bytes());
    h.finalize().into()
}

/// v2 internal node hash per RFC 9162: `sha256(0x01 || left || right)`.
pub(crate) fn hash_internal_v2(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Version-dispatched leaf hash. Rejects unknown versions instead of
/// falling back: a silent fallback to v1 was the original downgrade
/// vector — a receipt could claim `merkle_version: 99` and get
/// recomputed under v1 hashing.
pub(crate) fn hash_leaf(version: u8, artifact_id: &str) -> Result<[u8; 32], MerkleError> {
    match version {
        MERKLE_VERSION_V1 => Ok(hash_leaf_v1(artifact_id)),
        MERKLE_VERSION_V2 => Ok(hash_leaf_v2(artifact_id)),
        other => Err(MerkleError::UnknownVersion(other)),
    }
}

/// Version-dispatched internal node hash. Rejects unknown versions
/// for the same reason as [`hash_leaf`].
pub(crate) fn hash_internal(
    version: u8,
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<[u8; 32], MerkleError> {
    match version {
        MERKLE_VERSION_V1 => Ok(hash_internal_v1(left, right)),
        MERKLE_VERSION_V2 => Ok(hash_internal_v2(left, right)),
        other => Err(MerkleError::UnknownVersion(other)),
    }
}

/// An inclusion proof: the sibling path from a leaf to the root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: usize,
    /// Hex-encoded leaf hash.
    pub leaf_hash: String,
    pub path: Vec<ProofStep>,
    /// Algorithm used to build this proof. Missing = v1 (duplicate-last).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    /// Merkle format version byte. Drives the leaf and internal hash
    /// dispatch at verify time. Missing on pre-v0.10.3 proofs — defaults
    /// to `1` (no domain separation) so v0.10.2 receipts continue to
    /// verify. New proofs always serialize `2`.
    #[serde(default = "default_merkle_version_v1")]
    pub merkle_version: u8,
}

/// An append-only binary Merkle tree.
///
/// Domain separation per RFC 9162 (when `version == 2`): leaves are
/// `sha256(0x00 || artifact_id)` and internal nodes are
/// `sha256(0x01 || left || right)`. Pre-domain-separation hashing
/// (`version == 1`) is retained ONLY for the deprecation window so
/// v0.10.2-and-earlier receipts continue to round-trip; new trees
/// default to v2.
///
/// Odd leaf counts are handled by promoting the unpaired node to the
/// next level without hashing, matching RFC 9162 (Certificate
/// Transparency) construction.
pub struct MerkleTree {
    /// All leaf hashes in insertion order.
    leaves: Vec<[u8; 32]>,
    /// Hash version used for leaf + internal-node hashing.
    version: u8,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    /// New tree using the current default version (v2, domain-separated).
    pub fn new() -> Self {
        // SAFETY: V2 is a recognised version, so with_version cannot fail.
        Self::with_version(MERKLE_VERSION_V2)
            .expect("MERKLE_VERSION_V2 is always a valid version")
    }

    /// New tree pinned to an explicit hash version. Returns
    /// `Err(MerkleError::UnknownVersion)` if `version` is anything other
    /// than [`MERKLE_VERSION_V1`] or [`MERKLE_VERSION_V2`]. Validating
    /// at construction time is what lets `append`, `root`, and
    /// `inclusion_proof` keep their infallible signatures.
    pub fn with_version(version: u8) -> Result<Self, MerkleError> {
        if version != MERKLE_VERSION_V1 && version != MERKLE_VERSION_V2 {
            return Err(MerkleError::UnknownVersion(version));
        }
        Ok(Self { leaves: Vec::new(), version })
    }

    /// Hash version this tree builds proofs under.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Append an artifact ID as a new leaf. Returns the leaf index.
    pub fn append(&mut self, artifact_id: &str) -> usize {
        // Invariant: `self.version` was validated by `with_version`, so
        // hash_leaf cannot return UnknownVersion here.
        let hash = hash_leaf(self.version, artifact_id)
            .expect("tree version validated at construction");
        self.leaves.push(hash);
        self.leaves.len() - 1
    }

    /// Number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Compute the root hash. Returns `None` for an empty tree.
    pub fn root(&self) -> Option<[u8; 32]> {
        if self.leaves.is_empty() {
            return None;
        }
        Some(self.compute_root(&self.leaves))
    }

    /// Height of the tree: ceil(log2(n_leaves)).
    pub fn height(&self) -> usize {
        if self.leaves.len() <= 1 {
            return 0;
        }
        (self.leaves.len() as f64).log2().ceil() as usize
    }

    /// Generate an inclusion proof for the leaf at `leaf_index`.
    pub fn inclusion_proof(&self, leaf_index: usize) -> Option<InclusionProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut path = Vec::new();
        let mut idx = leaf_index;
        let mut level: Vec<[u8; 32]> = self.leaves.clone();

        while level.len() > 1 {
            // RFC 9162: if idx has a sibling, add it to the proof path.
            // If idx is the unpaired last node, it promotes without a sibling step.
            if idx + 1 < level.len() && idx % 2 == 0 {
                // Sibling is to the right
                path.push(ProofStep {
                    direction: Direction::Right,
                    hash: hex::encode(level[idx + 1]),
                });
            } else if idx % 2 == 1 {
                // Sibling is to the left
                path.push(ProofStep {
                    direction: Direction::Left,
                    hash: hex::encode(level[idx - 1]),
                });
            }
            // else: unpaired last node, no sibling step needed

            // Move up: compute parent hashes (RFC 9162 promotion). The
            // tree-version invariant guarantees hash_internal cannot
            // return UnknownVersion.
            let mut next_level = Vec::with_capacity((level.len() + 1) / 2);
            let mut i = 0;
            while i + 1 < level.len() {
                next_level.push(
                    hash_internal(self.version, &level[i], &level[i + 1])
                        .expect("tree version validated at construction"),
                );
                i += 2;
            }
            if i < level.len() {
                next_level.push(level[i]);
            }
            level = next_level;

            idx /= 2;
        }

        Some(InclusionProof {
            leaf_index,
            leaf_hash: hex::encode(self.leaves[leaf_index]),
            path,
            algorithm: Some(match self.version {
                MERKLE_VERSION_V1 => MERKLE_ALGORITHM_V1.to_string(),
                _ => MERKLE_ALGORITHM_V2.to_string(),
            }),
            merkle_version: self.version,
        })
    }

    /// Verify an inclusion proof against a hex-encoded root hash.
    ///
    /// Recomputes the root from `artifact_id` + the proof path and checks
    /// that it matches `root_hex`. Fully offline, no tree state needed.
    ///
    /// `expected_version` is the **trusted** merkle version — typically the
    /// merkle_version pulled from a signature-verified checkpoint or from
    /// the parent receipt's merkle section. The verifier hashes under
    /// `expected_version` and *additionally* rejects the proof if
    /// `proof.merkle_version != expected_version`. This is what closes
    /// the downgrade vector: the version that drives hashing is taken
    /// from a trusted source, not from the (attacker-controlled) proof
    /// blob.
    ///
    /// Rejects:
    /// - `expected_version` outside {1, 2}
    /// - `proof.merkle_version != expected_version`
    /// - in v2, an empty path with `leaf_index != 0` — closes the
    ///   internal-node-as-leaf impersonation that v1 permitted.
    pub fn verify_proof(
        expected_version: u8,
        root_hex: &str,
        artifact_id: &str,
        proof: &InclusionProof,
    ) -> bool {
        // The trusted version itself must be a known one. Unknown =
        // misconfiguration upstream; reject loudly.
        if expected_version != MERKLE_VERSION_V1 && expected_version != MERKLE_VERSION_V2 {
            return false;
        }

        // The proof's self-declared version must agree with the trusted
        // version. Mismatch = downgrade attempt (or honest drift —
        // either way, refuse).
        if proof.merkle_version != expected_version {
            return false;
        }

        // Validate algorithm string ONLY when present. v0.10.2 receipts
        // carry `algorithm = "sha256-rfc9162"` even though no domain
        // separation was applied — we no longer let the string drive
        // dispatch; merkle_version does. Unknown strings still reject.
        if let Some(algo) = proof.algorithm.as_deref() {
            if algo != MERKLE_ALGORITHM_V1 && algo != MERKLE_ALGORITHM_V2 {
                return false;
            }
        }

        // v2 hardens the single-leaf path. An empty proof path is only
        // legitimate when this leaf IS the root (single-leaf tree at
        // index 0). In v1 we cannot enforce this without breaking
        // legacy receipts, so the check is v2-only.
        if expected_version == MERKLE_VERSION_V2 && proof.path.is_empty() && proof.leaf_index != 0 {
            return false;
        }

        let current: [u8; 32] = match hash_leaf(expected_version, artifact_id) {
            Ok(h) => h,
            Err(_) => return false,
        };
        // Verify leaf hash matches artifact
        if hex::encode(current) != proof.leaf_hash {
            return false;
        }

        let mut current = current;
        for step in &proof.path {
            let sibling = match hex::decode(&step.hash) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => return false,
            };

            current = match step.direction {
                Direction::Right => match hash_internal(expected_version, &current, &sibling) {
                    Ok(h) => h,
                    Err(_) => return false,
                },
                Direction::Left => match hash_internal(expected_version, &sibling, &current) {
                    Ok(h) => h,
                    Err(_) => return false,
                },
            };
        }

        hex::encode(current) == root_hex
    }

    /// Internal: compute root from a slice of leaf hashes.
    /// RFC 9162 construction: odd nodes are promoted without hashing.
    fn compute_root(&self, leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.len() == 1 {
            return leaves[0];
        }
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            let mut next_level = Vec::with_capacity((level.len() + 1) / 2);
            let mut i = 0;
            while i + 1 < level.len() {
                // Invariant: tree version validated at construction.
                next_level.push(
                    hash_internal(self.version, &level[i], &level[i + 1])
                        .expect("tree version validated at construction"),
                );
                i += 2;
            }
            // RFC 9162: promote unpaired node without hashing
            if i < level.len() {
                next_level.push(level[i]);
            }
            level = next_level;
        }
        level[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_leaf_root_is_leaf_hash() {
        // Tree built with the current default (v2). The root of a
        // single-leaf tree equals the v2 leaf hash of the artifact.
        let mut tree = MerkleTree::new();
        tree.append("art_abc123");
        let root = tree.root().unwrap();
        let expected = hash_leaf_v2("art_abc123");
        assert_eq!(root, expected);
    }

    #[test]
    fn single_leaf_root_is_leaf_hash_v1_legacy() {
        let mut tree = MerkleTree::with_version(MERKLE_VERSION_V1).unwrap();
        tree.append("art_abc123");
        let root = tree.root().unwrap();
        let expected = hash_leaf_v1("art_abc123");
        assert_eq!(root, expected);
    }

    #[test]
    fn inclusion_proof_verifies() {
        let mut tree = MerkleTree::new();
        let ids = ["art_a", "art_b", "art_c", "art_d"];
        for id in &ids {
            tree.append(id);
        }

        let root = hex::encode(tree.root().unwrap());
        let proof = tree.inclusion_proof(1).unwrap(); // art_b at index 1

        assert!(MerkleTree::verify_proof(MERKLE_VERSION_V2, &root, "art_b", &proof));
    }

    #[test]
    fn wrong_artifact_fails_verification() {
        let mut tree = MerkleTree::new();
        tree.append("art_a");
        tree.append("art_b");

        let root = hex::encode(tree.root().unwrap());
        let proof = tree.inclusion_proof(0).unwrap(); // proof for art_a

        // Try to verify art_WRONG against art_a's proof
        assert!(!MerkleTree::verify_proof(MERKLE_VERSION_V2, &root, "art_WRONG", &proof));
    }

    #[test]
    fn tampered_sibling_fails() {
        let mut tree = MerkleTree::new();
        tree.append("art_a");
        tree.append("art_b");

        let root = hex::encode(tree.root().unwrap());
        let mut proof = tree.inclusion_proof(0).unwrap();

        // Tamper with a sibling hash
        proof.path[0].hash = "0".repeat(64);

        assert!(!MerkleTree::verify_proof(MERKLE_VERSION_V2, &root, "art_a", &proof));
    }

    // ── v2 hash primitives ─────────────────────────────────────────
    // These tests pin the byte-identical output of the new
    // domain-separated leaf and internal hash functions. They are the
    // anchor that cross-SDK verifiers can compare against to detect
    // split-view attacks.

    #[test]
    fn v2_leaf_uses_0x00_prefix() {
        let got = hash_leaf_v2("art_test");
        let mut h = Sha256::new();
        h.update([0x00u8]);
        h.update(b"art_test");
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(got, expected);
    }

    #[test]
    fn v2_internal_uses_0x01_prefix() {
        let left = [0x11u8; 32];
        let right = [0x22u8; 32];
        let got = hash_internal_v2(&left, &right);
        let mut h = Sha256::new();
        h.update([0x01u8]);
        h.update(left);
        h.update(right);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(got, expected);
    }

    #[test]
    fn v1_legacy_root_unchanged() {
        // Pin a known v1 root so existing v0.10.2 receipts continue to
        // verify byte-identically against this code path.
        let ids = ["art_a", "art_b", "art_c", "art_d"];
        let mut leaves: Vec<[u8; 32]> = ids.iter().map(|id| hash_leaf_v1(id)).collect();
        while leaves.len() > 1 {
            let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
            let mut i = 0;
            while i + 1 < leaves.len() {
                next.push(hash_internal_v1(&leaves[i], &leaves[i + 1]));
                i += 2;
            }
            if i < leaves.len() {
                next.push(leaves[i]);
            }
            leaves = next;
        }
        // This expected root is computed from the *current* v0.10.2
        // hashing (no domain separation, RFC 9162 promotion). If this
        // value changes, every v0.10.2 receipt in the wild becomes
        // unverifiable — that would be the definition of a regression.
        let got = hex::encode(leaves[0]);
        // Pinned literal: v0.10.2 hashing applied to the input set above.
        // Drift here means a previously-issued v0.10.2 receipt would no
        // longer verify under v1.
        let expected = "cb4c9e4a9374ea3917b9ba75554ce8908a593db1183f1af48edf41fa3eb67b0d";
        assert_eq!(
            got, expected,
            "v1 root drifted; v0.10.2 receipts will fail to verify",
        );
    }

    #[test]
    fn v2_differs_from_v1_for_same_input() {
        // Sanity: domain separation must change the output.
        assert_ne!(hash_leaf_v1("x"), hash_leaf_v2("x"));
        let l = [0x33u8; 32];
        let r = [0x44u8; 32];
        assert_ne!(hash_internal_v1(&l, &r), hash_internal_v2(&l, &r));
    }

    #[test]
    fn odd_number_of_leaves() {
        // 5 leaves -- last leaf is duplicated for padding
        let mut tree = MerkleTree::new();
        for i in 0..5 {
            tree.append(&format!("art_{}", i));
        }

        let root = hex::encode(tree.root().unwrap());
        let proof = tree.inclusion_proof(4).unwrap(); // last leaf

        assert!(MerkleTree::verify_proof(MERKLE_VERSION_V2, &root, "art_4", &proof));
    }

    // ── v2 round-trip + cross-version rejection ────────────────────

    #[test]
    fn v2_verify_round_trip() {
        let mut tree = MerkleTree::new();
        for id in &["art_a", "art_b", "art_c", "art_d"] {
            tree.append(id);
        }
        assert_eq!(tree.version(), MERKLE_VERSION_V2);

        let root = hex::encode(tree.root().unwrap());
        let proof = tree.inclusion_proof(1).unwrap();
        assert_eq!(proof.merkle_version, MERKLE_VERSION_V2);
        assert!(MerkleTree::verify_proof(MERKLE_VERSION_V2, &root, "art_b", &proof));
    }

    #[test]
    fn v2_rejects_v1_proof() {
        // Build a v2 tree, take its proof, then mutate the proof to claim
        // v1. Re-verification under v2 (the trusted version) must fail
        // because proof.merkle_version mismatches expected_version.
        let mut tree = MerkleTree::new();
        for id in &["art_a", "art_b", "art_c", "art_d"] {
            tree.append(id);
        }
        let root = hex::encode(tree.root().unwrap());
        let mut proof = tree.inclusion_proof(1).unwrap();
        proof.merkle_version = MERKLE_VERSION_V1;
        assert!(
            !MerkleTree::verify_proof(MERKLE_VERSION_V2, &root, "art_b", &proof),
            "v2 verifier must reject a proof that downgrades itself to v1",
        );
    }

    #[test]
    fn v1_rejects_v2_proof() {
        // Symmetric to v2_rejects_v1_proof: a v1 tree's proof reinterpreted
        // as v2 must reject.
        let mut tree = MerkleTree::with_version(MERKLE_VERSION_V1).unwrap();
        for id in &["art_a", "art_b", "art_c", "art_d"] {
            tree.append(id);
        }
        let root = hex::encode(tree.root().unwrap());
        let mut proof = tree.inclusion_proof(1).unwrap();
        proof.merkle_version = MERKLE_VERSION_V2;
        assert!(
            !MerkleTree::verify_proof(MERKLE_VERSION_V1, &root, "art_b", &proof),
            "v1 verifier must reject a proof that upgrades itself to v2",
        );
    }

    #[test]
    fn v2_rejects_internal_node_as_leaf() {
        // Construct an internal-node hash (under v2 domain separation),
        // hand-craft a fake "single-leaf proof" claiming this internal
        // hash is the leaf. The verifier must reject because the
        // computed v2 leaf hash for the supplied artifact_id cannot
        // equal an internal-node hash (different domain prefix).
        let left = [0x11u8; 32];
        let right = [0x22u8; 32];
        let internal = hash_internal_v2(&left, &right);
        let internal_hex = hex::encode(internal);

        let fake_proof = InclusionProof {
            leaf_index: 0,
            leaf_hash: internal_hex.clone(),
            path: vec![],
            algorithm: Some(MERKLE_ALGORITHM_V2.to_string()),
            merkle_version: MERKLE_VERSION_V2,
        };

        assert!(
            !MerkleTree::verify_proof(MERKLE_VERSION_V2, &internal_hex, "art_attacker", &fake_proof),
            "v2 verifier must reject an internal-node hash impersonating a single-leaf tree",
        );
    }

    #[test]
    fn v2_rejects_empty_path_with_nonzero_leaf_index() {
        // Empty proof path only makes sense for a single-leaf tree at
        // leaf_index 0. A v2 verifier must reject any other shape.
        let mut tree = MerkleTree::new();
        tree.append("art_a");
        let root = hex::encode(tree.root().unwrap());

        // Synthesize a malformed proof: index 1 but no path.
        let bad = InclusionProof {
            leaf_index: 1,
            leaf_hash: hex::encode(hash_leaf_v2("art_a")),
            path: vec![],
            algorithm: Some(MERKLE_ALGORITHM_V2.to_string()),
            merkle_version: MERKLE_VERSION_V2,
        };
        assert!(!MerkleTree::verify_proof(MERKLE_VERSION_V2, &root, "art_a", &bad));
    }

    #[test]
    fn unknown_merkle_version_rejected() {
        let mut tree = MerkleTree::new();
        tree.append("art_a");
        tree.append("art_b");
        let root = hex::encode(tree.root().unwrap());
        let mut proof = tree.inclusion_proof(0).unwrap();
        proof.merkle_version = 7; // not v1 or v2
        // Trusted version is v2 here; proof claims 7 — must reject.
        assert!(!MerkleTree::verify_proof(MERKLE_VERSION_V2, &root, "art_a", &proof));
        // And separately: if the *trusted* version is unknown, also reject.
        let mut proof2 = tree.inclusion_proof(0).unwrap();
        proof2.merkle_version = 7;
        assert!(!MerkleTree::verify_proof(7, &root, "art_a", &proof2));
    }

    #[test]
    fn default_merkle_version_function_returns_one() {
        // Documents the contract relied on by `#[serde(default = ...)]`
        // for backward compatibility with v0.10.2 receipts.
        assert_eq!(default_merkle_version_v1(), MERKLE_VERSION_V1);
    }

    #[test]
    fn missing_merkle_version_field_defaults_to_v1() {
        // Deserialize an InclusionProof JSON produced before this field
        // existed and confirm it falls back to v1.
        let json = serde_json::json!({
            "leaf_index": 0,
            "leaf_hash": "00".repeat(32),
            "path": [],
            "algorithm": "sha256-duplicate-last",
        });
        let proof: InclusionProof = serde_json::from_value(json).unwrap();
        assert_eq!(proof.merkle_version, MERKLE_VERSION_V1);
    }

    #[test]
    fn mixed_version_in_receipt_explicit() {
        // Round-trip a proof through JSON with `merkle_version: 2`
        // explicitly set, then verify the deserialized proof routes
        // through the v2 dispatch.
        let mut tree = MerkleTree::new();
        for id in &["art_a", "art_b"] {
            tree.append(id);
        }
        let root = hex::encode(tree.root().unwrap());
        let proof = tree.inclusion_proof(0).unwrap();
        let json = serde_json::to_string(&proof).unwrap();
        assert!(json.contains("\"merkle_version\":2"), "wire shape must include merkle_version=2");
        let parsed: InclusionProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.merkle_version, MERKLE_VERSION_V2);
        assert!(MerkleTree::verify_proof(MERKLE_VERSION_V2, &root, "art_a", &parsed));
    }
}
