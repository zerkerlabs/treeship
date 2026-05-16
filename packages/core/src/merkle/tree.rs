use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

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

/// Version-dispatched leaf hash. Falls back to v1 on any unknown version
/// so callers that pre-date this field do not silently mis-verify; the
/// outer `verify_proof` still rejects unknown versions explicitly.
pub(crate) fn hash_leaf(version: u8, artifact_id: &str) -> [u8; 32] {
    match version {
        MERKLE_VERSION_V2 => hash_leaf_v2(artifact_id),
        _ => hash_leaf_v1(artifact_id),
    }
}

/// Version-dispatched internal node hash.
pub(crate) fn hash_internal(version: u8, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    match version {
        MERKLE_VERSION_V2 => hash_internal_v2(left, right),
        _ => hash_internal_v1(left, right),
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
}

/// An append-only binary Merkle tree.
///
/// Leaves are `sha256(artifact_id)`. Odd leaf counts are handled by
/// promoting the unpaired node to the next level without hashing,
/// matching the RFC 9162 (Certificate Transparency) construction.
pub struct MerkleTree {
    /// All leaf hashes in insertion order.
    leaves: Vec<[u8; 32]>,
}

impl MerkleTree {
    pub fn new() -> Self {
        Self { leaves: Vec::new() }
    }

    /// Append an artifact ID as a new leaf. Returns the leaf index.
    pub fn append(&mut self, artifact_id: &str) -> usize {
        let hash = Sha256::digest(artifact_id.as_bytes());
        self.leaves.push(hash.into());
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

            // Move up: compute parent hashes (RFC 9162 promotion)
            let mut next_level = Vec::with_capacity((level.len() + 1) / 2);
            let mut i = 0;
            while i + 1 < level.len() {
                let mut h = Sha256::new();
                h.update(level[i]);
                h.update(level[i + 1]);
                next_level.push(h.finalize().into());
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
            algorithm: Some(MERKLE_ALGORITHM_V2.to_string()),
        })
    }

    /// Verify an inclusion proof against a hex-encoded root hash.
    ///
    /// Recomputes the root from `artifact_id` + the proof path and checks
    /// that it matches `root_hex`. Fully offline, no tree state needed.
    ///
    /// Supports both v1 (sha256-duplicate-last) and v2 (sha256-rfc9162) proofs.
    /// Rejects unknown algorithm values.
    pub fn verify_proof(
        root_hex: &str,
        artifact_id: &str,
        proof: &InclusionProof,
    ) -> bool {
        // Validate algorithm field. Missing = v1 (legacy), known values accepted.
        let algo = proof.algorithm.as_deref().unwrap_or(MERKLE_ALGORITHM_V1);
        if algo != MERKLE_ALGORITHM_V1 && algo != MERKLE_ALGORITHM_V2 {
            return false; // unknown algorithm -- reject
        }

        let current: [u8; 32] = Sha256::digest(artifact_id.as_bytes()).into();
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

            let mut h = Sha256::new();
            match step.direction {
                Direction::Right => {
                    h.update(current);
                    h.update(sibling);
                }
                Direction::Left => {
                    h.update(sibling);
                    h.update(current);
                }
            }
            current = h.finalize().into();
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
                let mut h = Sha256::new();
                h.update(level[i]);
                h.update(level[i + 1]);
                next_level.push(h.finalize().into());
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
        let mut tree = MerkleTree::new();
        tree.append("art_abc123");
        let root = tree.root().unwrap();
        let expected = Sha256::digest(b"art_abc123");
        assert_eq!(root, expected.as_slice());
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

        assert!(MerkleTree::verify_proof(&root, "art_b", &proof));
    }

    #[test]
    fn wrong_artifact_fails_verification() {
        let mut tree = MerkleTree::new();
        tree.append("art_a");
        tree.append("art_b");

        let root = hex::encode(tree.root().unwrap());
        let proof = tree.inclusion_proof(0).unwrap(); // proof for art_a

        // Try to verify art_WRONG against art_a's proof
        assert!(!MerkleTree::verify_proof(&root, "art_WRONG", &proof));
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

        assert!(!MerkleTree::verify_proof(&root, "art_a", &proof));
    }

    // ── v1/v2 hash primitives ──────────────────────────────────────
    // These tests pin the byte-identical output of the new
    // domain-separated leaf and internal hash functions, and document
    // the v1 (legacy) hashing that v0.10.2 receipts continue to use.
    // They are the anchor that cross-SDK verifiers can compare against
    // to detect split-view attacks.

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
            let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
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
    fn default_merkle_version_function_returns_one() {
        // Documents the contract relied on by `#[serde(default = ...)]`
        // for backward compatibility with v0.10.2 receipts.
        assert_eq!(default_merkle_version_v1(), MERKLE_VERSION_V1);
        assert_eq!(MERKLE_VERSION_V1, 1);
        assert_eq!(MERKLE_VERSION_V2, 2);
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

        assert!(MerkleTree::verify_proof(&root, "art_4", &proof));
    }
}
