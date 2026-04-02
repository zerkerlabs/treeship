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

/// An inclusion proof: the sibling path from a leaf to the root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: usize,
    /// Hex-encoded leaf hash.
    pub leaf_hash: String,
    pub path: Vec<ProofStep>,
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
        })
    }

    /// Verify an inclusion proof against a hex-encoded root hash.
    ///
    /// Recomputes the root from `artifact_id` + the proof path and checks
    /// that it matches `root_hex`. Fully offline, no tree state needed.
    pub fn verify_proof(
        root_hex: &str,
        artifact_id: &str,
        proof: &InclusionProof,
    ) -> bool {
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
