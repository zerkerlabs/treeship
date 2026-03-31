//! Merkle tree module: append-only binary Merkle tree with checkpoints
//! and inclusion proofs for batch integrity verification.

pub mod tree;
pub mod checkpoint;
pub mod proof;

pub use tree::{MerkleTree, InclusionProof, Direction, ProofStep};
pub use checkpoint::{Checkpoint, CheckpointError};
pub use proof::{ProofFile, ArtifactSummary};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::Ed25519Signer;

    #[test]
    fn checkpoint_signs_and_verifies() {
        let mut tree = MerkleTree::new();
        tree.append("art_a");
        tree.append("art_b");

        let signer = Ed25519Signer::generate("key_test").unwrap();
        let checkpoint = Checkpoint::create(1, &tree, &signer).unwrap();

        assert!(checkpoint.verify());
    }

    #[test]
    fn tampered_checkpoint_fails() {
        let mut tree = MerkleTree::new();
        tree.append("art_a");

        let signer = Ed25519Signer::generate("key_test").unwrap();
        let mut checkpoint = Checkpoint::create(1, &tree, &signer).unwrap();

        checkpoint.tree_size = 999; // tamper

        assert!(!checkpoint.verify());
    }

    #[test]
    fn proof_file_round_trips_json() {
        let mut tree = MerkleTree::new();
        tree.append("art_a");
        tree.append("art_b");

        let signer = Ed25519Signer::generate("key_test").unwrap();
        let checkpoint = Checkpoint::create(1, &tree, &signer).unwrap();
        let inclusion_proof = tree.inclusion_proof(1).unwrap();

        let file = ProofFile {
            artifact_id: "art_b".to_string(),
            artifact_summary: ArtifactSummary {
                actor: "agent://test".to_string(),
                action: "test.run".to_string(),
                timestamp: "2026-03-26T00:00:00Z".to_string(),
                key_id: "key_test".to_string(),
            },
            inclusion_proof,
            checkpoint,
        };

        let json = serde_json::to_string(&file).unwrap();
        let restored: ProofFile = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.artifact_id, "art_b");
    }
}
