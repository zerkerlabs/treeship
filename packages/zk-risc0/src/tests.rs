#[cfg(test)]
mod tests {
    use crate::prover::*;

    #[test]
    fn chain_proof_result_serializes() {
        let proof = ChainProofResult {
            image_id: "sha256:test123".to_string(),
            chain_root_id: Some("art_root".to_string()),
            chain_tip_id: Some("art_tip".to_string()),
            artifact_count: 5,
            all_signatures_valid: true,
            chain_intact: true,
            approval_nonces_matched: true,
            public_key_digest: "sha256:key456".to_string(),
            proved_at: "1234567890Z".to_string(),
            prover_mode: "Local".to_string(),
            receipt_bytes: Vec::new(),
        };

        let json = serde_json::to_string(&proof).unwrap();
        let back: ChainProofResult = serde_json::from_str(&json).unwrap();

        assert_eq!(back.artifact_count, 5);
        assert!(back.all_signatures_valid);
        assert!(back.chain_intact);
        assert_eq!(back.image_id, "sha256:test123");
    }

    #[test]
    fn chain_proof_save_load_roundtrip() {
        let proof = ChainProofResult {
            image_id: "sha256:roundtrip".to_string(),
            chain_root_id: Some("art_a".to_string()),
            chain_tip_id: Some("art_z".to_string()),
            artifact_count: 10,
            all_signatures_valid: true,
            chain_intact: true,
            approval_nonces_matched: true,
            public_key_digest: "sha256:abc".to_string(),
            proved_at: "9999Z".to_string(),
            prover_mode: "Local".to_string(),
            receipt_bytes: vec![1, 2, 3, 4],
        };

        let tmp = std::path::PathBuf::from("/tmp/treeship_test_proof.json");
        RiscZeroProver::save_proof(&proof, &tmp).unwrap();

        let loaded = RiscZeroProver::load_proof(&tmp).unwrap();
        assert_eq!(loaded.artifact_count, 10);
        assert_eq!(loaded.receipt_bytes, vec![1, 2, 3, 4]);

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn prover_handles_empty_chain() {
        let prover = RiscZeroProver::new(ProverMode::default());
        let result = prover.prove_chain(&[], [0u8; 32]);
        assert!(result.is_ok());
        let proof = result.unwrap();
        assert_eq!(proof.artifact_count, 0);
    }

    #[test]
    fn chain_artifact_serializes() {
        let artifact = ChainArtifact {
            artifact_id: "art_test".to_string(),
            digest: "sha256:abc".to_string(),
            payload_type: "application/vnd.treeship.action.v1+json".to_string(),
            signed_at: "2026-04-02T00:00:00Z".to_string(),
            parent_id: Some("art_parent".to_string()),
            signature: "base64sig".to_string(),
            pae_message: vec![1, 2, 3],
        };

        let json = serde_json::to_string(&artifact).unwrap();
        assert!(json.contains("art_test"));
        assert!(json.contains("art_parent"));
    }

    #[test]
    fn composite_checkpoint_with_proof_summary() {
        use treeship_core::merkle::checkpoint::{Checkpoint, ChainProofSummary};

        let summary = ChainProofSummary {
            image_id: "sha256:verifier_v0.5.0".to_string(),
            all_signatures_valid: true,
            chain_intact: true,
            approval_nonces_matched: true,
            artifact_count: 47,
            public_key_digest: "sha256:key789".to_string(),
            proved_at: "2026-04-02T00:00:00Z".to_string(),
        };

        // Serialize just the summary
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("all_signatures_valid"));
        assert!(json.contains("47"));

        // Verify it deserializes
        let back: ChainProofSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(back.artifact_count, 47);
        assert!(back.chain_intact);
    }
}
