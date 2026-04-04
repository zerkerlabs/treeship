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
            chain_intact: true,
            all_digests_valid: true,
            all_signatures_valid: true,
            public_key_digest: "sha256:key456".to_string(),
            proved_at: "1234567890Z".to_string(),
            prover_mode: "Local".to_string(),
            receipt_bytes: Vec::new(),
        };

        let json = serde_json::to_string(&proof).unwrap();
        let back: ChainProofResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.artifact_count, 5);
        assert!(back.chain_intact);
        assert!(back.all_signatures_valid);
    }

    #[test]
    fn chain_proof_save_load_roundtrip() {
        let proof = ChainProofResult {
            image_id: "sha256:roundtrip".to_string(),
            chain_root_id: Some("art_a".to_string()),
            chain_tip_id: Some("art_z".to_string()),
            artifact_count: 10,
            chain_intact: true,
            all_digests_valid: true,
            all_signatures_valid: true,
            public_key_digest: "sha256:abc".to_string(),
            proved_at: "9999Z".to_string(),
            prover_mode: "Local".to_string(),
            receipt_bytes: vec![1, 2, 3, 4],
        };

        let tmp = std::path::PathBuf::from("/tmp/treeship_test_proof_v061.json");
        RiscZeroProver::save_proof(&proof, &tmp).unwrap();
        let loaded = RiscZeroProver::load_proof(&tmp).unwrap();
        assert_eq!(loaded.artifact_count, 10);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn verify_rejects_empty_receipt() {
        let proof = ChainProofResult {
            image_id: "test".to_string(),
            chain_root_id: None,
            chain_tip_id: None,
            artifact_count: 0,
            chain_intact: true,
            all_digests_valid: true,
            all_signatures_valid: false,
            public_key_digest: String::new(),
            proved_at: "0Z".to_string(),
            prover_mode: "Local".to_string(),
            receipt_bytes: Vec::new(),
        };
        let result = RiscZeroProver::verify(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn chain_artifact_serializes() {
        let artifact = ChainArtifact {
            artifact_id: "art_test".to_string(),
            digest: "sha256:abc".to_string(),
            payload_type: "action".to_string(),
            signed_at: "2026-04-04T00:00:00Z".to_string(),
            parent_id: Some("art_parent".to_string()),
            signature: "sig".to_string(),
            pae_message: vec![1, 2, 3],
        };
        let json = serde_json::to_string(&artifact).unwrap();
        assert!(json.contains("art_test"));
    }
}
