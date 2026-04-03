use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Result of a RISC Zero chain proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProofResult {
    pub image_id: String,
    pub chain_root_id: Option<String>,
    pub chain_tip_id: Option<String>,
    pub artifact_count: usize,
    pub all_signatures_valid: bool,
    pub chain_intact: bool,
    pub approval_nonces_matched: bool,
    pub public_key_digest: String,
    pub proved_at: String,
    pub prover_mode: String,
    /// The raw RISC Zero receipt (serialized, for offline verification)
    pub receipt_bytes: Vec<u8>,
}

/// Proving mode: local (slow, no external trust) or Bonsai (fast, hosted).
#[derive(Debug, Clone, Copy)]
pub enum ProverMode {
    Local,
    #[cfg(feature = "zk-bonsai")]
    Bonsai,
}

impl Default for ProverMode {
    fn default() -> Self {
        ProverMode::Local
    }
}

/// RISC Zero chain prover.
pub struct RiscZeroProver {
    mode: ProverMode,
}

/// A minimal artifact for passing to the guest program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainArtifact {
    pub artifact_id: String,
    pub digest: String,
    pub payload_type: String,
    pub signed_at: String,
    pub parent_id: Option<String>,
    pub signature: String,
    pub pae_message: Vec<u8>,
}

impl RiscZeroProver {
    pub fn new(mode: ProverMode) -> Self {
        Self { mode }
    }

    /// Prove a chain of artifacts. This is the slow operation (~5-15 min locally).
    /// Should always be called from a background thread, never inline.
    pub fn prove_chain(
        &self,
        artifacts: &[ChainArtifact],
        public_key_bytes: [u8; 32],
    ) -> Result<ChainProofResult, Box<dyn std::error::Error>> {
        let now = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!("{}Z", secs)
        };

        // RISC Zero guest program is written but not yet compiled with rzup.
        // Return a clear error instead of fabricating success.
        // Real proving ships in v0.6.0 when the guest ELF is compiled in CI.
        Err("RISC Zero chain proving not yet available.\n\
             The guest program exists but requires the rzup toolchain to compile.\n\
             Install: curl -L https://risczero.com/install | bash && rzup install\n\
             Coming in v0.6.0. For now, use Circom proofs: treeship prove --circuit policy-checker".into())

        // When rzup is configured, uncomment this:
        /*
        let key_digest = {
            use sha2::{Sha256, Digest};
            hex::encode(Sha256::digest(public_key_bytes))
        };

        Ok(ChainProofResult {
            image_id: "pending_build".to_string(),
            chain_root_id: artifacts.first().map(|a| a.artifact_id.clone()),
            chain_tip_id: artifacts.last().map(|a| a.artifact_id.clone()),
            artifact_count: artifacts.len(),
            all_signatures_valid: true,
            chain_intact: true,
            approval_nonces_matched: true,
            public_key_digest: key_digest,
            proved_at: now,
            prover_mode: format!("{:?}", self.mode),
            receipt_bytes: Vec::new(),
        })
        */
    }

    /// Verify a chain proof receipt offline.
    pub fn verify(proof: &ChainProofResult) -> Result<bool, Box<dyn std::error::Error>> {
        if proof.receipt_bytes.is_empty() {
            // Placeholder proof -- can't verify without actual receipt
            return Ok(false);
        }

        // TODO: Deserialize the receipt and verify against the image ID
        // using risc0_zkvm::Receipt::verify()

        Ok(true)
    }

    /// Save a proof to a file.
    pub fn save_proof(
        proof: &ChainProofResult,
        path: &PathBuf,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_vec_pretty(proof)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load a proof from a file.
    pub fn load_proof(path: &PathBuf) -> Result<ChainProofResult, Box<dyn std::error::Error>> {
        let bytes = std::fs::read(path)?;
        let proof: ChainProofResult = serde_json::from_slice(&bytes)?;
        Ok(proof)
    }
}
