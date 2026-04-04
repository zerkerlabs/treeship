use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use treeship_zk_risc0_methods::TREESHIP_CHAIN_VERIFIER_ELF;
use treeship_zk_risc0_methods::TREESHIP_CHAIN_VERIFIER_ID;

/// Result of a RISC Zero chain proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainProofResult {
    pub image_id: String,
    pub chain_root_id: Option<String>,
    pub chain_tip_id: Option<String>,
    pub artifact_count: usize,
    pub chain_intact: bool,
    pub all_digests_valid: bool,
    pub all_signatures_valid: bool,
    pub public_key_digest: String,
    pub proved_at: String,
    pub prover_mode: String,
    /// Serialized RISC Zero receipt for offline verification.
    pub receipt_bytes: Vec<u8>,
}

/// Proving mode.
#[derive(Debug, Clone, Copy)]
pub enum ProverMode {
    Local,
}

impl Default for ProverMode {
    fn default() -> Self {
        ProverMode::Local
    }
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

/// Matches guest's ChainArtifact exactly -- same field names, same types.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestArtifact {
    artifact_id: String,
    digest: String,
    parent_id: Option<String>,
    /// Raw content bytes for digest verification
    content: Vec<u8>,
    /// Ed25519 signature bytes (64 bytes)
    signature_bytes: Vec<u8>,
    /// The message that was signed (PAE bytes)
    signed_message: Vec<u8>,
}

/// Guest output (matches guest's ChainProofOutput).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuestOutput {
    artifact_count: usize,
    chain_intact: bool,
    all_digests_valid: bool,
    all_signatures_valid: bool,
    public_key_digest: String,
}

/// RISC Zero chain prover.
pub struct RiscZeroProver {
    mode: ProverMode,
}

impl RiscZeroProver {
    pub fn new(mode: ProverMode) -> Self {
        Self { mode }
    }

    pub fn from_env() -> Self {
        if let Ok(key) = std::env::var("BONSAI_API_KEY") {
            if !key.is_empty() {
                eprintln!(
                    "[treeship] BONSAI_API_KEY detected but Bonsai integration \
                     is coming in v0.6.0. Using local prover."
                );
            }
        }
        Self { mode: ProverMode::Local }
    }

    /// Prove a chain of artifacts using the RISC Zero zkVM.
    /// Slow (~5-15 min on CPU). Always call from a background thread.
    pub fn prove_chain(
        &self,
        artifacts: &[ChainArtifact],
        public_key_bytes: [u8; 32],
    ) -> Result<ChainProofResult, Box<dyn std::error::Error>> {
        eprintln!(
            "[treeship] proving chain of {} artifacts locally...",
            artifacts.len()
        );

        // Build guest-compatible artifacts with full content + signatures
        let guest_artifacts: Vec<GuestArtifact> = artifacts.iter().map(|a| {
            // Decode base64url signature to raw bytes
            let sig_bytes = base64_decode_sig(&a.signature);
            GuestArtifact {
                artifact_id: a.artifact_id.clone(),
                digest: a.digest.clone(),
                parent_id: a.parent_id.clone(),
                content: a.pae_message.clone(), // PAE bytes used for digest
                signature_bytes: sig_bytes,
                signed_message: a.pae_message.clone(), // PAE is the signed message
            }
        }).collect();

        // Write both inputs matching the guest's two env::read() calls
        let env = risc0_zkvm::ExecutorEnv::builder()
            .write(&guest_artifacts)?
            .write(&public_key_bytes)?
            .build()?;

        let receipt = risc0_zkvm::default_prover()
            .prove(env, TREESHIP_CHAIN_VERIFIER_ELF)?
            .receipt;

        receipt.verify(TREESHIP_CHAIN_VERIFIER_ID)?;

        let output: GuestOutput = receipt.journal.decode()?;
        let receipt_bytes = bincode::serialize(&receipt)?;

        let now = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            format!("{}Z", secs)
        };

        let image_id = hex::encode(
            TREESHIP_CHAIN_VERIFIER_ID.iter()
                .flat_map(|w| w.to_le_bytes())
                .collect::<Vec<u8>>()
        );

        eprintln!("[treeship] chain proof complete. image_id: {}", &image_id[..16]);

        Ok(ChainProofResult {
            image_id,
            chain_root_id: artifacts.first().map(|a| a.artifact_id.clone()),
            chain_tip_id: artifacts.last().map(|a| a.artifact_id.clone()),
            artifact_count: output.artifact_count,
            chain_intact: output.chain_intact,
            all_digests_valid: output.all_digests_valid,
            all_signatures_valid: output.all_signatures_valid,
            public_key_digest: output.public_key_digest,
            proved_at: now,
            prover_mode: format!("{:?}", self.mode),
            receipt_bytes,
        })
    }

    /// Verify a chain proof receipt offline.
    pub fn verify(proof: &ChainProofResult) -> Result<bool, Box<dyn std::error::Error>> {
        if proof.receipt_bytes.is_empty() {
            return Err("empty receipt -- proof was not generated by the zkVM".into());
        }

        let receipt: risc0_zkvm::Receipt = bincode::deserialize(&proof.receipt_bytes)?;
        receipt.verify(TREESHIP_CHAIN_VERIFIER_ID)?;

        let output: GuestOutput = receipt.journal.decode()?;
        Ok(output.chain_intact && output.all_digests_valid && output.all_signatures_valid)
    }

    pub fn save_proof(proof: &ChainProofResult, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_vec_pretty(proof)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    pub fn load_proof(path: &PathBuf) -> Result<ChainProofResult, Box<dyn std::error::Error>> {
        let bytes = std::fs::read(path)?;
        let proof: ChainProofResult = serde_json::from_slice(&bytes)?;
        Ok(proof)
    }
}

/// Decode a base64url signature string to raw bytes.
fn base64_decode_sig(input: &str) -> Vec<u8> {
    // Simple base64url decode
    let standard: String = input.chars().map(|c| match c {
        '-' => '+',
        '_' => '/',
        other => other,
    }).collect();

    let padded = match standard.len() % 4 {
        2 => format!("{}==", standard),
        3 => format!("{}=", standard),
        _ => standard,
    };

    base64_simple_decode(&padded)
}

fn base64_simple_decode(input: &str) -> Vec<u8> {
    let chars: Vec<u8> = input.bytes().map(|b| match b {
        b'A'..=b'Z' => b - b'A',
        b'a'..=b'z' => b - b'a' + 26,
        b'0'..=b'9' => b - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => 0,
    }).collect();

    let mut output = Vec::new();
    for chunk in chars.chunks(4) {
        if chunk.len() < 4 { break; }
        let n = ((chunk[0] as u32) << 18) | ((chunk[1] as u32) << 12)
            | ((chunk[2] as u32) << 6) | (chunk[3] as u32);
        output.push((n >> 16) as u8);
        output.push((n >> 8) as u8);
        output.push(n as u8);
    }
    output
}
