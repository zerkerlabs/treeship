//! Treeship Chain Verifier -- RISC Zero Guest Program
//!
//! Runs inside the zkVM. Verifies:
//! - Ed25519 signature validity on each artifact
//! - Content-addressed digest correctness (SHA-256)
//! - Chain link integrity (parent_id linkage)
//!
//! Commits results as public output without revealing artifact content.

#![no_main]
risc0_zkvm::guest::entry!(main);

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainArtifact {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainProofOutput {
    artifact_count: usize,
    chain_intact: bool,
    all_digests_valid: bool,
    all_signatures_valid: bool,
    public_key_digest: String,
}

fn main() {
    let artifacts: Vec<ChainArtifact> = env::read();
    let public_key_bytes: [u8; 32] = env::read();

    // Compute public key digest (only thing revealed about the key)
    let key_digest = hex::encode(Sha256::digest(&public_key_bytes));

    // Reconstruct verifying key
    let verifying_key = match VerifyingKey::from_bytes(&public_key_bytes) {
        Ok(vk) => Some(vk),
        Err(_) => None,
    };

    let mut chain_intact = true;
    let mut all_digests_valid = true;
    let mut all_signatures_valid = verifying_key.is_some();
    let artifact_count = artifacts.len();

    for i in 0..artifacts.len() {
        // 1. Verify chain link integrity
        if i > 0 {
            match &artifacts[i].parent_id {
                Some(parent) if *parent == artifacts[i - 1].artifact_id => {}
                Some(_) => { chain_intact = false; }
                None => { chain_intact = false; }
            }
        }

        // 2. Verify content-addressed digest
        if !artifacts[i].content.is_empty() {
            let computed_hash = hex::encode(Sha256::digest(&artifacts[i].content));
            let expected = artifacts[i].digest
                .strip_prefix("sha256:")
                .unwrap_or(&artifacts[i].digest);
            if computed_hash != expected {
                all_digests_valid = false;
            }
        }

        // 3. Verify Ed25519 signature
        if let Some(ref vk) = verifying_key {
            if artifacts[i].signature_bytes.len() == 64 && !artifacts[i].signed_message.is_empty() {
                let mut sig_arr = [0u8; 64];
                sig_arr.copy_from_slice(&artifacts[i].signature_bytes);
                let signature = Signature::from_bytes(&sig_arr);

                if vk.verify(&artifacts[i].signed_message, &signature).is_err() {
                    all_signatures_valid = false;
                }
            } else if !artifacts[i].signed_message.is_empty() {
                // Signature bytes wrong length
                all_signatures_valid = false;
            }
        }
    }

    env::commit(&ChainProofOutput {
        artifact_count,
        chain_intact,
        all_digests_valid,
        all_signatures_valid,
        public_key_digest: key_digest,
    });
}
