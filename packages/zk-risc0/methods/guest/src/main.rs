//! Treeship Chain Verifier -- RISC Zero Guest Program
//!
//! Runs inside the zkVM. Verifies chain link integrity and
//! content-addressed digest correctness. Commits results as public output.
//!
//! What this proves:
//! - Chain links are intact (parent_id matches previous artifact)
//! - Content-addressed digests are correct (SHA-256 of artifact content)
//! - Artifact count
//!
//! What this does NOT prove (yet):
//! - Ed25519 signature validity (requires ed25519-dalek in zkVM, heavy)
//! - Approval nonce binding (requires statement parsing)
//! These are verified outside the zkVM by the regular verifier.

#![no_main]
risc0_zkvm::guest::entry!(main);

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainProofOutput {
    artifact_count: usize,
    chain_intact: bool,
    all_digests_valid: bool,
}

fn main() {
    let artifacts: Vec<ChainArtifact> = env::read();

    let mut chain_intact = true;
    let mut all_digests_valid = true;
    let artifact_count = artifacts.len();

    for i in 0..artifacts.len() {
        // Verify chain link integrity
        if i > 0 {
            match &artifacts[i].parent_id {
                Some(parent) if *parent == artifacts[i - 1].artifact_id => {}
                Some(_) => { chain_intact = false; }
                None => { chain_intact = false; } // non-root missing parent
            }
        }

        // Verify content-addressed digest
        if !artifacts[i].content.is_empty() {
            let computed_hash = hex::encode(Sha256::digest(&artifacts[i].content));
            let expected = artifacts[i].digest
                .strip_prefix("sha256:")
                .unwrap_or(&artifacts[i].digest);
            if computed_hash != expected {
                all_digests_valid = false;
            }
        }
    }

    env::commit(&ChainProofOutput {
        artifact_count,
        chain_intact,
        all_digests_valid,
    });
}
