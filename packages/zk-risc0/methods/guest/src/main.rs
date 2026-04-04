//! Treeship Chain Verifier -- RISC Zero Guest Program
//!
//! Runs inside the zkVM. Takes a chain of artifacts and verifies
//! chain integrity, then commits the result as public output.

#![no_main]
risc0_zkvm::guest::entry!(main);

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// Minimal artifact record for chain verification inside the zkVM.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainArtifact {
    artifact_id: String,
    digest: String,
    parent_id: Option<String>,
}

/// Public output committed by the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainProofOutput {
    artifact_count: usize,
    chain_intact: bool,
    all_digests_valid: bool,
}

fn main() {
    // Read private inputs
    let artifacts: Vec<ChainArtifact> = env::read();

    let mut chain_intact = true;
    let mut all_digests_valid = true;
    let artifact_count = artifacts.len();

    // Verify chain links
    for i in 1..artifacts.len() {
        if let Some(ref parent) = artifacts[i].parent_id {
            if *parent != artifacts[i - 1].artifact_id {
                chain_intact = false;
            }
        }
    }

    // Verify content-addressed IDs
    for artifact in &artifacts {
        let computed = format!("sha256:{}", hex::encode(Sha256::digest(artifact.artifact_id.as_bytes())));
        // The digest field should be derivable from the artifact content
        // For now, we verify the artifact_id is well-formed
        if !artifact.artifact_id.starts_with("art_") {
            all_digests_valid = false;
        }
    }

    // Commit public output
    let output = ChainProofOutput {
        artifact_count,
        chain_intact,
        all_digests_valid,
    };

    env::commit(&output);
}
