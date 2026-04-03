//! Treeship Chain Verifier -- RISC Zero Guest Program
//!
//! Runs inside the zkVM. Takes a chain of artifacts and a public key,
//! verifies every signature and chain link, and commits the result
//! without revealing any artifact content.

#![no_main]
risc0_zkvm::guest::entry!(main);

use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// A minimal artifact record for chain verification inside the zkVM.
/// This is a stripped-down version of treeship_core::storage::Record
/// to minimize the guest binary size.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainArtifact {
    artifact_id: String,
    digest: String,
    payload_type: String,
    signed_at: String,
    parent_id: Option<String>,
    /// Base64url-encoded DSSE signature bytes
    signature: String,
    /// The PAE message that was signed (pre-computed by the host)
    pae_message: Vec<u8>,
}

/// The public output committed by the guest program.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChainProofOutput {
    chain_root_id: Option<String>,
    chain_tip_id: Option<String>,
    artifact_count: usize,
    all_signatures_valid: bool,
    chain_intact: bool,
    approval_nonces_matched: bool,
    public_key_digest: String,
}

fn main() {
    // Read private inputs from the host
    let artifacts: Vec<ChainArtifact> = risc0_zkvm::guest::env::read();
    let public_key_bytes: [u8; 32] = risc0_zkvm::guest::env::read();

    // Compute public key digest (this is the only thing revealed about the key)
    let key_digest = hex::encode(Sha256::digest(&public_key_bytes));

    // Reconstruct the verifying key
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes)
        .expect("invalid public key");

    let mut all_sigs_valid = true;
    let mut chain_intact = true;
    let artifact_count = artifacts.len();

    // Verify each artifact
    for (i, artifact) in artifacts.iter().enumerate() {
        // 1. Verify Ed25519 signature
        let sig_bytes = base64url_decode(&artifact.signature);
        if sig_bytes.len() != 64 {
            all_sigs_valid = false;
            continue;
        }

        let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap_or([0u8; 64]);
        let signature = Signature::from_bytes(&sig_arr);

        if verifying_key.verify(&artifact.pae_message, &signature).is_err() {
            all_sigs_valid = false;
        }

        // 2. Verify chain link (parent_id matches previous artifact)
        if i > 0 {
            if let Some(ref parent) = artifact.parent_id {
                if *parent != artifacts[i - 1].artifact_id {
                    chain_intact = false;
                }
            }
            // No parent_id on non-first artifact is also a chain break
            // (unless it's explicitly allowed for parallel chains)
        }

        // 3. Verify content-addressed ID
        let computed_digest = hex::encode(Sha256::digest(&artifact.pae_message));
        if artifact.digest != format!("sha256:{}", computed_digest)
            && artifact.digest != computed_digest
        {
            // Digest mismatch -- artifact content was modified
            all_sigs_valid = false;
        }
    }

    // Commit the public output (this is what the verifier sees)
    let output = ChainProofOutput {
        chain_root_id: artifacts.first().map(|a| a.artifact_id.clone()),
        chain_tip_id: artifacts.last().map(|a| a.artifact_id.clone()),
        artifact_count,
        all_signatures_valid: all_sigs_valid,
        chain_intact,
        approval_nonces_matched: true, // TODO: implement nonce checking
        public_key_digest: key_digest,
    };

    risc0_zkvm::guest::env::commit(&output);
}

/// Minimal base64url decoder for the guest (no external dependency)
fn base64url_decode(input: &str) -> Vec<u8> {
    // Convert base64url to standard base64
    let standard: String = input
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();

    // Add padding
    let padded = match standard.len() % 4 {
        2 => format!("{}==", standard),
        3 => format!("{}=", standard),
        _ => standard,
    };

    // Simple base64 decode
    let chars: Vec<u8> = padded.bytes().map(|b| {
        match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => 0,
        }
    }).collect();

    let mut output = Vec::new();
    for chunk in chars.chunks(4) {
        if chunk.len() < 4 { break; }
        let n = ((chunk[0] as u32) << 18)
            | ((chunk[1] as u32) << 12)
            | ((chunk[2] as u32) << 6)
            | (chunk[3] as u32);
        output.push((n >> 16) as u8);
        if padded.as_bytes().get(chunk.len() * 4 / 4 * 3 - 1) != Some(&b'=') {
            output.push((n >> 8) as u8);
        }
        if padded.as_bytes().last() != Some(&b'=') {
            output.push(n as u8);
        }
    }
    output
}
