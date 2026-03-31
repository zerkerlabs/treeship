use wasm_bindgen::prelude::*;
use std::collections::HashMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::VerifyingKey;

use treeship_core::attestation::{
    pae, artifact_id_from_pae, digest_from_pae,
    Envelope, Verifier, VerifyResult,
};

/// Verify a DSSE envelope JSON string against a set of trusted public keys.
///
/// `envelope_json`: the full DSSE envelope as JSON
/// `trusted_keys_json`: JSON object mapping key_id -> base64url(public_key_32_bytes)
///
/// Returns JSON: { "valid": true/false, "artifact_id": "art_...", "digest": "sha256:...",
///                  "verified_keys": [...], "error": null/"..." }
#[wasm_bindgen]
pub fn verify_envelope(envelope_json: &str, trusted_keys_json: &str) -> String {
    match verify_inner(envelope_json, trusted_keys_json) {
        Ok(result) => serde_json::json!({
            "valid": true,
            "artifact_id": result.artifact_id,
            "digest": result.digest,
            "verified_keys": result.verified_key_ids,
            "payload_type": result.payload_type,
            "error": serde_json::Value::Null,
        }).to_string(),
        Err(e) => serde_json::json!({
            "valid": false,
            "artifact_id": serde_json::Value::Null,
            "digest": serde_json::Value::Null,
            "verified_keys": Vec::<String>::new(),
            "payload_type": serde_json::Value::Null,
            "error": e,
        }).to_string(),
    }
}

fn verify_inner(envelope_json: &str, trusted_keys_json: &str) -> Result<VerifyResult, String> {
    let envelope: Envelope = serde_json::from_str(envelope_json)
        .map_err(|e| format!("invalid envelope JSON: {}", e))?;

    let keys_map: HashMap<String, String> = serde_json::from_str(trusted_keys_json)
        .map_err(|e| format!("invalid trusted_keys JSON: {}", e))?;

    let mut verifying_keys: HashMap<String, VerifyingKey> = HashMap::new();
    for (key_id, b64_pubkey) in &keys_map {
        let bytes = URL_SAFE_NO_PAD.decode(b64_pubkey)
            .map_err(|e| format!("bad base64 for key {}: {}", key_id, e))?;
        if bytes.len() != 32 {
            return Err(format!("key {} is {} bytes, expected 32", key_id, bytes.len()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let vk = VerifyingKey::from_bytes(&arr)
            .map_err(|e| format!("invalid Ed25519 key {}: {}", key_id, e))?;
        verifying_keys.insert(key_id.clone(), vk);
    }

    let verifier = Verifier::new(verifying_keys);
    verifier.verify_any(&envelope)
        .map_err(|e| format!("{}", e))
}

/// Derive the content-addressed artifact ID from an envelope.
/// Returns "art_..." or an error string.
#[wasm_bindgen]
pub fn artifact_id(envelope_json: &str) -> String {
    match artifact_id_inner(envelope_json) {
        Ok(id) => id,
        Err(e) => format!("error: {}", e),
    }
}

fn artifact_id_inner(envelope_json: &str) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(envelope_json)
        .map_err(|e| format!("invalid envelope JSON: {}", e))?;

    let payload_bytes = URL_SAFE_NO_PAD.decode(&envelope.payload)
        .map_err(|e| format!("bad payload base64: {}", e))?;

    let pae_bytes = pae(&envelope.payload_type, &payload_bytes);
    Ok(artifact_id_from_pae(&pae_bytes))
}

/// Derive the SHA-256 digest from an envelope.
/// Returns "sha256:..." or an error string.
#[wasm_bindgen]
pub fn digest(envelope_json: &str) -> String {
    match digest_inner(envelope_json) {
        Ok(d) => d,
        Err(e) => format!("error: {}", e),
    }
}

fn digest_inner(envelope_json: &str) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(envelope_json)
        .map_err(|e| format!("invalid envelope JSON: {}", e))?;

    let payload_bytes = URL_SAFE_NO_PAD.decode(&envelope.payload)
        .map_err(|e| format!("bad payload base64: {}", e))?;

    let pae_bytes = pae(&envelope.payload_type, &payload_bytes);
    Ok(digest_from_pae(&pae_bytes))
}

/// Decode the statement payload from an envelope (without verification).
/// Returns the JSON string of the statement.
#[wasm_bindgen]
pub fn decode_payload(envelope_json: &str) -> String {
    match decode_inner(envelope_json) {
        Ok(s) => s,
        Err(e) => format!("{{\"error\":\"{}\"}}", e),
    }
}

fn decode_inner(envelope_json: &str) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(envelope_json)
        .map_err(|e| format!("invalid envelope JSON: {}", e))?;

    let payload_bytes = URL_SAFE_NO_PAD.decode(&envelope.payload)
        .map_err(|e| format!("bad payload base64: {}", e))?;

    String::from_utf8(payload_bytes)
        .map_err(|e| format!("payload is not UTF-8: {}", e))
}

/// Verify a Merkle inclusion proof JSON.
/// Returns JSON: { "valid": true/false, "message": "...", "artifact_id": "...",
///   "leaf_index": N, "checkpoint_index": N, "checkpoint_root": "...",
///   "signed_at": "...", "signer": "..." }
#[wasm_bindgen]
pub fn verify_merkle_proof(proof_json: &str) -> String {
    match verify_merkle_inner(proof_json) {
        Ok(result) => result,
        Err(e) => serde_json::json!({
            "valid": false,
            "message": e,
        }).to_string(),
    }
}

fn verify_merkle_inner(proof_json: &str) -> Result<String, String> {
    let proof_file: treeship_core::merkle::ProofFile = serde_json::from_str(proof_json)
        .map_err(|e| format!("invalid proof JSON: {}", e))?;

    // 1. Verify checkpoint signature
    if !proof_file.checkpoint.verify() {
        return Ok(serde_json::json!({
            "valid": false,
            "message": "checkpoint signature invalid",
            "artifact_id": proof_file.artifact_id,
            "checkpoint_index": proof_file.checkpoint.index,
        }).to_string());
    }

    // 2. Verify inclusion proof
    let root = proof_file.checkpoint.root
        .strip_prefix("sha256:")
        .unwrap_or(&proof_file.checkpoint.root);

    let valid = treeship_core::merkle::MerkleTree::verify_proof(
        root,
        &proof_file.artifact_id,
        &proof_file.inclusion_proof,
    );

    Ok(serde_json::json!({
        "valid": valid,
        "message": if valid { "inclusion verified" } else { "proof invalid" },
        "artifact_id": proof_file.artifact_id,
        "leaf_index": proof_file.inclusion_proof.leaf_index,
        "checkpoint_index": proof_file.checkpoint.index,
        "checkpoint_root": proof_file.checkpoint.root,
        "signed_at": proof_file.checkpoint.signed_at,
        "signer": proof_file.checkpoint.signer,
    }).to_string())
}

/// Version string for the WASM module.
#[wasm_bindgen]
pub fn version() -> String {
    format!("treeship-core-wasm {}", env!("CARGO_PKG_VERSION"))
}
