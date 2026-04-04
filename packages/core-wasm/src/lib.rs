use wasm_bindgen::prelude::*;
use std::collections::HashMap;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::VerifyingKey;

#[cfg(feature = "zk")]
mod zk;

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

/// Verify a ZK proof file (auto-detects type from proof.system field).
///
/// Supports:
/// - "circom-groth16": validates proof structure and public signals
/// - "risc0": validates proof structure and chain summary
///
/// Returns JSON: { "valid": true/false, "system": "...", "details": {...} }
#[wasm_bindgen]
pub fn verify_zk_proof(proof_json: &str) -> String {
    match verify_zk_inner(proof_json) {
        Ok(result) => result,
        Err(e) => serde_json::json!({
            "valid": false,
            "system": "unknown",
            "error": e,
        }).to_string(),
    }
}

fn verify_zk_inner(proof_json: &str) -> Result<String, String> {
    let proof: serde_json::Value = serde_json::from_str(proof_json)
        .map_err(|e| format!("invalid proof JSON: {}", e))?;

    let system = proof.get("system")
        .and_then(|s| s.as_str())
        .unwrap_or("unknown");

    match system {
        "circom-groth16" => verify_circom_proof_inner(&proof),
        "risc0" => verify_risc0_proof_inner(&proof),
        other => Err(format!("unsupported proof system: {}", other)),
    }
}

#[cfg(feature = "zk")]
fn verify_circom_proof_inner(proof: &serde_json::Value) -> Result<String, String> {
    zk::verify_circom_proof(proof)
}

#[cfg(not(feature = "zk"))]
fn verify_circom_proof_inner(proof: &serde_json::Value) -> Result<String, String> {
    let circuit = proof.get("circuit").and_then(|c| c.as_str()).unwrap_or("unknown");
    let artifact_id = proof.get("artifact_id").and_then(|a| a.as_str()).unwrap_or("unknown");
    Ok(serde_json::json!({
        "valid": false,
        "system": "circom-groth16",
        "circuit": circuit,
        "artifact_id": artifact_id,
        "error": "ZK verification not enabled in this WASM build. Rebuild with --features zk.",
    }).to_string())
}

fn verify_risc0_proof_inner(proof: &serde_json::Value) -> Result<String, String> {
    // WASM can only do structural validation + journal field presence checks.
    // Full zkVM receipt verification (receipt.verify(GUEST_ID)) requires the
    // native CLI: treeship verify-proof

    let receipt_arr = proof.get("receipt_bytes")
        .and_then(|r| r.as_array());

    let receipt_len = receipt_arr.map(|a| a.len()).unwrap_or(0);

    // No receipt means no proof -- return invalid immediately
    if receipt_len == 0 {
        return Ok(serde_json::json!({
            "valid": false,
            "system": "risc0",
            "error": "no receipt present, proof was generated by placeholder prover",
            "note": "RISC Zero chain proofs require a receipt for any validity claim"
        }).to_string());
    }

    // Structural check: attempt to interpret receipt_bytes as a valid byte array.
    // Each element must be a u8 (0-255). If any element is out of range or not
    // a number, the receipt is structurally invalid.
    let receipt_valid_structure = receipt_arr
        .map(|arr| arr.iter().all(|v| {
            v.as_u64().map_or(false, |n| n <= 255)
        }))
        .unwrap_or(false);

    if !receipt_valid_structure {
        return Ok(serde_json::json!({
            "valid": false,
            "system": "risc0",
            "error": "receipt_bytes failed structural validation (not a valid byte array)",
        }).to_string());
    }

    // Require journal fields to be present. Without these, the receipt
    // cannot be meaningful even if it deserializes.
    let image_id = proof.get("image_id")
        .and_then(|i| i.as_str());
    let artifact_count = proof.get("artifact_count")
        .and_then(|c| c.as_u64());
    let proved_at = proof.get("proved_at")
        .and_then(|p| p.as_str());

    if image_id.is_none() || artifact_count.is_none() || proved_at.is_none() {
        return Ok(serde_json::json!({
            "valid": false,
            "system": "risc0",
            "error": "missing required journal fields (image_id, artifact_count, proved_at)",
            "has_receipt": true,
        }).to_string());
    }

    // Read summary fields for informational output only.
    // These JSON booleans are NOT used to determine validity.
    let all_sigs = proof.get("all_signatures_valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let chain_intact = proof.get("chain_intact")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let approvals_matched = proof.get("approval_nonces_matched")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // WASM verdict: receipt is structurally present and journal fields exist.
    // This is NOT full verification. We report "structurally_valid" but do not
    // claim "valid: true" since we cannot run receipt.verify(GUEST_ID) in WASM.
    Ok(serde_json::json!({
        "valid": false,
        "structurally_valid": true,
        "system": "risc0",
        "image_id": image_id.unwrap_or("unknown"),
        "artifact_count": artifact_count.unwrap_or(0),
        "receipt_bytes_len": receipt_len,
        "summary": {
            "all_signatures_valid": all_sigs,
            "chain_intact": chain_intact,
            "approval_nonces_matched": approvals_matched,
        },
        "proved_at": proved_at.unwrap_or("unknown"),
        "note": "WASM performed structural validation only. Full zkVM receipt verification available via: treeship verify-proof",
    }).to_string())
}

/// Version string for the WASM module.
#[wasm_bindgen]
pub fn version() -> String {
    format!("treeship-core-wasm {}", env!("CARGO_PKG_VERSION"))
}
