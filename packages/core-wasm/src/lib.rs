use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

#[cfg(feature = "zk")]
mod zk;

use treeship_core::attestation::{
    artifact_id_from_pae, digest_from_pae, pae, Envelope, Verifier, VerifyResult,
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
        })
        .to_string(),
        Err(e) => serde_json::json!({
            "valid": false,
            "artifact_id": serde_json::Value::Null,
            "digest": serde_json::Value::Null,
            "verified_keys": Vec::<String>::new(),
            "payload_type": serde_json::Value::Null,
            "error": e,
        })
        .to_string(),
    }
}

fn verify_inner(envelope_json: &str, trusted_keys_json: &str) -> Result<VerifyResult, String> {
    let envelope: Envelope =
        serde_json::from_str(envelope_json).map_err(|e| format!("invalid envelope JSON: {}", e))?;

    let keys_map: HashMap<String, String> = serde_json::from_str(trusted_keys_json)
        .map_err(|e| format!("invalid trusted_keys JSON: {}", e))?;

    let mut verifying_keys: HashMap<String, VerifyingKey> = HashMap::new();
    for (key_id, b64_pubkey) in &keys_map {
        let bytes = URL_SAFE_NO_PAD
            .decode(b64_pubkey)
            .map_err(|e| format!("bad base64 for key {}: {}", key_id, e))?;
        if bytes.len() != 32 {
            return Err(format!(
                "key {} is {} bytes, expected 32",
                key_id,
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let vk = VerifyingKey::from_bytes(&arr)
            .map_err(|e| format!("invalid Ed25519 key {}: {}", key_id, e))?;
        verifying_keys.insert(key_id.clone(), vk);
    }

    let verifier = Verifier::new(verifying_keys);
    verifier.verify_any(&envelope).map_err(|e| format!("{}", e))
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
    let envelope: Envelope =
        serde_json::from_str(envelope_json).map_err(|e| format!("invalid envelope JSON: {}", e))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.payload)
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
    let envelope: Envelope =
        serde_json::from_str(envelope_json).map_err(|e| format!("invalid envelope JSON: {}", e))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.payload)
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
    let envelope: Envelope =
        serde_json::from_str(envelope_json).map_err(|e| format!("invalid envelope JSON: {}", e))?;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.payload)
        .map_err(|e| format!("bad payload base64: {}", e))?;

    String::from_utf8(payload_bytes).map_err(|e| format!("payload is not UTF-8: {}", e))
}

/// Verify a Merkle inclusion proof JSON. The `trust_roots_json` argument
/// pins the checkpoint issuer; pass an empty string for "no trust
/// configured" (which causes verification to fail-closed -- post-audit
/// behavior, the checkpoint's embedded pubkey is no longer trusted on
/// its own).
///
/// Returns JSON: { "valid": true/false, "message": "...", "artifact_id": "...",
///   "leaf_index": N, "checkpoint_index": N, "checkpoint_root": "...",
///   "signed_at": "...", "signer": "..." }
#[wasm_bindgen]
pub fn verify_merkle_proof(proof_json: &str, trust_roots_json: &str) -> String {
    match verify_merkle_inner(proof_json, trust_roots_json) {
        Ok(result) => result,
        Err(e) => serde_json::json!({
            "valid": false,
            "message": e,
        })
        .to_string(),
    }
}

fn verify_merkle_inner(proof_json: &str, trust_roots_json: &str) -> Result<String, String> {
    let proof_file: treeship_core::merkle::ProofFile =
        serde_json::from_str(proof_json).map_err(|e| format!("invalid proof JSON: {}", e))?;

    let trust = parse_wasm_trust_roots(trust_roots_json)?;

    // 1. Verify checkpoint signature against the pinned trust root.
    // The signature now binds merkle_version (see Checkpoint::canonical_for_signing),
    // so a tampered version on the checkpoint reaches us as an invalid signature.
    if !proof_file.checkpoint.verify(&trust) {
        return Ok(serde_json::json!({
            "valid": false,
            "message": "checkpoint signature invalid",
            "artifact_id": proof_file.artifact_id,
            "checkpoint_index": proof_file.checkpoint.index,
        })
        .to_string());
    }

    // 2. Verify inclusion proof. The trusted merkle_version comes from
    // the signature-verified checkpoint above — NOT from the
    // (attacker-controllable) inclusion proof. verify_proof additionally
    // rejects if proof.merkle_version != checkpoint.merkle_version.
    let root = proof_file
        .checkpoint
        .root
        .strip_prefix("sha256:")
        .unwrap_or(&proof_file.checkpoint.root);

    let valid = treeship_core::merkle::MerkleTree::verify_proof(
        proof_file.checkpoint.merkle_version,
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
    })
    .to_string())
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
        })
        .to_string(),
    }
}

fn verify_zk_inner(proof_json: &str) -> Result<String, String> {
    let proof: serde_json::Value =
        serde_json::from_str(proof_json).map_err(|e| format!("invalid proof JSON: {}", e))?;

    let system = proof
        .get("system")
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
    let circuit = proof
        .get("circuit")
        .and_then(|c| c.as_str())
        .unwrap_or("unknown");
    let artifact_id = proof
        .get("artifact_id")
        .and_then(|a| a.as_str())
        .unwrap_or("unknown");
    Ok(serde_json::json!({
        "valid": false,
        "system": "circom-groth16",
        "circuit": circuit,
        "artifact_id": artifact_id,
        "error": "ZK verification not enabled in this WASM build. Rebuild with --features zk.",
    })
    .to_string())
}

fn verify_risc0_proof_inner(proof: &serde_json::Value) -> Result<String, String> {
    // WASM can only do structural validation + journal field presence checks.
    // Full zkVM receipt verification (receipt.verify(GUEST_ID)) requires the
    // native CLI: treeship verify-proof

    let receipt_arr = proof.get("receipt_bytes").and_then(|r| r.as_array());

    let receipt_len = receipt_arr.map(|a| a.len()).unwrap_or(0);

    // No receipt means no proof -- return invalid immediately
    if receipt_len == 0 {
        return Ok(serde_json::json!({
            "valid": false,
            "system": "risc0",
            "error": "no receipt present, proof was generated by placeholder prover",
            "note": "RISC Zero chain proofs require a receipt for any validity claim"
        })
        .to_string());
    }

    // Structural check: attempt to interpret receipt_bytes as a valid byte array.
    // Each element must be a u8 (0-255). If any element is out of range or not
    // a number, the receipt is structurally invalid.
    let receipt_valid_structure = receipt_arr
        .map(|arr| arr.iter().all(|v| v.as_u64().map_or(false, |n| n <= 255)))
        .unwrap_or(false);

    if !receipt_valid_structure {
        return Ok(serde_json::json!({
            "valid": false,
            "system": "risc0",
            "error": "receipt_bytes failed structural validation (not a valid byte array)",
        })
        .to_string());
    }

    // Require journal fields to be present. Without these, the receipt
    // cannot be meaningful even if it deserializes.
    let image_id = proof.get("image_id").and_then(|i| i.as_str());
    let artifact_count = proof.get("artifact_count").and_then(|c| c.as_u64());
    let proved_at = proof.get("proved_at").and_then(|p| p.as_str());

    if image_id.is_none() || artifact_count.is_none() || proved_at.is_none() {
        return Ok(serde_json::json!({
            "valid": false,
            "system": "risc0",
            "error": "missing required journal fields (image_id, artifact_count, proved_at)",
            "has_receipt": true,
        })
        .to_string());
    }

    // Read summary fields for informational output only.
    // These JSON booleans are NOT used to determine validity.
    let all_sigs = proof
        .get("all_signatures_valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let chain_intact = proof
        .get("chain_intact")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let approvals_matched = proof
        .get("approval_nonces_matched")
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

// ============================================================================
// High-level verification exports (v0.9.1)
//
// Same rules as `treeship verify` runs; same result shape across runtimes.
// Each function accepts JSON in, returns JSON out, and never panics. Errors
// surface as { outcome: "error", error_code, message } instead of throwing.
// ============================================================================

/// Verify a Session Receipt JSON document. Runs the receipt-level checks
/// derivable from JSON alone (Merkle root recomputation, inclusion proofs,
/// leaf count, timeline ordering). Signature verification on individual
/// envelopes requires the original envelope bytes and is NOT part of this
/// function — use the CLI's local-storage path for that.
///
/// Returns JSON:
/// ```json
/// {
///   "outcome": "pass" | "fail" | "error",
///   "checks": [{"step": "...", "status": "pass"|"fail"|"warn", "detail": "..."}],
///   "session": {"id": "...", "ship_id": "...", "agent": "...", "duration_ms": 0, "actions": 0},
///   "error_code": "...",   // only on error
///   "message": "..."       // only on error
/// }
/// ```
#[wasm_bindgen]
pub fn verify_receipt(receipt_json: &str) -> String {
    use treeship_core::session::{SessionReceipt, VerifyStatus};
    use treeship_core::verify::verify_receipt_json_checks;

    let receipt: SessionReceipt = match serde_json::from_str(receipt_json) {
        Ok(r) => r,
        Err(e) => return error_result("invalid_json", &format!("invalid receipt JSON: {e}")),
    };

    let checks = verify_receipt_json_checks(&receipt);
    let any_fail = checks.iter().any(|c| c.status == VerifyStatus::Fail);
    // AUD-01 / AUD-P10: these checks are keyless and self-referential — no
    // signature or trust-root check runs here, and an empty receipt passes
    // vacuously. The strongest honest outcome is "structural-pass", never
    // "pass" (which a consumer could read as authenticity). An empty receipt
    // proves nothing, so it is a "fail".
    let empty_receipt = receipt.artifacts.is_empty();
    let outcome = if any_fail || empty_receipt {
        "fail"
    } else {
        "structural-pass"
    };

    let agent_name = receipt
        .agent_graph
        .nodes
        .first()
        .map(|n| n.agent_name.clone())
        .unwrap_or_default();

    serde_json::json!({
        "outcome": outcome,
        "signatures_verified": false,
        "issuer_verified": false,
        "note": "structural checks only (Merkle root, inclusion proofs, leaf count, timeline). Signatures and issuer are NOT verified from a receipt JSON.",
        "checks": checks.iter().map(|c| serde_json::json!({
            "step": c.name,
            "status": status_label(&c.status),
            "detail": c.detail,
        })).collect::<Vec<_>>(),
        "session": {
            "id": receipt.session.id,
            "ship_id": receipt.session.ship_id,
            "schema_version": receipt.schema_version,
            "agent": agent_name,
            "duration_ms": receipt.session.duration_ms,
            "actions": receipt.artifacts.len(),
        }
    })
    .to_string()
}

/// Verify an Agent Certificate JSON document. Checks the embedded Ed25519
/// signature against the certificate's embedded public key, then classifies
/// the validity window relative to `now_rfc3339`. An empty string for
/// `now_rfc3339` defers validity classification and returns only the
/// signature check.
///
/// Returns JSON:
/// ```json
/// {
///   "outcome": "pass" | "fail" | "error",
///   "signature_valid": true|false,
///   "validity": "valid" | "expired" | "not_yet_valid" | "not_checked",
///   "certificate": {"ship_id": "...", "agent_name": "...", "issued_at": "...", "valid_until": "...", "schema_version": "..."},
///   "error_code": "...",
///   "message": "..."
/// }
/// ```
#[wasm_bindgen]
pub fn verify_certificate(cert_json: &str, now_rfc3339: &str, trust_roots_json: &str) -> String {
    use treeship_core::agent::{verify_certificate as verify_cert, AgentCertificate};

    let cert: AgentCertificate = match serde_json::from_str(cert_json) {
        Ok(c) => c,
        Err(e) => return error_result("invalid_json", &format!("invalid certificate JSON: {e}")),
    };

    // Caller-supplied trust roots. Empty string = no trust configured,
    // which makes verification fail closed -- matches the audit fix:
    // the browser-side verifier no longer trusts whatever pubkey the
    // certificate happens to carry.
    let trust = match parse_wasm_trust_roots(trust_roots_json) {
        Ok(t) => t,
        Err(e) => return error_result("invalid_trust_roots", &e),
    };
    let sig_ok = verify_cert(&cert, &trust).is_ok();

    let validity = if now_rfc3339.is_empty() {
        "not_checked".to_string()
    } else if now_rfc3339 < cert.identity.issued_at.as_str() {
        "not_yet_valid".to_string()
    } else if now_rfc3339 > cert.identity.valid_until.as_str() {
        "expired".to_string()
    } else {
        "valid".to_string()
    };

    let outcome = if !sig_ok {
        "fail"
    } else if validity == "not_checked" || validity == "valid" {
        "pass"
    } else {
        "fail"
    };

    serde_json::json!({
        "outcome": outcome,
        "signature_valid": sig_ok,
        "validity": validity,
        "certificate": {
            "ship_id": cert.identity.ship_id,
            "agent_name": cert.identity.agent_name,
            "issued_at": cert.identity.issued_at,
            "valid_until": cert.identity.valid_until,
            "schema_version": cert.schema_version,
        }
    })
    .to_string()
}

/// Cross-verify a Session Receipt against an Agent Certificate. Wraps
/// `treeship_core::verify::cross_verify_receipt_and_certificate` and adds
/// a top-level `ok` roll-up: ship IDs match, certificate is valid, no
/// unauthorized tool calls, and the certificate's embedded signature verifies.
///
/// Returns JSON:
/// ```json
/// {
///   "outcome": "pass" | "fail" | "error",
///   "ok": true|false,
///   "ship_id_status": "match" | "mismatch" | "unknown",
///   "certificate_status": "valid" | "expired" | "not_yet_valid",
///   "certificate_signature_valid": true|false,
///   "authorized_tool_calls": [...],
///   "unauthorized_tool_calls": [...],
///   "authorized_tools_never_called": [...],
///   "error_code": "...", "message": "..."
/// }
/// ```
#[wasm_bindgen]
pub fn cross_verify(
    receipt_json: &str,
    cert_json: &str,
    now_rfc3339: &str,
    trust_roots_json: &str,
) -> String {
    use treeship_core::agent::{verify_certificate as verify_cert, AgentCertificate};
    use treeship_core::session::SessionReceipt;
    use treeship_core::verify::{
        cross_verify_receipt_and_certificate, CertificateStatus, ShipIdStatus,
    };

    let receipt: SessionReceipt = match serde_json::from_str(receipt_json) {
        Ok(r) => r,
        Err(e) => return error_result("invalid_json", &format!("invalid receipt JSON: {e}")),
    };
    let cert: AgentCertificate = match serde_json::from_str(cert_json) {
        Ok(c) => c,
        Err(e) => return error_result("invalid_json", &format!("invalid certificate JSON: {e}")),
    };
    let trust = match parse_wasm_trust_roots(trust_roots_json) {
        Ok(t) => t,
        Err(e) => return error_result("invalid_trust_roots", &e),
    };

    let cert_sig_ok = verify_cert(&cert, &trust).is_ok();
    let result = cross_verify_receipt_and_certificate(&receipt, &cert, now_rfc3339);

    let ship_label = match &result.ship_id_status {
        ShipIdStatus::Match => "match",
        ShipIdStatus::Mismatch { .. } => "mismatch",
        ShipIdStatus::Unknown => "unknown",
    };
    let cert_label = match &result.certificate_status {
        CertificateStatus::Valid => "valid",
        CertificateStatus::Expired { .. } => "expired",
        CertificateStatus::NotYetValid { .. } => "not_yet_valid",
    };

    let ok = cert_sig_ok && result.ok();

    serde_json::json!({
        "outcome": if ok { "pass" } else { "fail" },
        "ok": ok,
        "ship_id_status": ship_label,
        "certificate_status": cert_label,
        "certificate_signature_valid": cert_sig_ok,
        "authorized_tool_calls": result.authorized_tool_calls,
        "unauthorized_tool_calls": result.unauthorized_tool_calls,
        "authorized_tools_never_called": result.authorized_tools_never_called,
    })
    .to_string()
}

fn error_result(error_code: &str, message: &str) -> String {
    serde_json::json!({
        "outcome": "error",
        "error_code": error_code,
        "message": message,
    })
    .to_string()
}

/// Verify an `agent_card.v1` capability card in the browser. Mirrors
/// `treeship verify-capability` but takes the receipts as input (no storage):
///   - `card_json`: the agent_card.v1 DSSE envelope
///   - `actions_json`: a JSON array of action DSSE envelopes to cross-check
///   - `trust_roots_json`: trust roots, for the AgentCert key-bound check
///
/// Shares the matching logic with the CLI via `treeship_core::capability`, so a
/// receipt viewer in the browser reaches the same key-bound / in-scope verdict
/// the CLI does. Honest contract: consistency over the *provided* actions, not
/// completeness. Returns JSON:
/// ```json
/// {
///   "outcome": "pass" | "fail" | "error",
///   "agent": "agent://...", "key_bound": true|false,
///   "declared_tools": [...], "in_scope": N, "out_of_scope": M,
///   "violations": [{ "tool": "..." }], "status": "verified|self-asserted|violations"
/// }
/// ```
#[wasm_bindgen]
pub fn verify_capability(card_json: &str, actions_json: &str, trust_roots_json: &str) -> String {
    use treeship_core::capability::{action_in_scope, declared_tools, is_key_bound};
    use treeship_core::statements::{ActionStatement, ReceiptStatement};

    let card_env: Envelope = match serde_json::from_str(card_json) {
        Ok(e) => e,
        Err(e) => return error_result("invalid_json", &format!("invalid card envelope JSON: {e}")),
    };
    let card_stmt: ReceiptStatement = match card_env.unmarshal_statement() {
        Ok(s) => s,
        Err(e) => return error_result("invalid_card", &format!("card is not a receipt: {e}")),
    };
    if card_stmt.kind != "agent_card.v1" {
        return error_result(
            "not_a_card",
            &format!("kind `{}` is not agent_card.v1", card_stmt.kind),
        );
    }
    let payload = match card_stmt.payload {
        Some(p) => p,
        None => return error_result("invalid_card", "agent_card.v1 has no payload"),
    };
    let card_keyid = payload.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
    let card_agent = payload.get("agent").and_then(|v| v.as_str()).unwrap_or("");
    let tools = declared_tools(&payload);

    let trust = match parse_wasm_trust_roots(trust_roots_json) {
        Ok(t) => t,
        Err(e) => return error_result("invalid_trust_roots", &e),
    };
    // AUD-17: key-bound requires the card's OWN key to have produced a VALID
    // signature, re-verified against the pinned trust roots — never read from
    // the unverified `signatures[0].keyid`, which a forged card can set to a
    // victim's pinned AgentCert key alongside a garbage signature. This
    // mirrors the native CLI (cli/src/commands/capability.rs) so the browser
    // and CLI reach the same verdict by construction, closing the
    // native/WASM strictness split.
    let verifier = verifier_from_wasm_trust(&trust);
    let card_verified: Vec<String> = verifier
        .verify_any(&card_env)
        .map(|r| r.verified_key_ids)
        .unwrap_or_default();
    let key_bound = !card_keyid.is_empty()
        && card_verified.iter().any(|k| k == card_keyid)
        && is_key_bound(card_keyid, card_keyid, &trust);

    // Cross-check the provided action envelopes signed by the card's key.
    let actions: Vec<Envelope> = match serde_json::from_str(actions_json) {
        Ok(a) => a,
        Err(e) => {
            return error_result(
                "invalid_json",
                &format!("invalid actions JSON (expected array of envelopes): {e}"),
            )
        }
    };
    let mut in_scope = 0usize;
    let mut violations: Vec<serde_json::Value> = Vec::new();
    for env in &actions {
        // AUD-17: count an action only when the card's key produced a VALID
        // signature over it (re-verified against trust roots), never on an
        // unverified signatures[0].keyid match — a forged action naming the
        // card's key must not inflate the in-scope count.
        let averified: Vec<String> = verifier
            .verify_any(env)
            .map(|r| r.verified_key_ids)
            .unwrap_or_default();
        if !averified.iter().any(|k| k == card_keyid) {
            continue; // only the card key's VALIDLY-SIGNED actions count
        }
        let Ok(action) = env.unmarshal_statement::<ActionStatement>() else {
            continue;
        };
        if action_in_scope(&action, &tools) {
            in_scope += 1;
        } else {
            let mut label = action.action.clone();
            if let Some(t) = action
                .meta
                .as_ref()
                .and_then(|m| m.get("tool"))
                .and_then(|v| v.as_str())
            {
                label = format!("{} / {t}", action.action);
            }
            violations.push(serde_json::json!({ "tool": label }));
        }
    }

    let status = if !key_bound {
        "self-asserted"
    } else if violations.is_empty() {
        "verified"
    } else {
        "violations"
    };

    serde_json::json!({
        "outcome": if status == "violations" { "fail" } else { "pass" },
        "agent": card_agent,
        "key_bound": key_bound,
        "declared_tools": tools,
        "in_scope": in_scope,
        "out_of_scope": violations.len(),
        "violations": violations,
        "status": status,
    })
    .to_string()
}

/// Parse the `trust_roots_json` argument the WASM verify_* surfaces
/// accept. The JSON shape mirrors the on-disk
/// `~/.treeship/trust_roots.json`:
///
/// ```json
/// { "version": 1, "roots": [ { "key_id": "...", "public_key": "ed25519:...", "kind": "agent_cert", ... } ] }
/// ```
///
/// An empty string means "no trust roots configured" -- verifiers
/// fail-closed in that state, which matches the audit fix.
/// Build a `Verifier` from a parsed WASM trust store, keyed by each root's
/// pinned public key. Mirrors the CLI's `verifier_from_trust` so the browser
/// and CLI verify capability cards the same way (AUD-17).
fn verifier_from_wasm_trust(trust: &treeship_core::trust::TrustRootStore) -> Verifier {
    let mut map: HashMap<String, VerifyingKey> = HashMap::new();
    for r in trust.roots() {
        if let Ok(vk) = treeship_core::trust::decode_ed25519_pubkey(&r.public_key) {
            map.insert(r.key_id.clone(), vk);
        }
    }
    Verifier::new(map)
}

fn parse_wasm_trust_roots(s: &str) -> Result<treeship_core::trust::TrustRootStore, String> {
    use treeship_core::trust::{TrustRoot, TrustRootStore};
    if s.trim().is_empty() {
        return Ok(TrustRootStore::empty());
    }
    #[derive(serde::Deserialize)]
    struct File {
        version: u8,
        roots: Vec<TrustRoot>,
    }
    let file: File =
        serde_json::from_str(s).map_err(|e| format!("invalid trust_roots_json: {e}"))?;
    if file.version != 1 {
        return Err(format!(
            "unsupported trust_roots schema version: {}",
            file.version
        ));
    }
    // Validate every embedded pubkey parses now -- otherwise the
    // verifier would silently ignore a malformed root.
    for r in &file.roots {
        treeship_core::trust::decode_ed25519_pubkey(&r.public_key)
            .map_err(|m| format!("trust root {}: {m}", r.key_id))?;
    }
    Ok(TrustRootStore::with_roots(file.roots))
}

fn status_label(s: &treeship_core::session::VerifyStatus) -> &'static str {
    use treeship_core::session::VerifyStatus;
    match s {
        VerifyStatus::Pass => "pass",
        VerifyStatus::Fail => "fail",
        VerifyStatus::Warn => "warn",
    }
}

/// Version string for the WASM module.
#[wasm_bindgen]
pub fn version() -> String {
    format!("treeship-core-wasm {}", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    //! Unit tests for the high-level verify_* exports. Run with
    //! `cargo test -p treeship-core-wasm` against the host target; the
    //! `wasm_bindgen` attribute does not interfere with native test runs.

    use super::*;
    use treeship_core::session::{
        ArtifactEntry, EventType, LifecycleMode, ReceiptComposer, SessionEvent, SessionManifest,
        SessionStatus,
    };

    fn sample_receipt_json() -> String {
        let mk = |seq: u64, inst: &str, et: EventType| -> SessionEvent {
            SessionEvent {
                event_id: format!("ev_{seq}"),
                timestamp: format!("2026-04-15T08:00:{:02}Z", seq),
                sequence_no: seq,
                session_id: "ssn_wasm_test".into(),
                trace_id: "trace_wasm".into(),
                span_id: format!("span_{seq}"),
                parent_span_id: None,
                agent_id: format!("agent://{inst}"),
                agent_instance_id: inst.into(),
                agent_name: inst.into(),
                agent_role: None,
                host_id: "host_1".into(),
                tool_runtime_id: None,
                event_type: et,
                artifact_ref: None,
                meta: None,
            }
        };
        let events = vec![
            mk(0, "root", EventType::SessionStarted),
            mk(
                1,
                "root",
                EventType::AgentStarted {
                    parent_agent_instance_id: None,
                },
            ),
            mk(
                2,
                "root",
                EventType::AgentCalledTool {
                    tool_name: "Bash".into(),
                    tool_input_digest: None,
                    tool_output_digest: None,
                    duration_ms: Some(8),
                },
            ),
            mk(
                3,
                "root",
                EventType::AgentCompleted {
                    termination_reason: None,
                },
            ),
            mk(
                4,
                "root",
                EventType::SessionClosed {
                    summary: Some("Done".into()),
                    duration_ms: Some(120_000),
                },
            ),
        ];
        let mut m = SessionManifest::new(
            "ssn_wasm_test".into(),
            "ship://ship_demo".into(),
            "2026-04-15T08:00:00Z".into(),
            1_744_704_000_000,
        );
        m.mode = LifecycleMode::Manual;
        m.status = SessionStatus::Completed;
        let artifacts = vec![
            ArtifactEntry {
                artifact_id: "art_001".into(),
                payload_type: "action".into(),
                digest: None,
                signed_at: None,
            },
            ArtifactEntry {
                artifact_id: "art_002".into(),
                payload_type: "action".into(),
                digest: None,
                signed_at: None,
            },
        ];
        let r = ReceiptComposer::compose(&m, &events, artifacts);
        serde_json::to_string(&r).unwrap()
    }

    /// Build a trust_roots_json that pins `pk_b64` for kind `agent_cert`.
    /// Every certificate-verifying WASM test below uses this so the trust
    /// pin doesn't short-circuit before the signature math runs.
    fn trust_roots_for(pk_b64: &str) -> String {
        serde_json::json!({
            "version": 1,
            "roots": [{
                "key_id":     "key_demo",
                "public_key": format!("ed25519:{pk_b64}"),
                "kind":       "agent_cert",
                "label":      "test issuer",
                "added_at":   "2026-05-15T00:00:00Z",
            }]
        })
        .to_string()
    }

    fn sample_cert_with_key(valid_until: &str) -> (String, String) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use treeship_core::agent::{
            AgentCapabilities, AgentCertificate, AgentDeclaration, AgentIdentity,
            CertificateSignature, ToolCapability, CERTIFICATE_SCHEMA_VERSION, CERTIFICATE_TYPE,
        };
        use treeship_core::attestation::{Ed25519Signer, Signer};

        let signer = Ed25519Signer::generate("key_demo").unwrap();
        let pk_b64 = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());

        let identity = AgentIdentity {
            agent_name: "agent-007".into(),
            ship_id: "ship_demo".into(),
            public_key: pk_b64.clone(),
            issuer: "ship://ship_demo".into(),
            issued_at: "2026-04-01T00:00:00Z".into(),
            valid_until: valid_until.into(),
            model: None,
            description: None,
        };
        let capabilities = AgentCapabilities {
            tools: vec![ToolCapability {
                name: "Bash".into(),
                description: None,
            }],
            api_endpoints: vec![],
            mcp_servers: vec![],
        };
        let declaration = AgentDeclaration {
            bounded_actions: vec!["Bash".into()],
            forbidden: vec![],
            escalation_required: vec![],
        };
        let payload = serde_json::json!({
            "identity": identity, "capabilities": capabilities, "declaration": declaration,
        });
        let sig = signer.sign(&serde_json::to_vec(&payload).unwrap()).unwrap();

        let cert = AgentCertificate {
            r#type: CERTIFICATE_TYPE.into(),
            schema_version: Some(CERTIFICATE_SCHEMA_VERSION.into()),
            identity,
            capabilities,
            declaration,
            signature: CertificateSignature {
                algorithm: "ed25519".into(),
                key_id: "key_demo".into(),
                public_key: pk_b64.clone(),
                signature: URL_SAFE_NO_PAD.encode(sig),
                signed_fields: "identity+capabilities+declaration".into(),
            },
        };
        (serde_json::to_string(&cert).unwrap(), pk_b64)
    }

    fn sample_cert_json(valid_until: &str) -> String {
        sample_cert_with_key(valid_until).0
    }

    #[test]
    fn verify_receipt_is_structural_pass_not_authentic() {
        // AUD-01: a consistent receipt is "structural-pass", never "pass".
        // This surface verifies no signature, so it must not imply authenticity.
        let json = sample_receipt_json();
        let out: serde_json::Value = serde_json::from_str(&verify_receipt(&json)).unwrap();
        assert_eq!(out["outcome"], "structural-pass", "got: {out}");
        assert_eq!(out["signatures_verified"], false);
        assert_eq!(out["issuer_verified"], false);
        assert_eq!(out["session"]["id"], "ssn_wasm_test");
        assert_eq!(out["session"]["ship_id"], "ship_demo");
        assert_eq!(out["session"]["actions"], 2);
        assert_eq!(out["session"]["agent"], "root");
    }

    #[test]
    fn verify_receipt_fabricated_but_consistent_is_not_pass() {
        // The attack from AUD-01: fabricate a receipt for an arbitrary ship,
        // fill merkle.root/inclusion_proofs with the PUBLIC algorithm so every
        // self-referential check passes. The outcome must NOT be "pass" and
        // must flag that no signature was verified.
        let mut val: serde_json::Value = serde_json::from_str(&sample_receipt_json()).unwrap();
        val["session"]["ship_id"] = serde_json::Value::String("ship_ATTACKER".into());
        let forged = val.to_string();
        let out: serde_json::Value = serde_json::from_str(&verify_receipt(&forged)).unwrap();
        assert_ne!(
            out["outcome"], "pass",
            "must never claim a plain pass: {out}"
        );
        assert_eq!(out["outcome"], "structural-pass");
        assert_eq!(out["signatures_verified"], false);
    }

    #[test]
    fn verify_receipt_empty_is_fail() {
        // An internally-consistent receipt with zero artifacts proves nothing.
        let mut val: serde_json::Value = serde_json::from_str(&sample_receipt_json()).unwrap();
        val["artifacts"] = serde_json::Value::Array(vec![]);
        val["merkle"]["root"] = serde_json::Value::Null;
        let empty = val.to_string();
        let out: serde_json::Value = serde_json::from_str(&verify_receipt(&empty)).unwrap();
        assert_eq!(out["outcome"], "fail", "empty receipt must fail: {out}");
    }

    #[test]
    fn verify_receipt_returns_error_shape_on_invalid_json() {
        let out: serde_json::Value = serde_json::from_str(&verify_receipt("not json")).unwrap();
        assert_eq!(out["outcome"], "error");
        assert_eq!(out["error_code"], "invalid_json");
    }

    #[test]
    fn verify_receipt_fails_on_tampered_merkle_root() {
        let mut val: serde_json::Value = serde_json::from_str(&sample_receipt_json()).unwrap();
        val["merkle"]["root"] = serde_json::Value::String("mroot_deadbeef".into());
        let tampered = val.to_string();
        let out: serde_json::Value = serde_json::from_str(&verify_receipt(&tampered)).unwrap();
        assert_eq!(out["outcome"], "fail");
        let any_merkle_fail = out["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["step"] == "merkle_root" && c["status"] == "fail");
        assert!(any_merkle_fail, "expected merkle_root to fail: {out}");
    }

    #[test]
    fn verify_certificate_passes_freshly_signed_cert() {
        let (cert, pk) = sample_cert_with_key("2027-01-01T00:00:00Z");
        let trust = trust_roots_for(&pk);
        let out: serde_json::Value =
            serde_json::from_str(&verify_certificate(&cert, "2026-06-01T00:00:00Z", &trust))
                .unwrap();
        assert_eq!(out["outcome"], "pass", "got: {out}");
        assert_eq!(out["signature_valid"], true);
        assert_eq!(out["validity"], "valid");
        assert_eq!(out["certificate"]["ship_id"], "ship_demo");
    }

    #[test]
    fn verify_certificate_flags_expiry() {
        let (cert, pk) = sample_cert_with_key("2026-04-10T00:00:00Z");
        let trust = trust_roots_for(&pk);
        let out: serde_json::Value =
            serde_json::from_str(&verify_certificate(&cert, "2026-06-01T00:00:00Z", &trust))
                .unwrap();
        assert_eq!(out["outcome"], "fail");
        assert_eq!(out["validity"], "expired");
    }

    #[test]
    fn verify_certificate_empty_now_defers_validity() {
        let (cert, pk) = sample_cert_with_key("2027-01-01T00:00:00Z");
        let trust = trust_roots_for(&pk);
        let out: serde_json::Value =
            serde_json::from_str(&verify_certificate(&cert, "", &trust)).unwrap();
        assert_eq!(out["outcome"], "pass");
        assert_eq!(out["validity"], "not_checked");
    }

    /// Trust pin: with no trust_roots_json supplied, the WASM verifier
    /// must reject a freshly-signed cert. This is the headline audit
    /// fix on the browser-side path.
    #[test]
    fn verify_certificate_rejects_with_no_trust_roots() {
        let cert = sample_cert_json("2027-01-01T00:00:00Z");
        let out: serde_json::Value =
            serde_json::from_str(&verify_certificate(&cert, "2026-06-01T00:00:00Z", "")).unwrap();
        assert_eq!(out["outcome"], "fail", "no trust roots must fail: {out}");
        assert_eq!(out["signature_valid"], false);
    }

    /// Trust pin: cert whose issuer is not in the supplied trust set
    /// must be rejected even though the signature math is good.
    #[test]
    fn verify_certificate_rejects_unknown_issuer() {
        let cert = sample_cert_json("2027-01-01T00:00:00Z");
        // Trust a totally unrelated public key.
        let bogus_trust = trust_roots_for(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 32 zero bytes
        );
        let out: serde_json::Value = serde_json::from_str(&verify_certificate(
            &cert,
            "2026-06-01T00:00:00Z",
            &bogus_trust,
        ))
        .unwrap();
        assert_eq!(out["outcome"], "fail", "unknown issuer must fail: {out}");
        assert_eq!(out["signature_valid"], false);
    }

    #[test]
    fn cross_verify_rolls_up_pass() {
        let receipt = sample_receipt_json();
        let (cert, pk) = sample_cert_with_key("2027-01-01T00:00:00Z");
        let trust = trust_roots_for(&pk);
        let out: serde_json::Value = serde_json::from_str(&cross_verify(
            &receipt,
            &cert,
            "2026-06-01T00:00:00Z",
            &trust,
        ))
        .unwrap();
        assert_eq!(out["outcome"], "pass", "got: {out}");
        assert_eq!(out["ok"], true);
        assert_eq!(out["ship_id_status"], "match");
        assert_eq!(out["certificate_status"], "valid");
        assert_eq!(out["certificate_signature_valid"], true);
        assert_eq!(out["unauthorized_tool_calls"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn cross_verify_fails_when_cert_expired() {
        let receipt = sample_receipt_json();
        let (cert, pk) = sample_cert_with_key("2026-04-10T00:00:00Z");
        let trust = trust_roots_for(&pk);
        let out: serde_json::Value = serde_json::from_str(&cross_verify(
            &receipt,
            &cert,
            "2026-06-01T00:00:00Z",
            &trust,
        ))
        .unwrap();
        assert_eq!(out["ok"], false);
        assert_eq!(out["certificate_status"], "expired");
    }

    #[test]
    fn cross_verify_returns_error_on_malformed_input() {
        let out: serde_json::Value =
            serde_json::from_str(&cross_verify("bad", "also bad", "2026-06-01T00:00:00Z", ""))
                .unwrap();
        assert_eq!(out["outcome"], "error");
        assert_eq!(out["error_code"], "invalid_json");
    }

    #[test]
    fn verify_capability_matches_cli_verdict() {
        use treeship_core::attestation::{sign, Ed25519Signer};
        use treeship_core::statements::{payload_type, ActionStatement, ReceiptStatement};

        let signer = Ed25519Signer::generate("key_agent_test").unwrap();
        let keyid = "key_agent_test";

        // agent_card.v1 declaring file.*
        let mut card = ReceiptStatement::new("system://registry", "agent_card.v1");
        card.payload = Some(serde_json::json!({
            "schema": "agent_card.v1",
            "agent": "agent://deployer",
            "keyid": keyid,
            "version": "1.0.0",
            "capabilities": { "tools": ["file.*"] }
        }));
        let card_env = sign(&payload_type("receipt"), &card, &signer)
            .unwrap()
            .envelope;
        let card_json = serde_json::to_string(&card_env).unwrap();

        // file.write (in scope via file.*) and command.run (out of scope)
        let a1 = sign(
            &payload_type("action"),
            &ActionStatement::new("agent://deployer", "file.write"),
            &signer,
        )
        .unwrap()
        .envelope;
        let a2 = sign(
            &payload_type("action"),
            &ActionStatement::new("agent://deployer", "command.run"),
            &signer,
        )
        .unwrap()
        .envelope;
        let actions_json = serde_json::to_string(&vec![a1, a2]).unwrap();

        // Pin the signer's REAL public key under agent_cert. (AUD-17: this
        // test previously pinned a garbage all-A pubkey and still expected
        // key_bound:true — silently encoding the bug that the WASM path never
        // verified the signature. With verification, the pinned key must be
        // the one that actually signed.)
        let real_pk = URL_SAFE_NO_PAD.encode(signer.verifying_key().to_bytes());
        let trust_json = serde_json::json!({
            "version": 1,
            "roots": [{
                "key_id": keyid,
                "public_key": format!("ed25519:{real_pk}"),
                "kind": "agent_cert",
                "label": "",
                "added_at": ""
            }]
        })
        .to_string();

        // With trust roots: key-bound, 1 in / 1 out, status violations -- the
        // exact verdict the CLI verify-capability returns for the same inputs.
        let out: serde_json::Value =
            serde_json::from_str(&verify_capability(&card_json, &actions_json, &trust_json))
                .unwrap();
        assert_eq!(out["key_bound"], true, "{out}");
        assert_eq!(out["in_scope"], 1);
        assert_eq!(out["out_of_scope"], 1);
        assert_eq!(out["status"], "violations");
        assert_eq!(out["agent"], "agent://deployer");

        // Without trust roots, the same card is self-asserted (fail-closed).
        let out2: serde_json::Value =
            serde_json::from_str(&verify_capability(&card_json, &actions_json, "")).unwrap();
        assert_eq!(out2["key_bound"], false);
        assert_eq!(out2["status"], "self-asserted");

        // A non-card receipt is rejected, not silently passed.
        let err: serde_json::Value =
            serde_json::from_str(&verify_capability("{}", "[]", "")).unwrap();
        assert_eq!(err["outcome"], "error");
    }

    // AUD-17: a card whose signatures[0].keyid NAMES a victim's pinned key but
    // is actually signed by an attacker key must NOT be reported key-bound, and
    // a forged in-scope action naming the same key must NOT be counted. This is
    // the forgery the pre-fix WASM path accepted (key_id strings are public).
    #[test]
    fn verify_capability_rejects_forged_signature() {
        use treeship_core::attestation::{sign, Ed25519Signer};
        use treeship_core::statements::{payload_type, ActionStatement, ReceiptStatement};

        // The victim's real key that a counterparty has pinned under AgentCert.
        let victim = Ed25519Signer::generate("key_victim").unwrap();
        let victim_pk = URL_SAFE_NO_PAD.encode(victim.verifying_key().to_bytes());

        // The attacker holds a DIFFERENT key but labels their signer id as the
        // victim's key_id (key_ids are public strings, not secrets).
        let attacker = Ed25519Signer::generate("key_victim").unwrap();

        let mut card = ReceiptStatement::new("system://registry", "agent_card.v1");
        card.payload = Some(serde_json::json!({
            "schema": "agent_card.v1",
            "agent": "agent://deployer",
            "keyid": "key_victim",
            "version": "1.0.0",
            "capabilities": { "tools": ["file.*"] }
        }));
        // Signed by the ATTACKER but its signature carries keyid "key_victim".
        let card_env = sign(&payload_type("receipt"), &card, &attacker)
            .unwrap()
            .envelope;
        let card_json = serde_json::to_string(&card_env).unwrap();

        // A forged in-scope action, also signed by the attacker under key_victim.
        let a1 = sign(
            &payload_type("action"),
            &ActionStatement::new("agent://deployer", "file.write"),
            &attacker,
        )
        .unwrap()
        .envelope;
        let actions_json = serde_json::to_string(&vec![a1]).unwrap();

        // The victim's REAL key is what is pinned.
        let trust_json = serde_json::json!({
            "version": 1,
            "roots": [{
                "key_id": "key_victim",
                "public_key": format!("ed25519:{victim_pk}"),
                "kind": "agent_cert",
                "label": "",
                "added_at": ""
            }]
        })
        .to_string();

        let out: serde_json::Value =
            serde_json::from_str(&verify_capability(&card_json, &actions_json, &trust_json))
                .unwrap();
        assert_eq!(
            out["key_bound"], false,
            "forged card must not be key-bound: {out}"
        );
        assert_eq!(out["status"], "self-asserted");
        assert_eq!(out["in_scope"], 0, "a forged action must not be counted");
    }
}
