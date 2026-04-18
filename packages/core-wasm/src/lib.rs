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

// ============================================================================
// High-level verification exports (v0.9.1)
//
// Same rules as `treeship verify` runs; same result shape across runtimes.
// Each function accepts JSON in, returns JSON out, and never panics. Errors
// surface as { outcome: "error", error_code, message } instead of throwing.
// ============================================================================

/// Verify a Session Receipt JSON document. Runs the receipt-level checks
/// derivable from JSON alone (Merkle root recomputation, inclusion proofs,
/// leaf count, timeline ordering, chain linkage). Signature verification on
/// individual envelopes requires the original envelope bytes and is NOT
/// part of this function — use the CLI's local-storage path for that.
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

    let agent_name = receipt
        .agent_graph
        .nodes
        .first()
        .map(|n| n.agent_name.clone())
        .unwrap_or_default();

    serde_json::json!({
        "outcome": if any_fail { "fail" } else { "pass" },
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
pub fn verify_certificate(cert_json: &str, now_rfc3339: &str) -> String {
    use treeship_core::agent::{verify_certificate as verify_cert, AgentCertificate};

    let cert: AgentCertificate = match serde_json::from_str(cert_json) {
        Ok(c) => c,
        Err(e) => return error_result("invalid_json", &format!("invalid certificate JSON: {e}")),
    };

    let sig_ok = verify_cert(&cert).is_ok();

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
pub fn cross_verify(receipt_json: &str, cert_json: &str, now_rfc3339: &str) -> String {
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

    let cert_sig_ok = verify_cert(&cert).is_ok();
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
            mk(1, "root", EventType::AgentStarted { parent_agent_instance_id: None }),
            mk(2, "root", EventType::AgentCalledTool {
                tool_name: "Bash".into(),
                tool_input_digest: None,
                tool_output_digest: None,
                duration_ms: Some(8),
            }),
            mk(3, "root", EventType::AgentCompleted { termination_reason: None }),
            mk(4, "root", EventType::SessionClosed {
                summary: Some("Done".into()),
                duration_ms: Some(120_000),
            }),
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
            ArtifactEntry { artifact_id: "art_001".into(), payload_type: "action".into(), digest: None, signed_at: None },
            ArtifactEntry { artifact_id: "art_002".into(), payload_type: "action".into(), digest: None, signed_at: None },
        ];
        let r = ReceiptComposer::compose(&m, &events, artifacts);
        serde_json::to_string(&r).unwrap()
    }

    fn sample_cert_json(valid_until: &str) -> String {
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
            tools: vec![ToolCapability { name: "Bash".into(), description: None }],
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
                public_key: pk_b64,
                signature: URL_SAFE_NO_PAD.encode(sig),
                signed_fields: "identity+capabilities+declaration".into(),
            },
        };
        serde_json::to_string(&cert).unwrap()
    }

    #[test]
    fn verify_receipt_passes_on_fresh_compose() {
        let json = sample_receipt_json();
        let out: serde_json::Value = serde_json::from_str(&verify_receipt(&json)).unwrap();
        assert_eq!(out["outcome"], "pass", "got: {out}");
        assert_eq!(out["session"]["id"], "ssn_wasm_test");
        assert_eq!(out["session"]["ship_id"], "ship_demo");
        assert_eq!(out["session"]["actions"], 2);
        assert_eq!(out["session"]["agent"], "root");
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
        let cert = sample_cert_json("2027-01-01T00:00:00Z");
        let out: serde_json::Value =
            serde_json::from_str(&verify_certificate(&cert, "2026-06-01T00:00:00Z")).unwrap();
        assert_eq!(out["outcome"], "pass", "got: {out}");
        assert_eq!(out["signature_valid"], true);
        assert_eq!(out["validity"], "valid");
        assert_eq!(out["certificate"]["ship_id"], "ship_demo");
    }

    #[test]
    fn verify_certificate_flags_expiry() {
        let cert = sample_cert_json("2026-04-10T00:00:00Z");
        let out: serde_json::Value =
            serde_json::from_str(&verify_certificate(&cert, "2026-06-01T00:00:00Z")).unwrap();
        assert_eq!(out["outcome"], "fail");
        assert_eq!(out["validity"], "expired");
    }

    #[test]
    fn verify_certificate_empty_now_defers_validity() {
        let cert = sample_cert_json("2027-01-01T00:00:00Z");
        let out: serde_json::Value =
            serde_json::from_str(&verify_certificate(&cert, "")).unwrap();
        assert_eq!(out["outcome"], "pass");
        assert_eq!(out["validity"], "not_checked");
    }

    #[test]
    fn cross_verify_rolls_up_pass() {
        let receipt = sample_receipt_json();
        let cert = sample_cert_json("2027-01-01T00:00:00Z");
        let out: serde_json::Value =
            serde_json::from_str(&cross_verify(&receipt, &cert, "2026-06-01T00:00:00Z")).unwrap();
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
        let cert = sample_cert_json("2026-04-10T00:00:00Z");
        let out: serde_json::Value =
            serde_json::from_str(&cross_verify(&receipt, &cert, "2026-06-01T00:00:00Z")).unwrap();
        assert_eq!(out["ok"], false);
        assert_eq!(out["certificate_status"], "expired");
    }

    #[test]
    fn cross_verify_returns_error_on_malformed_input() {
        let out: serde_json::Value =
            serde_json::from_str(&cross_verify("bad", "also bad", "2026-06-01T00:00:00Z")).unwrap();
        assert_eq!(out["outcome"], "error");
        assert_eq!(out["error_code"], "invalid_json");
    }
}
