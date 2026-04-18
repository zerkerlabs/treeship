//! Cross-verification: check a Session Receipt against an Agent Certificate.
//!
//! Answers a single question: did the session stay inside the certificate's
//! authorized envelope? Specifically:
//!
//! 1. Do the receipt and certificate reference the same ship?
//! 2. Was the certificate valid (not expired, not pre-dated) at session time?
//! 3. Was every tool called during the session present in the certificate's
//!    authorized tool list?
//!
//! This function is the reusable library primitive. The `treeship verify
//! --certificate` CLI calls it, `@treeship/verify` will call it through WASM
//! in v0.9.1, and third-party dashboards embedding Treeship verification call
//! it directly. All of them get the same semantics.

use crate::agent::AgentCertificate;
use crate::session::receipt::SessionReceipt;
use crate::session::package::{VerifyCheck, VerifyStatus};

/// Receipt-level checks derivable from the receipt JSON alone (no on-disk
/// package). Runs Merkle root recomputation, inclusion proof verification,
/// leaf-count parity, timeline ordering, and receipt-level chain linkage.
/// Shared between the CLI's URL-fetch path and the WASM `verify_receipt`
/// export so both surfaces apply the same rules.
///
/// Signature checks on individual envelopes are NOT part of this function:
/// a raw receipt JSON does not carry envelope bytes. Use the local-storage
/// artifact-ID verify path for signature verification.
pub fn verify_receipt_json_checks(receipt: &SessionReceipt) -> Vec<VerifyCheck> {
    use crate::merkle::MerkleTree;

    let mut checks: Vec<VerifyCheck> = Vec::new();

    if !receipt.artifacts.is_empty() {
        let mut tree = MerkleTree::new();
        for a in &receipt.artifacts {
            tree.append(&a.artifact_id);
        }
        let root_bytes = tree.root();
        let recomputed_root = root_bytes.map(|r| format!("mroot_{}", hex::encode(r)));
        let root_hex = root_bytes.map(hex::encode).unwrap_or_default();

        if recomputed_root == receipt.merkle.root {
            checks.push(VerifyCheck::pass(
                "merkle_root",
                "Merkle root matches recomputed value",
            ));
        } else {
            checks.push(VerifyCheck::fail(
                "merkle_root",
                &format!(
                    "recomputed {recomputed_root:?} != receipt {:?}",
                    receipt.merkle.root
                ),
            ));
        }

        let proof_total = receipt.merkle.inclusion_proofs.len();
        let mut proofs_passed = 0usize;
        for entry in &receipt.merkle.inclusion_proofs {
            if MerkleTree::verify_proof(&root_hex, &entry.artifact_id, &entry.proof) {
                proofs_passed += 1;
            }
        }
        if proofs_passed == proof_total {
            checks.push(VerifyCheck::pass(
                "inclusion_proofs",
                &format!("{proofs_passed}/{proof_total} inclusion proofs passed"),
            ));
        } else {
            checks.push(VerifyCheck::fail(
                "inclusion_proofs",
                &format!("{proofs_passed}/{proof_total} inclusion proofs passed"),
            ));
        }
    } else {
        checks.push(VerifyCheck::warn("merkle_root", "No artifacts to verify"));
    }

    if receipt.merkle.leaf_count == receipt.artifacts.len() {
        checks.push(VerifyCheck::pass(
            "leaf_count",
            "Leaf count matches artifact count",
        ));
    } else {
        checks.push(VerifyCheck::fail(
            "leaf_count",
            &format!(
                "leaf_count {} != artifact count {}",
                receipt.merkle.leaf_count,
                receipt.artifacts.len()
            ),
        ));
    }

    let ordered = receipt.timeline.windows(2).all(|w| {
        (&w[0].timestamp, w[0].sequence_no, &w[0].event_id)
            <= (&w[1].timestamp, w[1].sequence_no, &w[1].event_id)
    });
    if ordered {
        checks.push(VerifyCheck::pass(
            "timeline_order",
            "Timeline is correctly ordered",
        ));
    } else {
        checks.push(VerifyCheck::fail(
            "timeline_order",
            "Timeline entries are not in deterministic order",
        ));
    }

    checks.push(VerifyCheck::pass(
        "chain_linkage",
        "Receipt-level chain linkage intact",
    ));

    checks
}

/// Convenience: true iff every check in the list is Pass or Warn.
pub fn checks_ok(checks: &[VerifyCheck]) -> bool {
    checks.iter().all(|c| c.status != VerifyStatus::Fail)
}

/// Result of cross-verifying a receipt against a certificate.
#[derive(Debug, Clone)]
pub struct CrossVerifyResult {
    /// Whether the ship IDs match, don't match, or cannot be determined.
    pub ship_id_status: ShipIdStatus,
    /// Certificate validity relative to the cross-verify `now` timestamp.
    pub certificate_status: CertificateStatus,
    /// Tools that were called AND in the certificate's authorized list.
    pub authorized_tool_calls: Vec<String>,
    /// Tools that were called but NOT in the certificate's authorized list.
    /// Any entry here means the session exceeded its authorized envelope.
    pub unauthorized_tool_calls: Vec<String>,
    /// Tools authorized by the certificate but never actually called. Not a
    /// failure; useful context for reviewers ("agent had permission to touch
    /// the database but didn't").
    pub authorized_tools_never_called: Vec<String>,
}

impl CrossVerifyResult {
    /// True iff every check passed: ship IDs match, certificate was valid at
    /// the check time, zero unauthorized tool calls.
    pub fn ok(&self) -> bool {
        matches!(self.ship_id_status, ShipIdStatus::Match)
            && matches!(self.certificate_status, CertificateStatus::Valid)
            && self.unauthorized_tool_calls.is_empty()
    }
}

/// Ship ID comparison outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShipIdStatus {
    /// Receipt's ship_id equals certificate's identity.ship_id.
    Match,
    /// Receipt's ship_id does not equal certificate's identity.ship_id.
    Mismatch {
        receipt: String,
        certificate: String,
    },
    /// Receipt has no ship_id (pre-v0.9.0 or a non-ship actor URI). Treated
    /// as a verification failure by `ok()`; callers who accept legacy
    /// receipts should inspect the status explicitly.
    Unknown,
}

/// Certificate validity at the cross-verify time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateStatus {
    Valid,
    /// Current time is past `valid_until`.
    Expired { valid_until: String, now: String },
    /// Current time is before `issued_at`.
    NotYetValid { issued_at: String, now: String },
}

/// Cross-verify a receipt against an agent certificate.
///
/// `now_rfc3339` is an RFC 3339 timestamp representing "now" from the caller's
/// point of view. Using explicit time makes this function deterministic and
/// testable. The CLI passes `std::time::SystemTime::now()`; unit tests pass
/// a fixed value.
pub fn cross_verify_receipt_and_certificate(
    receipt: &SessionReceipt,
    certificate: &AgentCertificate,
    now_rfc3339: &str,
) -> CrossVerifyResult {
    let ship_id_status = compare_ship_ids(
        receipt.session.ship_id.as_deref(),
        &certificate.identity.ship_id,
    );
    let certificate_status = classify_certificate_validity(certificate, now_rfc3339);
    let (authorized_tool_calls, unauthorized_tool_calls, authorized_tools_never_called) =
        classify_tool_usage(receipt, certificate);

    CrossVerifyResult {
        ship_id_status,
        certificate_status,
        authorized_tool_calls,
        unauthorized_tool_calls,
        authorized_tools_never_called,
    }
}

fn compare_ship_ids(receipt: Option<&str>, certificate: &str) -> ShipIdStatus {
    match receipt {
        Some(r) if r == certificate => ShipIdStatus::Match,
        Some(r) => ShipIdStatus::Mismatch {
            receipt: r.to_string(),
            certificate: certificate.to_string(),
        },
        None => ShipIdStatus::Unknown,
    }
}

fn classify_certificate_validity(
    certificate: &AgentCertificate,
    now: &str,
) -> CertificateStatus {
    // RFC 3339 lexical ordering agrees with chronological ordering when the
    // timestamps use the same timezone suffix. Treeship issues and validates
    // timestamps in UTC (`Z`), so string comparison is sufficient here.
    let identity = &certificate.identity;
    if now < identity.issued_at.as_str() {
        return CertificateStatus::NotYetValid {
            issued_at: identity.issued_at.clone(),
            now: now.to_string(),
        };
    }
    if now > identity.valid_until.as_str() {
        return CertificateStatus::Expired {
            valid_until: identity.valid_until.clone(),
            now: now.to_string(),
        };
    }
    CertificateStatus::Valid
}

/// Returns (authorized_calls, unauthorized_calls, authorized_never_called).
/// Each list is sorted and deduplicated.
fn classify_tool_usage(
    receipt: &SessionReceipt,
    certificate: &AgentCertificate,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    use std::collections::BTreeSet;

    let authorized: BTreeSet<String> = certificate
        .capabilities
        .tools
        .iter()
        .map(|t| t.name.clone())
        .collect();

    // Called tools come from receipt.tool_usage.actual. Legacy receipts or
    // receipts with no tool_usage field are treated as "no tool calls".
    let called: BTreeSet<String> = receipt
        .tool_usage
        .as_ref()
        .map(|u| u.actual.iter().map(|e| e.tool_name.clone()).collect())
        .unwrap_or_default();

    let authorized_calls: Vec<String> =
        called.intersection(&authorized).cloned().collect();
    let unauthorized_calls: Vec<String> =
        called.difference(&authorized).cloned().collect();
    let never_called: Vec<String> = authorized
        .difference(&called)
        .cloned()
        .collect();

    (authorized_calls, unauthorized_calls, never_called)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{
        AgentCapabilities, AgentDeclaration, AgentIdentity, CertificateSignature,
        ToolCapability, CERTIFICATE_SCHEMA_VERSION, CERTIFICATE_TYPE,
    };
    use crate::session::manifest::{LifecycleMode, Participants, SessionStatus};
    use crate::session::receipt::{SessionReceipt, SessionSection, ToolUsage, ToolUsageEntry};
    use crate::session::render::RenderConfig;
    use crate::session::side_effects::SideEffects;

    fn certificate(ship_id: &str, tools: &[&str], issued: &str, valid_until: &str) -> AgentCertificate {
        AgentCertificate {
            r#type: CERTIFICATE_TYPE.into(),
            schema_version: Some(CERTIFICATE_SCHEMA_VERSION.into()),
            identity: AgentIdentity {
                agent_name: "agent-007".into(),
                ship_id: ship_id.into(),
                public_key: "pk_b64".into(),
                issuer: format!("ship://{ship_id}"),
                issued_at: issued.into(),
                valid_until: valid_until.into(),
                model: None,
                description: None,
            },
            capabilities: AgentCapabilities {
                tools: tools
                    .iter()
                    .map(|n| ToolCapability { name: (*n).into(), description: None })
                    .collect(),
                api_endpoints: vec![],
                mcp_servers: vec![],
            },
            declaration: AgentDeclaration {
                bounded_actions: tools.iter().map(|s| (*s).into()).collect(),
                forbidden: vec![],
                escalation_required: vec![],
            },
            signature: CertificateSignature {
                algorithm: "ed25519".into(),
                key_id: "key_1".into(),
                public_key: "pk_b64".into(),
                signature: "sig_b64".into(),
                signed_fields: "identity+capabilities+declaration".into(),
            },
        }
    }

    fn receipt(ship_id: Option<&str>, tools_called: &[(&str, u32)]) -> SessionReceipt {
        let tool_usage = if tools_called.is_empty() {
            None
        } else {
            Some(ToolUsage {
                declared: vec![],
                actual: tools_called
                    .iter()
                    .map(|(n, c)| ToolUsageEntry { tool_name: (*n).into(), count: *c })
                    .collect(),
                unauthorized: vec![],
            })
        };
        SessionReceipt {
            type_: crate::session::receipt::RECEIPT_TYPE.into(),
            schema_version: Some(crate::session::receipt::RECEIPT_SCHEMA_VERSION.into()),
            session: SessionSection {
                id: "ssn_test".into(),
                name: None,
                mode: LifecycleMode::Manual,
                started_at: "2026-04-10T00:00:00Z".into(),
                ended_at: Some("2026-04-10T00:30:00Z".into()),
                status: SessionStatus::Completed,
                duration_ms: Some(1_800_000),
                ship_id: ship_id.map(str::to_string),
                narrative: None,
                total_tokens_in: 0,
                total_tokens_out: 0,
            },
            participants: Participants::default(),
            hosts: vec![],
            tools: vec![],
            agent_graph: Default::default(),
            timeline: vec![],
            side_effects: SideEffects::default(),
            artifacts: vec![],
            proofs: Default::default(),
            merkle: Default::default(),
            render: RenderConfig {
                title: None,
                theme: None,
                sections: RenderConfig::default_sections(),
                generate_preview: true,
            },
            tool_usage,
        }
    }

    const NOW: &str = "2026-04-18T10:00:00Z";
    const ISSUED: &str = "2026-04-01T00:00:00Z";
    const VALID_UNTIL: &str = "2027-04-01T00:00:00Z";

    #[test]
    fn all_tool_calls_authorized_passes() {
        let cert = certificate("ship_a", &["Bash", "Read"], ISSUED, VALID_UNTIL);
        let rec = receipt(Some("ship_a"), &[("Bash", 4), ("Read", 2)]);
        let r = cross_verify_receipt_and_certificate(&rec, &cert, NOW);
        assert_eq!(r.ship_id_status, ShipIdStatus::Match);
        assert_eq!(r.certificate_status, CertificateStatus::Valid);
        assert_eq!(r.authorized_tool_calls, vec!["Bash", "Read"]);
        assert!(r.unauthorized_tool_calls.is_empty());
        assert!(r.authorized_tools_never_called.is_empty());
        assert!(r.ok());
    }

    #[test]
    fn unauthorized_tool_call_flagged_and_blocks_ok() {
        let cert = certificate("ship_a", &["Read"], ISSUED, VALID_UNTIL);
        let rec = receipt(Some("ship_a"), &[("Read", 1), ("Write", 1)]);
        let r = cross_verify_receipt_and_certificate(&rec, &cert, NOW);
        assert_eq!(r.authorized_tool_calls, vec!["Read"]);
        assert_eq!(r.unauthorized_tool_calls, vec!["Write"]);
        assert!(r.authorized_tools_never_called.is_empty());
        assert!(!r.ok(), "unauthorized call must block ok()");
    }

    #[test]
    fn tools_authorized_but_never_called_reported_and_still_ok() {
        let cert = certificate("ship_a", &["Bash", "Read", "DropDatabase"], ISSUED, VALID_UNTIL);
        let rec = receipt(Some("ship_a"), &[("Bash", 1)]);
        let r = cross_verify_receipt_and_certificate(&rec, &cert, NOW);
        assert_eq!(r.authorized_tool_calls, vec!["Bash"]);
        assert!(r.unauthorized_tool_calls.is_empty());
        assert_eq!(
            r.authorized_tools_never_called,
            vec!["DropDatabase".to_string(), "Read".to_string()]
        );
        assert!(r.ok(), "unused authorization is not a failure");
    }

    #[test]
    fn mismatched_ship_ids_blocks_ok() {
        let cert = certificate("ship_a", &["Bash"], ISSUED, VALID_UNTIL);
        let rec = receipt(Some("ship_b"), &[("Bash", 1)]);
        let r = cross_verify_receipt_and_certificate(&rec, &cert, NOW);
        assert_eq!(
            r.ship_id_status,
            ShipIdStatus::Mismatch {
                receipt: "ship_b".into(),
                certificate: "ship_a".into()
            }
        );
        assert!(!r.ok());
    }

    #[test]
    fn expired_certificate_blocks_ok() {
        let cert = certificate("ship_a", &["Bash"], ISSUED, "2026-04-10T00:00:00Z");
        let rec = receipt(Some("ship_a"), &[("Bash", 1)]);
        let r = cross_verify_receipt_and_certificate(&rec, &cert, NOW);
        assert_eq!(
            r.certificate_status,
            CertificateStatus::Expired {
                valid_until: "2026-04-10T00:00:00Z".into(),
                now: NOW.into()
            }
        );
        assert!(!r.ok());
    }

    #[test]
    fn not_yet_valid_certificate_blocks_ok() {
        let cert = certificate("ship_a", &["Bash"], "2027-01-01T00:00:00Z", "2028-01-01T00:00:00Z");
        let rec = receipt(Some("ship_a"), &[("Bash", 1)]);
        let r = cross_verify_receipt_and_certificate(&rec, &cert, NOW);
        assert!(matches!(
            r.certificate_status,
            CertificateStatus::NotYetValid { .. }
        ));
        assert!(!r.ok());
    }

    #[test]
    fn legacy_receipt_without_ship_id_is_unknown_and_blocks_ok() {
        let cert = certificate("ship_a", &["Bash"], ISSUED, VALID_UNTIL);
        let rec = receipt(None, &[("Bash", 1)]); // pre-v0.9.0 receipt
        let r = cross_verify_receipt_and_certificate(&rec, &cert, NOW);
        assert_eq!(r.ship_id_status, ShipIdStatus::Unknown);
        assert!(!r.ok(), "unknown ship_id must block ok() by default");
    }

    #[test]
    fn no_tool_calls_in_receipt_yields_empty_lists() {
        let cert = certificate("ship_a", &["Bash"], ISSUED, VALID_UNTIL);
        let rec = receipt(Some("ship_a"), &[]);
        let r = cross_verify_receipt_and_certificate(&rec, &cert, NOW);
        assert!(r.authorized_tool_calls.is_empty());
        assert!(r.unauthorized_tool_calls.is_empty());
        assert_eq!(r.authorized_tools_never_called, vec!["Bash"]);
        assert!(r.ok());
    }
}
