//! Verify a command artifact: signature against the provided authorized key
//! set, then payload-type discriminated parse.

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;

use crate::artifacts::types::{
    ApprovalDecision, BudgetUpdate, CommandType, KillCommand, MandateUpdate, TerminateSession,
    TYPE_APPROVAL_DECISION, TYPE_BUDGET_UPDATE, TYPE_KILL_COMMAND, TYPE_MANDATE_UPDATE,
    TYPE_TERMINATE_SESSION,
};
use crate::attestation::{Envelope, VerifyError, Verifier};

/// Returned on successful command verification.
#[derive(Debug)]
pub struct VerifyCommandResult {
    /// The discriminated, deserialized command payload.
    pub command: CommandType,
    /// Content-addressed artifact ID re-derived during verification.
    pub artifact_id: String,
    /// Key IDs that signed this command (subset of the authorized set).
    pub verified_key_ids: Vec<String>,
}

#[derive(Debug)]
pub enum VerifyCommandError {
    /// payloadType on the envelope is not a known command type.
    UnknownPayloadType(String),
    /// Signature verification against the authorized key set failed.
    Signature(VerifyError),
    /// Payload bytes did not deserialize into the expected struct.
    PayloadParse(String),
}

impl std::fmt::Display for VerifyCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownPayloadType(t) => {
                write!(f, "not a command artifact: payloadType '{}' is not a known command", t)
            }
            Self::Signature(e) => write!(f, "command signature: {}", e),
            Self::PayloadParse(e) => write!(f, "command payload parse: {}", e),
        }
    }
}

impl std::error::Error for VerifyCommandError {}

/// Verify a command artifact envelope.
///
/// `authorized_keys` is a (key_id → VerifyingKey) map of issuers permitted to
/// send commands to this ship. Any signature on the envelope from a key
/// outside this set is ignored; if no in-set key produced a valid signature,
/// verification fails. This mirrors the semantics of `Verifier::verify_any`.
///
/// On success returns the deserialized command, its content-addressed
/// artifact ID, and the key IDs that produced valid signatures.
pub fn verify_command(
    envelope: &Envelope,
    authorized_keys: &HashMap<String, VerifyingKey>,
) -> Result<VerifyCommandResult, VerifyCommandError> {
    if !is_known_command_type(&envelope.payload_type) {
        return Err(VerifyCommandError::UnknownPayloadType(
            envelope.payload_type.clone(),
        ));
    }

    let verifier = Verifier::new(authorized_keys.clone());
    let result = verifier
        .verify_any(envelope)
        .map_err(VerifyCommandError::Signature)?;

    let command = match envelope.payload_type.as_str() {
        TYPE_KILL_COMMAND => CommandType::Kill(
            envelope
                .unmarshal_statement::<KillCommand>()
                .map_err(|e| VerifyCommandError::PayloadParse(e.to_string()))?,
        ),
        TYPE_APPROVAL_DECISION => CommandType::ApprovalDecision(
            envelope
                .unmarshal_statement::<ApprovalDecision>()
                .map_err(|e| VerifyCommandError::PayloadParse(e.to_string()))?,
        ),
        TYPE_MANDATE_UPDATE => CommandType::MandateUpdate(
            envelope
                .unmarshal_statement::<MandateUpdate>()
                .map_err(|e| VerifyCommandError::PayloadParse(e.to_string()))?,
        ),
        TYPE_BUDGET_UPDATE => CommandType::BudgetUpdate(
            envelope
                .unmarshal_statement::<BudgetUpdate>()
                .map_err(|e| VerifyCommandError::PayloadParse(e.to_string()))?,
        ),
        TYPE_TERMINATE_SESSION => CommandType::TerminateSession(
            envelope
                .unmarshal_statement::<TerminateSession>()
                .map_err(|e| VerifyCommandError::PayloadParse(e.to_string()))?,
        ),
        // Filtered out by is_known_command_type above.
        other => return Err(VerifyCommandError::UnknownPayloadType(other.into())),
    };

    Ok(VerifyCommandResult {
        command,
        artifact_id: result.artifact_id,
        verified_key_ids: result.verified_key_ids,
    })
}

fn is_known_command_type(pt: &str) -> bool {
    matches!(
        pt,
        TYPE_KILL_COMMAND
            | TYPE_APPROVAL_DECISION
            | TYPE_MANDATE_UPDATE
            | TYPE_BUDGET_UPDATE
            | TYPE_TERMINATE_SESSION
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::types::Decision;
    use crate::attestation::{sign, Ed25519Signer, Signer};

    fn signer(id: &str) -> Ed25519Signer {
        Ed25519Signer::generate(id).unwrap()
    }

    fn keys(signers: &[&Ed25519Signer]) -> HashMap<String, VerifyingKey> {
        let mut m = HashMap::new();
        for s in signers {
            m.insert(s.key_id().to_string(), s.verifying_key());
        }
        m
    }

    #[test]
    fn verify_kill_command_round_trip() {
        let s = signer("issuer_1");
        let payload = KillCommand {
            session_id: "ssn_abc".into(),
            reason: "policy violation".into(),
            issued_at: "2026-04-18T10:00:00Z".into(),
        };
        let signed = sign(TYPE_KILL_COMMAND, &payload, &s).unwrap();
        let result = verify_command(&signed.envelope, &keys(&[&s])).unwrap();
        assert_eq!(result.command.kind(), "kill");
        match result.command {
            CommandType::Kill(k) => assert_eq!(k, payload),
            other => panic!("expected Kill, got {:?}", other),
        }
        assert_eq!(result.verified_key_ids, vec!["issuer_1"]);
        assert!(result.artifact_id.starts_with("art_"));
    }

    #[test]
    fn verify_approval_decision_round_trip() {
        let s = signer("approver_1");
        let payload = ApprovalDecision {
            approval_artifact_id: "art_pending".into(),
            decision: Decision::Approve,
            reason: Some("looks safe".into()),
            decided_at: "2026-04-18T10:01:00Z".into(),
        };
        let signed = sign(TYPE_APPROVAL_DECISION, &payload, &s).unwrap();
        let result = verify_command(&signed.envelope, &keys(&[&s])).unwrap();
        match result.command {
            CommandType::ApprovalDecision(d) => assert_eq!(d, payload),
            other => panic!("expected ApprovalDecision, got {:?}", other),
        }
    }

    #[test]
    fn verify_mandate_and_budget_and_terminate() {
        let s = signer("issuer_1");
        let trusted = keys(&[&s]);

        let mandate = MandateUpdate {
            ship_id: "ship_demo".into(),
            new_bounded_actions: vec!["Bash".into()],
            new_forbidden: vec!["DropDatabase".into()],
            valid_until: Some("2026-12-31T00:00:00Z".into()),
        };
        let env = sign(TYPE_MANDATE_UPDATE, &mandate, &s).unwrap().envelope;
        assert!(matches!(verify_command(&env, &trusted).unwrap().command, CommandType::MandateUpdate(_)));

        let budget = BudgetUpdate {
            ship_id: "ship_demo".into(),
            token_limit_delta: -50_000,
            valid_until: None,
        };
        let env = sign(TYPE_BUDGET_UPDATE, &budget, &s).unwrap().envelope;
        assert!(matches!(verify_command(&env, &trusted).unwrap().command, CommandType::BudgetUpdate(_)));

        let term = TerminateSession {
            session_id: "ssn_abc".into(),
            reason: "user requested".into(),
            requested_at: "2026-04-18T11:00:00Z".into(),
        };
        let env = sign(TYPE_TERMINATE_SESSION, &term, &s).unwrap().envelope;
        assert!(matches!(verify_command(&env, &trusted).unwrap().command, CommandType::TerminateSession(_)));
    }

    #[test]
    fn unauthorized_signer_rejected() {
        // Issuer not in the trusted key set.
        let issuer = signer("rogue_issuer");
        let trusted = keys(&[&signer("real_issuer")]);
        let payload = KillCommand {
            session_id: "ssn_abc".into(),
            reason: "evil".into(),
            issued_at: "2026-04-18T10:00:00Z".into(),
        };
        let signed = sign(TYPE_KILL_COMMAND, &payload, &issuer).unwrap();
        let err = verify_command(&signed.envelope, &trusted).unwrap_err();
        assert!(matches!(err, VerifyCommandError::Signature(_)),
            "expected Signature error for unauthorized signer, got: {err}");
    }

    #[test]
    fn non_command_payload_type_rejected() {
        let s = signer("issuer_1");
        // Sign with the action payload type instead of a command type.
        let signed = sign(
            "application/vnd.treeship.action.v1+json",
            &KillCommand {
                session_id: "ssn".into(),
                reason: "x".into(),
                issued_at: "2026-04-18T10:00:00Z".into(),
            },
            &s,
        )
        .unwrap();
        let err = verify_command(&signed.envelope, &keys(&[&s])).unwrap_err();
        assert!(matches!(err, VerifyCommandError::UnknownPayloadType(_)));
    }

    #[test]
    fn tampered_command_payload_rejected() {
        let s = signer("issuer_1");
        let payload = KillCommand {
            session_id: "ssn_a".into(),
            reason: "x".into(),
            issued_at: "2026-04-18T10:00:00Z".into(),
        };
        let mut signed = sign(TYPE_KILL_COMMAND, &payload, &s).unwrap();
        // Replace the payload bytes with a different command. PAE was over
        // the original payload so signature verification must fail.
        let evil = KillCommand {
            session_id: "ssn_other".into(),
            reason: "evil".into(),
            issued_at: "2026-04-18T10:00:00Z".into(),
        };
        let evil_bytes = serde_json::to_vec(&evil).unwrap();
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        signed.envelope.payload = URL_SAFE_NO_PAD.encode(evil_bytes);
        let err = verify_command(&signed.envelope, &keys(&[&s])).unwrap_err();
        assert!(matches!(err, VerifyCommandError::Signature(_)));
    }

    #[test]
    fn malformed_payload_rejected_after_valid_signature() {
        // Sign garbage bytes under the kill payload type. Signature check
        // passes, payload parse fails.
        let s = signer("issuer_1");
        #[derive(serde::Serialize)]
        struct Garbage { not_a_kill_field: u32 }
        let signed = sign(TYPE_KILL_COMMAND, &Garbage { not_a_kill_field: 7 }, &s).unwrap();
        let err = verify_command(&signed.envelope, &keys(&[&s])).unwrap_err();
        assert!(matches!(err, VerifyCommandError::PayloadParse(_)),
            "expected PayloadParse, got: {err}");
    }
}
