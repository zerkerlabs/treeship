//! The Treeship `agent_attestation` scheme.
//!
//! The spec's claim is `{"type": <scheme>, "value": <payload>}` and a
//! verifier that does not know `type` must ignore it. Treeship registers one
//! scheme name and fills `value` with a signed statement that ties the L3
//! credential to the agent's receipt chain:
//!
//! - `session`: the Treeship session id, which names the exported package;
//! - `chain_head`: the id of the last receipt in the chain when the
//!   credential was minted;
//! - `checkpoint`: the Merkle root over that chain (`mroot_…`), so any single
//!   receipt's inclusion can be proven;
//! - `approval_use`: the digest of the approval-use record the action ran
//!   under, when one exists;
//! - `mandate_digest`: `B64U(SHA-256(L2 base JWT))`, so the attestation names
//!   the mandate it was issued against;
//! - `transaction_id`: the checkout hash both L3 halves carry.
//!
//! The statement is signed with the ship's Ed25519 key as a DSSE envelope and
//! stored as an artifact chained onto `chain_head`, so the attestation is
//! itself a receipt. `value` carries the envelope, its artifact id, and the
//! signing public key, which makes it self-contained: any Ed25519 library
//! confirms the signature, and `treeship verify` confirms the chain.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::attestation::{sign, verify_with_key, Envelope, SignResult, Signer};
use crate::statements::{payload_type, ActionStatement, TYPE_ACTION};

use super::jws::b64u;
use super::ViError;

/// The `type` of the claim.
pub const ATTESTATION_SCHEME: &str = "treeship.receipt-chain.v1";
/// The action name of the receipt the attestation is: an ordinary
/// `treeship/action/v1` statement, so every existing verifier, package and
/// preview understands it and its `parentId` is inside the signature.
pub const ATTESTATION_ACTION: &str = "vi.l3.attested";
/// The `type` the attestation fields carry inside the action's `meta`.
pub const ATTESTATION_STATEMENT_TYPE: &str = "treeship/vi-attestation/v1";

/// The DSSE payload type of the signed receipt (an action).
pub fn attestation_payload_type() -> String {
    payload_type("action")
}

/// What the ship signs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationStatement {
    #[serde(rename = "type")]
    pub type_: String,
    /// RFC 3339, the signer's clock.
    pub timestamp: String,
    /// The agent actor URI the receipts were signed under.
    pub actor: String,
    /// Treeship session id (names the package a verifier is handed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
    /// The chain head at minting; this artifact's parent.
    pub chain_head: String,
    /// `mroot_<hex>` over the chain from the session root to `chain_head`.
    pub checkpoint: String,
    /// `sha256:<hex>` of the approval-use record, when the chain spent one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_use: Option<String>,
    /// `B64U(SHA-256(L2 base JWT))`.
    pub mandate_digest: String,
    /// `checkout_hash` / `transaction_id` of the L3 pair.
    pub transaction_id: String,
    /// How many artifacts `checkpoint` covers.
    pub chain_length: u64,
}

impl AttestationStatement {
    pub fn new(
        actor: &str,
        session: Option<String>,
        chain_head: &str,
        checkpoint: &str,
        chain_length: u64,
        approval_use: Option<String>,
        mandate_digest: &str,
        transaction_id: &str,
        timestamp: &str,
    ) -> Self {
        Self {
            type_: ATTESTATION_STATEMENT_TYPE.into(),
            timestamp: timestamp.into(),
            actor: actor.into(),
            session,
            chain_head: chain_head.into(),
            checkpoint: checkpoint.into(),
            approval_use,
            mandate_digest: mandate_digest.into(),
            transaction_id: transaction_id.into(),
            chain_length,
        }
    }
}

/// The claim as it sits in the L3 payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationClaim {
    #[serde(rename = "type")]
    pub type_: String,
    pub value: AttestationValue,
}

/// `value`: self-contained evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationValue {
    /// Content-addressed id of the signed statement (`art_…`).
    pub artifact_id: String,
    /// The ship key id that signed.
    pub key_id: String,
    /// `ed25519:<base64url>`; the same form `treeship trust add` pins.
    pub public_key: String,
    /// The DSSE envelope over the statement.
    pub envelope: Envelope,
}

/// Sign `stmt` as a `vi.l3.attested` action receipt chained onto
/// `stmt.chain_head`, and shape the claim. Returns the claim and the raw
/// sign result (the caller stores the artifact and advances the chain).
pub fn build_attestation_claim(
    stmt: &AttestationStatement,
    signer: &dyn Signer,
) -> Result<(AttestationClaim, SignResult), ViError> {
    let mut action = ActionStatement::new(&stmt.actor, ATTESTATION_ACTION);
    action.timestamp = stmt.timestamp.clone();
    action.parent_id = Some(stmt.chain_head.clone());
    action.meta = Some(serde_json::to_value(stmt).map_err(|e| ViError::Malformed(e.to_string()))?);
    let pt = attestation_payload_type();
    let result = sign(&pt, &action, signer).map_err(|e| ViError::Signature(e.to_string()))?;
    let claim = AttestationClaim {
        type_: ATTESTATION_SCHEME.into(),
        value: AttestationValue {
            artifact_id: result.artifact_id.clone(),
            key_id: signer.key_id().to_string(),
            public_key: format!("ed25519:{}", b64u(&signer.public_key_bytes())),
            envelope: result.envelope.clone(),
        },
    };
    Ok((claim, result))
}

/// A claim that verified: the statement it carries and the key it was
/// signed with. Whether that key is trusted is the caller's decision.
#[derive(Debug, Clone)]
pub struct AttestationVerified {
    pub artifact_id: String,
    pub key_id: String,
    pub public_key: String,
    pub statement: AttestationStatement,
}

/// Verify the claim's envelope against the public key it embeds, and that
/// the embedded artifact id is the one the envelope re-derives to.
pub fn verify_attestation_claim(claim: &Value) -> Result<AttestationVerified, ViError> {
    let parsed: AttestationClaim = serde_json::from_value(claim.clone())
        .map_err(|e| ViError::Malformed(format!("agent_attestation: {e}")))?;
    if parsed.type_ != ATTESTATION_SCHEME {
        return Err(ViError::Malformed(format!(
            "agent_attestation type is '{}', not '{ATTESTATION_SCHEME}'",
            parsed.type_
        )));
    }
    let v = &parsed.value;
    let pk_b64 = v
        .public_key
        .strip_prefix("ed25519:")
        .ok_or_else(|| ViError::Malformed("public_key must be 'ed25519:<base64url>'".into()))?;
    let pk = super::jws::b64u_decode(pk_b64)?;
    let pk: [u8; 32] = pk
        .as_slice()
        .try_into()
        .map_err(|_| ViError::Key("ed25519 public key must be 32 bytes".into()))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk)
        .map_err(|e| ViError::Key(format!("ed25519 public key: {e}")))?;
    if v.envelope.payload_type != attestation_payload_type() {
        return Err(ViError::Malformed(format!(
            "attestation envelope payloadType is '{}'",
            v.envelope.payload_type
        )));
    }
    let res = verify_with_key(&v.envelope, &v.key_id, vk)
        .map_err(|e| ViError::Signature(format!("attestation envelope: {e}")))?;
    if res.artifact_id != v.artifact_id {
        return Err(ViError::Signature(format!(
            "attestation artifact id {} does not match the envelope ({})",
            v.artifact_id, res.artifact_id
        )));
    }
    let payload = super::jws::b64u_decode(&v.envelope.payload)?;
    let action: Value = serde_json::from_slice(&payload)
        .map_err(|e| ViError::Malformed(format!("attestation statement: {e}")))?;
    if action.get("type").and_then(Value::as_str) != Some(TYPE_ACTION) {
        return Err(ViError::Malformed(format!(
            "attestation statement type is {}",
            action.get("type").cloned().unwrap_or(Value::Null)
        )));
    }
    if action.get("action").and_then(Value::as_str) != Some(ATTESTATION_ACTION) {
        return Err(ViError::Malformed(format!(
            "attestation action is {}",
            action.get("action").cloned().unwrap_or(Value::Null)
        )));
    }
    let statement: AttestationStatement =
        serde_json::from_value(action.get("meta").cloned().unwrap_or(Value::Null))
            .map_err(|e| ViError::Malformed(format!("attestation meta: {e}")))?;
    if statement.type_ != ATTESTATION_STATEMENT_TYPE {
        return Err(ViError::Malformed(format!(
            "attestation meta type is '{}'",
            statement.type_
        )));
    }
    if action.get("parentId").and_then(Value::as_str) != Some(statement.chain_head.as_str()) {
        return Err(ViError::Signature(
            "attestation parentId is not the chain head it names".into(),
        ));
    }
    if action.get("actor").and_then(Value::as_str) != Some(statement.actor.as_str()) {
        return Err(ViError::Signature(
            "attestation actor differs between the action and its meta".into(),
        ));
    }
    Ok(AttestationVerified {
        artifact_id: v.artifact_id.clone(),
        key_id: v.key_id.clone(),
        public_key: v.public_key.clone(),
        statement,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::Ed25519Signer;

    fn stmt() -> AttestationStatement {
        AttestationStatement::new(
            "agent://shopping",
            Some("ssn_x".into()),
            "art_head",
            "mroot_00",
            13,
            Some("sha256:aa".into()),
            "MDIG",
            "TXID",
            "2026-09-08T00:00:00Z",
        )
    }

    #[test]
    fn claim_round_trips_and_tamper_fails() {
        let signer = Ed25519Signer::generate("key_test").unwrap();
        let (claim, _) = build_attestation_claim(&stmt(), &signer).unwrap();
        let v = serde_json::to_value(&claim).unwrap();
        let ok = verify_attestation_claim(&v).unwrap();
        assert_eq!(ok.statement.chain_head, "art_head");
        assert_eq!(ok.key_id, "key_test");
        // Flip a byte in the payload: signature fails.
        let mut bad = v.clone();
        let p = bad["value"]["envelope"]["payload"]
            .as_str()
            .unwrap()
            .to_string();
        let mut bytes = super::super::jws::b64u_decode(&p).unwrap();
        let i = bytes.iter().position(|b| *b == b'h').unwrap();
        bytes[i] = b'H';
        bad["value"]["envelope"]["payload"] = Value::String(b64u(&bytes));
        assert!(verify_attestation_claim(&bad).is_err());
        // A different key's claim of the same statement is a different id.
        let other = Ed25519Signer::generate("key_other").unwrap();
        let (claim2, _) = build_attestation_claim(&stmt(), &other).unwrap();
        assert_ne!(claim2.value.public_key, claim.value.public_key);
        let mut swapped = v.clone();
        swapped["value"]["public_key"] = Value::String(claim2.value.public_key.clone());
        assert!(verify_attestation_claim(&swapped).is_err());
    }
}
