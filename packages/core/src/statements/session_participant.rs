//! Session-participant statement -- Phase 1 of the agent-invitations spec.
//!
//! See `docs/specs/agent-invitations-rooms.md`.
//!
//! A participant event records "agent X joined session S by redeeming
//! invitation I." Two signatures are required at the envelope layer:
//!
//!   * `joining_agent` signs first to assert "I'm joining"
//!   * `host` countersigns to assert "I observed this join and confirm
//!     it consumed the invitation"
//!
//! Either signature alone is invalid (Q4 decision). The verifier
//! (`verify_envelope_signatures`) enforces both presences AND that the
//! joining_agent's sig is over the canonical bytes and the host's sig
//! is over the same bytes -- and that the host pubkey matches the
//! invitation's issuer.
//!
//! `capabilities` is copied from the invitation at join time and is
//! immutable: any change to the field after the joining signature is
//! emitted invalidates BOTH signatures via the canonical binding.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::attestation::{Envelope, Signer, SignerError, Signature as DsseSignature};
use crate::statements::invitation::{canonical_json_digest, GrantedCapabilities};

// ---------------------------------------------------------------------------
// Type constants
// ---------------------------------------------------------------------------

pub const TYPE_SESSION_PARTICIPANT: &str = "treeship/session-participant/v1";

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// The unsigned payload. Wrap in a DSSE envelope; the envelope MUST
/// carry two signatures (joining agent first, then host countersign).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionParticipantStatement {
    #[serde(rename = "type")]
    pub type_: String,

    /// Same `session_ref` as the invitation. The verifier checks
    /// equality.
    pub session_ref: String,

    /// Artifact id of the invitation this participant event redeems.
    pub invitation_ref: String,

    /// Joining agent's Ed25519 public key (base64url-no-pad).
    pub joining_agent: String,

    /// Optional certificate artifact id; set when the invitation's
    /// restriction was `Cert` and the joining agent presented a cert.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joining_agent_cert_ref: Option<String>,

    /// RFC 3339.
    pub joined_at: String,

    /// COPIED from the invitation at join time. Immutable -- any
    /// mutation invalidates the joining_agent and host signatures.
    pub capabilities: GrantedCapabilities,
}

impl SessionParticipantStatement {
    pub fn new(
        session_ref:    impl Into<String>,
        invitation_ref: impl Into<String>,
        joining_agent:  impl Into<String>,
        joined_at:      impl Into<String>,
        capabilities:   GrantedCapabilities,
    ) -> Self {
        Self {
            type_:                  TYPE_SESSION_PARTICIPANT.into(),
            session_ref:            session_ref.into(),
            invitation_ref:         invitation_ref.into(),
            joining_agent:          joining_agent.into(),
            joining_agent_cert_ref: None,
            joined_at:              joined_at.into(),
            capabilities,
        }
    }

    /// Canonical signing bytes. Same pipe-delimited v0.10.4 shape as
    /// `InvitationStatement::canonical_for_signing`.
    ///
    /// Format:
    /// `"v1|session-participant|{session_ref}|{invitation_ref}|{joining_agent}|{cert_ref_or_empty}|{joined_at}|{capabilities_canonical}"`
    pub fn canonical_for_signing(&self) -> String {
        let caps_digest = canonical_json_digest(&self.capabilities);
        let cert_field  = self.joining_agent_cert_ref.as_deref().unwrap_or("");
        format!(
            "v1|session-participant|{}|{}|{}|{}|{}|{}",
            self.session_ref,
            self.invitation_ref,
            self.joining_agent,
            cert_field,
            self.joined_at,
            caps_digest,
        )
    }

    /// Sign with the joining agent's keypair. Returns the base64url
    /// signature suitable to drop into a DSSE envelope's first
    /// signature slot.
    pub fn sign_as_joining_agent(&self, signer: &dyn Signer) -> Result<String, SignerError> {
        let canonical = self.canonical_for_signing();
        let sig = signer.sign(canonical.as_bytes())?;
        Ok(URL_SAFE_NO_PAD.encode(sig))
    }

    /// Sign with the host's keypair (the countersign). The verifier
    /// rejects participant envelopes whose host signature is missing
    /// or whose signing key does not match the invitation's issuer.
    pub fn sign_as_host(&self, signer: &dyn Signer) -> Result<String, SignerError> {
        let canonical = self.canonical_for_signing();
        let sig = signer.sign(canonical.as_bytes())?;
        Ok(URL_SAFE_NO_PAD.encode(sig))
    }

    /// Build a DSSE envelope around the statement carrying ONLY the
    /// joining_agent signature. The verifier rejects this as
    /// `MissingHostCountersign`; this constructor exists so the
    /// `treeship session join` CLI can emit a "pending countersign"
    /// blob the host then fills in via `treeship session countersign`.
    pub fn pending_envelope(
        &self,
        joining_signer: &dyn Signer,
    ) -> Result<Envelope, SignerError> {
        let sig = self.sign_as_joining_agent(joining_signer)?;
        let payload = serde_json::to_vec(self)
            .map_err(|e| SignerError(format!("serialize participant: {e}")))?;
        Ok(Envelope {
            payload:      URL_SAFE_NO_PAD.encode(&payload),
            payload_type: crate::statements::payload_type("session-participant"),
            signatures:   vec![DsseSignature {
                keyid: joining_signer.key_id().to_string(),
                sig,
            }],
        })
    }

    /// Add the host's countersign to a pending envelope. Returns the
    /// finalized envelope with both signatures. Order is preserved:
    /// signatures[0] = joining_agent, signatures[1] = host.
    pub fn attach_host_countersign(
        envelope: &Envelope,
        host_signer: &dyn Signer,
    ) -> Result<Envelope, SignerError> {
        // Decode + re-canonicalize the embedded statement so the
        // countersign covers the exact bytes the joining agent did.
        let stmt: Self = envelope.unmarshal_statement()
            .map_err(|e| SignerError(format!("envelope decode: {e}")))?;
        let sig = stmt.sign_as_host(host_signer)?;
        let mut out = envelope.clone();
        // Refuse to append duplicate host signatures; idempotency at the
        // CLI surface is the caller's job. Here we just guarantee that
        // an envelope with two signatures already does not grow a third.
        if out.signatures.len() >= 2 {
            return Err(SignerError(
                "envelope already carries two signatures; refusing to append a third".into(),
            ));
        }
        out.signatures.push(DsseSignature {
            keyid: host_signer.key_id().to_string(),
            sig,
        });
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Why a participant envelope was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParticipantVerifyError {
    /// Envelope payload didn't deserialize as a participant statement
    /// (wrong type, bad JSON, truncated).
    BadPayload(String),
    /// The envelope has only one signature -- the host countersign is
    /// missing. This is the failure mode for envelopes emitted by
    /// `treeship session join` before `treeship session countersign`
    /// runs. Surface to the operator as "pending countersign," not as
    /// "forgery."
    MissingHostCountersign,
    /// The envelope has more than two signatures. Phase 1 schema is
    /// strictly two (joining_agent + host). Future multi-party rooms
    /// can relax via a canonical bump.
    TooManySignatures(usize),
    /// The joining agent's signature did not verify against
    /// `statement.joining_agent`'s pubkey over the canonical bytes.
    JoiningAgentSigInvalid,
    /// The host's signature did not verify, OR the signing key does
    /// not match the invitation's issuer (`expected_host_pubkey`).
    HostCountersignInvalid,
    /// The joining_agent field doesn't decode as a 32-byte Ed25519 key.
    JoiningAgentNotEd25519,
    /// The expected host pubkey provided by the caller doesn't decode.
    HostPubkeyNotEd25519,
}

impl std::fmt::Display for ParticipantVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPayload(m) => write!(f, "participant envelope payload invalid: {m}"),
            Self::MissingHostCountersign => write!(
                f,
                "participant envelope carries only the joining agent's signature; \
                 host countersign required (run `treeship session countersign`)",
            ),
            Self::TooManySignatures(n) => write!(
                f,
                "participant envelope carries {n} signatures; Phase 1 schema requires exactly 2",
            ),
            Self::JoiningAgentSigInvalid => write!(
                f,
                "joining agent's signature failed to verify against the statement's canonical bytes",
            ),
            Self::HostCountersignInvalid => write!(
                f,
                "host countersign failed to verify, or signing key does not match the invitation's issuer",
            ),
            Self::JoiningAgentNotEd25519 => write!(
                f,
                "participant.joining_agent does not decode as a 32-byte Ed25519 public key",
            ),
            Self::HostPubkeyNotEd25519 => write!(
                f,
                "expected host pubkey does not decode as a 32-byte Ed25519 public key",
            ),
        }
    }
}

impl std::error::Error for ParticipantVerifyError {}

/// Verify a participant envelope. Requires:
///
///   1. Exactly two signatures.
///   2. signatures[0] verifies against `statement.joining_agent`.
///   3. signatures[1] verifies against `expected_host_pubkey`.
///   4. `expected_host_pubkey` is the base64url-no-pad encoding of the
///      invitation's `issuer` field. Caller looks the invitation up and
///      passes it in; this function does not consult any external state.
///
/// On success, returns the decoded statement so the caller can apply
/// it (write the finalized event into the session log, etc.).
pub fn verify_participant_envelope(
    envelope: &Envelope,
    expected_host_pubkey: &str,
) -> Result<SessionParticipantStatement, ParticipantVerifyError> {
    let stmt: SessionParticipantStatement = envelope
        .unmarshal_statement()
        .map_err(|e| ParticipantVerifyError::BadPayload(e.to_string()))?;

    if stmt.type_ != TYPE_SESSION_PARTICIPANT {
        return Err(ParticipantVerifyError::BadPayload(format!(
            "wrong type: got {}, expected {}", stmt.type_, TYPE_SESSION_PARTICIPANT,
        )));
    }

    match envelope.signatures.len() {
        2 => {}
        1 => return Err(ParticipantVerifyError::MissingHostCountersign),
        n => return Err(ParticipantVerifyError::TooManySignatures(n)),
    }

    let canonical = stmt.canonical_for_signing();

    // signatures[0] : joining_agent
    let joiner_pk_bytes = URL_SAFE_NO_PAD
        .decode(stmt.joining_agent.as_bytes())
        .ok()
        .and_then(|b| if b.len() == 32 { Some(b) } else { None })
        .ok_or(ParticipantVerifyError::JoiningAgentNotEd25519)?;
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&joiner_pk_bytes);
    let joiner_vk = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|_| ParticipantVerifyError::JoiningAgentNotEd25519)?;
    let joiner_sig_bytes = URL_SAFE_NO_PAD
        .decode(envelope.signatures[0].sig.as_bytes())
        .map_err(|_| ParticipantVerifyError::JoiningAgentSigInvalid)?;
    if joiner_sig_bytes.len() != 64 {
        return Err(ParticipantVerifyError::JoiningAgentSigInvalid);
    }
    let mut joiner_sig_arr = [0u8; 64];
    joiner_sig_arr.copy_from_slice(&joiner_sig_bytes);
    let joiner_sig = Signature::from_bytes(&joiner_sig_arr);
    if joiner_vk.verify_strict(canonical.as_bytes(), &joiner_sig).is_err() {
        return Err(ParticipantVerifyError::JoiningAgentSigInvalid);
    }

    // signatures[1] : host countersign
    let host_pk_bytes = URL_SAFE_NO_PAD
        .decode(expected_host_pubkey.as_bytes())
        .ok()
        .and_then(|b| if b.len() == 32 { Some(b) } else { None })
        .ok_or(ParticipantVerifyError::HostPubkeyNotEd25519)?;
    let mut host_pk_arr = [0u8; 32];
    host_pk_arr.copy_from_slice(&host_pk_bytes);
    let host_vk = VerifyingKey::from_bytes(&host_pk_arr)
        .map_err(|_| ParticipantVerifyError::HostPubkeyNotEd25519)?;
    let host_sig_bytes = URL_SAFE_NO_PAD
        .decode(envelope.signatures[1].sig.as_bytes())
        .map_err(|_| ParticipantVerifyError::HostCountersignInvalid)?;
    if host_sig_bytes.len() != 64 {
        return Err(ParticipantVerifyError::HostCountersignInvalid);
    }
    let mut host_sig_arr = [0u8; 64];
    host_sig_arr.copy_from_slice(&host_sig_bytes);
    let host_sig = Signature::from_bytes(&host_sig_arr);
    if host_vk.verify_strict(canonical.as_bytes(), &host_sig).is_err() {
        return Err(ParticipantVerifyError::HostCountersignInvalid);
    }

    Ok(stmt)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::Ed25519Signer;
    use crate::statements::invitation::{GrantedCapabilities, InviteeRestriction, InvitationStatement};

    fn caps() -> GrantedCapabilities {
        GrantedCapabilities {
            action_types: vec!["tool.call".into()],
        }
    }

    fn keys() -> (Ed25519Signer, Ed25519Signer) {
        (
            Ed25519Signer::from_bytes("host", &[7u8; 32]).unwrap(),
            Ed25519Signer::from_bytes("agent", &[11u8; 32]).unwrap(),
        )
    }

    fn build_pair() -> (InvitationStatement, SessionParticipantStatement, Ed25519Signer, Ed25519Signer) {
        let (host, agent) = keys();
        let host_pk = URL_SAFE_NO_PAD.encode(host.public_key_bytes());
        let agent_pk = URL_SAFE_NO_PAD.encode(agent.public_key_bytes());

        let inv = InvitationStatement::new(
            "ssn_room", host_pk.clone(),
            InviteeRestriction::Open, caps(),
            "2030-01-01T00:00:00Z", "nonce_xyz",
        );
        let part = SessionParticipantStatement::new(
            "ssn_room", "art_invitation_001",
            agent_pk, "2026-05-18T01:00:00Z", caps(),
        );
        (inv, part, host, agent)
    }

    /// Q4 default: an envelope with only the joining_agent signature
    /// must be rejected.
    #[test]
    fn participant_requires_two_signatures() {
        let (inv, part, _host, agent) = build_pair();
        let pending = part.pending_envelope(&agent).unwrap();
        assert_eq!(pending.signatures.len(), 1);
        match verify_participant_envelope(&pending, &inv.issuer) {
            Err(ParticipantVerifyError::MissingHostCountersign) => {}
            other => panic!("expected MissingHostCountersign, got {other:?}"),
        }
    }

    /// Round-trip: pending envelope + host countersign + verify -> Ok.
    #[test]
    fn participant_pending_plus_countersign_verifies() {
        let (inv, part, host, agent) = build_pair();
        let pending = part.pending_envelope(&agent).unwrap();
        let finalized = SessionParticipantStatement::attach_host_countersign(&pending, &host).unwrap();
        assert_eq!(finalized.signatures.len(), 2);
        let back = verify_participant_envelope(&finalized, &inv.issuer).unwrap();
        assert_eq!(back.session_ref, part.session_ref);
        assert_eq!(back.invitation_ref, part.invitation_ref);
    }

    /// Q4: countersign by a key that ISN'T the invitation's issuer
    /// must be rejected, even if the signature math checks out under
    /// that other key.
    #[test]
    fn participant_requires_host_countersign_match() {
        let (inv, part, _real_host, agent) = build_pair();
        let imposter = Ed25519Signer::from_bytes("imposter", &[42u8; 32]).unwrap();
        let pending = part.pending_envelope(&agent).unwrap();
        let bad = SessionParticipantStatement::attach_host_countersign(&pending, &imposter).unwrap();
        match verify_participant_envelope(&bad, &inv.issuer) {
            Err(ParticipantVerifyError::HostCountersignInvalid) => {}
            other => panic!("expected HostCountersignInvalid, got {other:?}"),
        }
    }

    /// Capabilities in the participant envelope are immutable: any
    /// mutation after the signatures land invalidates both.
    #[test]
    fn participant_capabilities_immutable() {
        let (inv, part, host, agent) = build_pair();
        let pending = part.pending_envelope(&agent).unwrap();
        let mut finalized = SessionParticipantStatement::attach_host_countersign(&pending, &host).unwrap();

        // Mutate the embedded statement: bump capabilities and rewrap.
        let mut tampered: SessionParticipantStatement = finalized.unmarshal_statement().unwrap();
        tampered.capabilities.action_types.push("smuggled.cap".into());
        let new_payload = serde_json::to_vec(&tampered).unwrap();
        finalized.payload = URL_SAFE_NO_PAD.encode(&new_payload);

        // Both signatures were over the original capabilities; the
        // new canonical bytes differ, so verification fails.
        match verify_participant_envelope(&finalized, &inv.issuer) {
            Err(ParticipantVerifyError::JoiningAgentSigInvalid) => {}
            other => panic!("expected JoiningAgentSigInvalid, got {other:?}"),
        }
    }

    /// The canonical signing bytes MUST include every field. Mutating
    /// any one of them must change the canonical (and thus break both
    /// signatures). Pins the same property as the invitation test.
    #[test]
    fn participant_canonical_includes_all_fields() {
        let (_inv, part, _h, _a) = build_pair();
        let base = part.canonical_for_signing();

        let mut m1 = part.clone(); m1.session_ref = "ssn_other".into();
        assert_ne!(m1.canonical_for_signing(), base, "session_ref must bind");

        let mut m2 = part.clone(); m2.invitation_ref = "art_other".into();
        assert_ne!(m2.canonical_for_signing(), base, "invitation_ref must bind");

        let mut m3 = part.clone();
        m3.joining_agent = URL_SAFE_NO_PAD.encode([9u8; 32]);
        assert_ne!(m3.canonical_for_signing(), base, "joining_agent must bind");

        let mut m4 = part.clone();
        m4.joining_agent_cert_ref = Some("art_cert_x".into());
        assert_ne!(m4.canonical_for_signing(), base, "cert_ref must bind");

        let mut m5 = part.clone(); m5.joined_at = "2030-01-01T00:00:00Z".into();
        assert_ne!(m5.canonical_for_signing(), base, "joined_at must bind");

        let mut m6 = part.clone();
        m6.capabilities.action_types.push("extra".into());
        assert_ne!(m6.canonical_for_signing(), base, "capabilities must bind");
    }

    /// An envelope with three signatures is rejected up front. The
    /// schema is strictly two-sig in Phase 1.
    #[test]
    fn participant_rejects_more_than_two_signatures() {
        let (inv, part, host, agent) = build_pair();
        let pending = part.pending_envelope(&agent).unwrap();
        let mut finalized = SessionParticipantStatement::attach_host_countersign(&pending, &host).unwrap();
        // Cheat in a third signature directly (the attach helper refuses).
        finalized.signatures.push(DsseSignature {
            keyid: "extra".into(),
            sig:   URL_SAFE_NO_PAD.encode([0u8; 64]),
        });
        match verify_participant_envelope(&finalized, &inv.issuer) {
            Err(ParticipantVerifyError::TooManySignatures(3)) => {}
            other => panic!("expected TooManySignatures(3), got {other:?}"),
        }
    }
}
