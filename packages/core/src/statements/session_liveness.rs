//! `session-liveness/v1` — durable, portable evidence that a join was
//! live-challenged, and how long the challenge window actually was.
//!
//! # The gap this closes
//!
//! v0.24 added a liveness challenge at countersign time: the host mints a
//! nonce, the joining agent signs it, and the host refuses to countersign
//! unless the response verifies. That check works. It also left **no trace**.
//! `check_join_challenge` returned the response's `signed_at` and the call
//! site discarded it, so a third-party verifier reading the finalized
//! participant envelope could not tell a live-challenged join from an
//! unchallenged one. A security control that runs and leaves no evidence is
//! unverifiable by anyone who was not the host at the time.
//!
//! # Why a separate statement instead of a field
//!
//! `SessionParticipantStatement::canonical_for_signing` is covered by *two*
//! signatures — the joining agent's and the host's countersign. Adding a
//! field changes those bytes and invalidates both, which is why the original
//! module deferred portability to "a schema-v2 question".
//!
//! This sidesteps that. The host signs a separate statement referencing the
//! participant artifact by id. Additive, backward compatible, and the
//! participant envelope stays byte-identical.
//!
//! # Why the interval, not a boolean
//!
//! "Fresh at join" is a checkmark that hides a duration. A nonce answered
//! four seconds after it was issued and one answered forty minutes later both
//! pass, and they are not the same evidence: the second leaves a window in
//! which the agent's sandbox could have gone away, its key rotated, or its
//! process been replaced between proving liveness and acting.
//!
//! So this records both endpoints and lets the reader do the subtraction,
//! rather than pre-deciding a threshold on their behalf. Same reason
//! [`crate::verify::anchoring`] reports a span instead of `anchored: true`.
//!
//! # What this does NOT prove
//!
//! Both timestamps come from the parties' own clocks — `challenge_issued_at`
//! from the host, `response_signed_at` from the joining agent — so a
//! *cooperating* pair can report any interval they like. This is evidence
//! against a stale or replayed join, not against a host and agent colluding.
//! Bounding that needs an external witness (`docs/specs/time-anchoring.md`).
//!
//! It also says nothing about what happened *after* the join. A short
//! challenge window followed by an action six hours later is a short window
//! and a long gap; this records the first and the receipt's own timeline
//! records the second.

use serde::{Deserialize, Serialize};

use crate::attestation::{Signer, SignerError};

use super::{nonce_digest, parse_rfc3339_to_unix};

pub const TYPE_SESSION_LIVENESS: &str = "treeship/session-liveness/v1";

/// Host-signed evidence that a specific join answered a specific challenge,
/// with both endpoints of the window it took.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLivenessStatement {
    #[serde(rename = "type")]
    pub type_: String,

    /// `session_id` the join belongs to. Must equal the participant
    /// statement's `session_ref`; a verifier checks this rather than
    /// trusting the link.
    pub session_ref: String,

    /// Artifact id of the participant envelope this attests. The link that
    /// makes the evidence portable: given a participant receipt, a verifier
    /// can find the liveness statement, and given this, they can find what it
    /// describes.
    pub participant_ref: String,

    /// Joining agent's Ed25519 public key, base64url-no-pad. Duplicated from
    /// the participant statement deliberately: it is bound into these signed
    /// bytes, so this attestation cannot be re-pointed at a different join by
    /// editing the reference alone.
    pub joining_agent: String,

    /// `sha256:<hex>` of the nonce, never the nonce itself. The nonce is
    /// single-use liveness material; publishing it in a durable artifact
    /// would hand a replayer the exact string the host was expecting.
    /// A digest still lets the host's own records be reconciled against this.
    pub nonce_digest: String,

    /// RFC 3339. When the host minted the nonce.
    pub challenge_issued_at: String,

    /// RFC 3339. The `signed_at` the joining agent bound into its challenge
    /// response — the agent's own claim about when it answered.
    pub response_signed_at: String,
}

impl SessionLivenessStatement {
    pub fn new(
        session_ref: impl Into<String>,
        participant_ref: impl Into<String>,
        joining_agent: impl Into<String>,
        nonce: &str,
        challenge_issued_at: impl Into<String>,
        response_signed_at: impl Into<String>,
    ) -> Self {
        Self {
            type_: TYPE_SESSION_LIVENESS.into(),
            session_ref: session_ref.into(),
            participant_ref: participant_ref.into(),
            joining_agent: joining_agent.into(),
            nonce_digest: nonce_digest(nonce),
            challenge_issued_at: challenge_issued_at.into(),
            response_signed_at: response_signed_at.into(),
        }
    }

    /// The challenge window in seconds: issue to answer.
    ///
    /// `None` when either timestamp will not parse, or when the answer
    /// predates the challenge. A negative interval is not a small window —
    /// it means at least one clock is wrong or one timestamp was fabricated,
    /// and reporting it as a number would launder that into a reassuring
    /// value. The caller must handle `None` as "cannot be evaluated".
    pub fn interval_seconds(&self) -> Option<i64> {
        let issued = parse_rfc3339_to_unix(&self.challenge_issued_at)? as i64;
        let answered = parse_rfc3339_to_unix(&self.response_signed_at)? as i64;
        let delta = answered - issued;
        (delta >= 0).then_some(delta)
    }

    /// Canonical signing bytes. Same pipe-delimited shape as the other
    /// session statements, every field positional so none can be omitted.
    pub fn canonical_for_signing(&self) -> String {
        format!(
            "v1|session-liveness|{}|{}|{}|{}|{}|{}",
            self.session_ref,
            self.participant_ref,
            self.joining_agent,
            self.nonce_digest,
            self.challenge_issued_at,
            self.response_signed_at,
        )
    }

    /// Signed by the **host**, not the joining agent. The host is the party
    /// that issued the challenge and observed the answer; the agent cannot
    /// attest to when it was asked.
    pub fn sign_as_host(&self, host_signer: &dyn Signer) -> Result<String, SignerError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let sig = host_signer.sign(self.canonical_for_signing().as_bytes())?;
        Ok(URL_SAFE_NO_PAD.encode(sig))
    }
}

/// How a reader should treat a join's liveness evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LivenessVerdict {
    /// A liveness statement exists and its window is computable.
    Attested { interval_seconds: i64 },
    /// A statement exists but its timestamps do not yield a usable interval.
    /// Distinct from `Absent`: something was recorded and it does not make
    /// sense, which is a stronger signal than nothing being recorded.
    Malformed { reason: String },
    /// No liveness statement for this join.
    ///
    /// Not the same as "the join was not challenged": every join before this
    /// statement type existed looks like this, and so does one whose host ran
    /// the check and did not record it. It means the evidence is unavailable,
    /// which is what a verifier should say instead of guessing.
    Absent,
}

impl LivenessVerdict {
    pub fn from_statement(stmt: Option<&SessionLivenessStatement>) -> Self {
        match stmt {
            None => Self::Absent,
            Some(s) => match s.interval_seconds() {
                Some(interval_seconds) => Self::Attested { interval_seconds },
                None => Self::Malformed {
                    reason: format!(
                        "challenge_issued_at {:?} and response_signed_at {:?} do not yield a \
                         non-negative interval",
                        s.challenge_issued_at, s.response_signed_at
                    ),
                },
            },
        }
    }

    /// One line for humans, phrased so `Absent` cannot be read as a pass.
    pub fn summary(&self) -> String {
        match self {
            Self::Attested { interval_seconds } => {
                format!("live-challenged, answered in {interval_seconds}s")
            }
            Self::Malformed { reason } => format!("liveness evidence unusable: {reason}"),
            Self::Absent => "no liveness evidence — cannot tell a live-challenged join from an \
                 unchallenged one"
                .to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::Ed25519Signer;

    fn stmt(issued: &str, answered: &str) -> SessionLivenessStatement {
        SessionLivenessStatement::new(
            "ssn_abc",
            "art_0123456789abcdef0123456789abcdef",
            "Zm9vYmFy",
            "n_a_real_nonce_value_with_entropy",
            issued,
            answered,
        )
    }

    #[test]
    fn interval_is_the_window_from_challenge_to_answer() {
        let s = stmt("2026-08-13T10:00:00Z", "2026-08-13T10:00:04Z");
        assert_eq!(s.interval_seconds(), Some(4));
    }

    /// The case the boolean hid. Both of these pass a fresh-at-join check;
    /// they are not the same evidence, and the interval is what says so.
    #[test]
    fn a_slow_answer_is_reported_not_flattened() {
        let quick = stmt("2026-08-13T10:00:00Z", "2026-08-13T10:00:04Z");
        let slow = stmt("2026-08-13T10:00:00Z", "2026-08-13T10:40:00Z");

        assert_eq!(quick.interval_seconds(), Some(4));
        assert_eq!(slow.interval_seconds(), Some(2400));
        assert_ne!(
            LivenessVerdict::from_statement(Some(&quick)),
            LivenessVerdict::from_statement(Some(&slow)),
            "a 4s and a 40m challenge window must not produce the same verdict"
        );
    }

    /// An answer before its challenge is a broken clock or a fabricated
    /// timestamp. Returning a negative number would let a caller comparing
    /// `interval < 30` treat it as the freshest possible join.
    #[test]
    fn an_answer_before_its_challenge_is_not_a_small_interval() {
        let s = stmt("2026-08-13T10:00:00Z", "2026-08-13T09:00:00Z");
        assert_eq!(s.interval_seconds(), None);
        assert!(matches!(
            LivenessVerdict::from_statement(Some(&s)),
            LivenessVerdict::Malformed { .. }
        ));
    }

    #[test]
    fn absent_evidence_does_not_read_as_a_pass() {
        let v = LivenessVerdict::from_statement(None);
        assert_eq!(v, LivenessVerdict::Absent);
        let s = v.summary();
        assert!(s.contains("no liveness evidence"), "{s}");
        assert!(
            !s.contains("live-challenged,"),
            "absent must not be phrased like an attestation: {s}"
        );
    }

    /// The nonce is single-use liveness material. Publishing it in a durable
    /// artifact would hand a replayer the string the host was expecting.
    #[test]
    fn the_nonce_itself_never_enters_the_statement() {
        let nonce = "n_super_secret_nonce_material_xyz";
        let s = SessionLivenessStatement::new(
            "ssn_abc",
            "art_x",
            "pk",
            nonce,
            "2026-08-13T10:00:00Z",
            "2026-08-13T10:00:01Z",
        );
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains(nonce), "raw nonce leaked into the statement");
        assert!(s.nonce_digest.starts_with("sha256:"));
        assert!(!s.canonical_for_signing().contains(nonce));
    }

    /// Every field must be bound, or the attestation could be re-pointed at a
    /// different join by editing an unsigned reference.
    #[test]
    fn every_field_is_bound_into_the_signed_bytes() {
        let base = stmt("2026-08-13T10:00:00Z", "2026-08-13T10:00:04Z");
        let canon = base.canonical_for_signing();

        let mut other_session = base.clone();
        other_session.session_ref = "ssn_other".into();
        let mut other_participant = base.clone();
        other_participant.participant_ref = "art_ffffffffffffffffffffffffffffffff".into();
        let mut other_agent = base.clone();
        other_agent.joining_agent = "b3RoZXI".into();

        for variant in [other_session, other_participant, other_agent] {
            assert_ne!(
                canon,
                variant.canonical_for_signing(),
                "a changed field left the signed bytes identical"
            );
        }
    }

    #[test]
    fn host_signature_verifies_over_the_canonical_bytes() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let host = Ed25519Signer::from_bytes("host", &[7u8; 32]).unwrap();
        let s = stmt("2026-08-13T10:00:00Z", "2026-08-13T10:00:04Z");
        let sig_b64 = s.sign_as_host(&host).unwrap();

        let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&sig_b64)
            .unwrap()
            .try_into()
            .unwrap();
        let vk_bytes: [u8; 32] = host.public_key_bytes().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&vk_bytes).unwrap();

        assert!(vk
            .verify(
                s.canonical_for_signing().as_bytes(),
                &Signature::from_bytes(&sig_bytes)
            )
            .is_ok());

        // And must not verify over a tampered statement.
        let mut tampered = s.clone();
        tampered.response_signed_at = "2026-08-13T10:00:03Z".into();
        assert!(vk
            .verify(
                tampered.canonical_for_signing().as_bytes(),
                &Signature::from_bytes(&sig_bytes)
            )
            .is_err());
    }
}
