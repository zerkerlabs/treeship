//! Session-join challenge canonical: proves the JOINING AGENT controls its
//! key right now, at the moment the host is about to countersign a pending
//! participant event -- not just that it held the key whenever `session
//! join` produced the pending envelope.
//!
//! Why this exists: `join()` and `countersign()` can run on different
//! machines/sandboxes, with the pending participant envelope handed to the
//! host out of band (pasted, like the invitation blob). That hand-off has
//! no time bound. Without this, a host who countersigns hours later has no
//! way to tell a live join from a stale-but-validly-signed envelope whose
//! signer's sandbox is long gone, key rotated, or agent compromised.
//!
//! Same shape as `presentation::challenge_canonical` / `check_challenge`:
//! every externally-supplied field is digest-folded so no field can inject
//! separators and shift the others, and `signed_at` is bound so the
//! reported freshness is bearer-signed, not bearer-editable. The host picks
//! the nonce immediately before finalizing (any string; freshness is the
//! host's responsibility, same trust model `present --challenge` already
//! uses), so a pre-staged response cannot be replayed across join attempts.
//!
//! Deliberately NOT part of `SessionParticipantStatement::canonical_for_signing`:
//! this is an ephemeral, host-side liveness gate at countersign time, not a
//! durable claim baked into the two-sig envelope. Making it portable (so a
//! third-party verifier can later confirm a join was live-challenged) is a
//! schema-v2 question -- it would touch the canonical bytes both signatures
//! already cover, which is out of scope for an additive, backward-compatible
//! change.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// The canonical bytes a join-challenge response signs.
pub fn join_challenge_canonical(
    session_ref: &str,
    participant_id: &str,
    joining_agent: &str,
    nonce: &str,
    signed_at: &str,
) -> Vec<u8> {
    let d = |s: &str| hex::encode(Sha256::digest(s.as_bytes()));
    format!(
        "v1|room-join-challenge|{}|{}|{}|{}|{signed_at}",
        d(session_ref),
        d(participant_id),
        d(joining_agent),
        d(nonce),
    )
    .into_bytes()
}

/// Verify a join-challenge response against the nonce the HOST issued and
/// the joining agent's pubkey established by the pending participant
/// statement itself (`stmt.joining_agent`). Returns the bearer-signed
/// `signed_at` on success; a specific, honest reason on failure.
pub fn check_join_challenge(
    response: &serde_json::Value,
    session_ref: &str,
    participant_id: &str,
    joining_agent_pubkey_b64: &str,
    expected_nonce: &str,
    joining_agent_vk: &VerifyingKey,
) -> Result<String, String> {
    let nonce = response
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or("challenge response carries no nonce")?;
    if nonce != expected_nonce {
        return Err(
            "challenge response nonce does not match the one the host issued -- this answers a DIFFERENT challenge (replay?)"
                .into(),
        );
    }
    let signed_at = response
        .get("signed_at")
        .and_then(|v| v.as_str())
        .ok_or("challenge response carries no signed_at")?;
    let sig_b64 = response
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or("challenge response carries no signature")?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "challenge response signature is not valid base64url".to_string())?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "challenge response signature is not 64 bytes".to_string())?;
    let canonical = join_challenge_canonical(
        session_ref,
        participant_id,
        joining_agent_pubkey_b64,
        expected_nonce,
        signed_at,
    );
    joining_agent_vk
        .verify_strict(&canonical, &Signature::from_bytes(&sig_arr))
        .map_err(|_| {
            "challenge response signature INVALID for the joining agent's key".to_string()
        })?;
    Ok(signed_at.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{Ed25519Signer, Signer};

    fn signer() -> Ed25519Signer {
        Ed25519Signer::from_bytes("agent", &[9u8; 32]).unwrap()
    }

    fn vk_of(s: &Ed25519Signer) -> VerifyingKey {
        let bytes: [u8; 32] = s.public_key_bytes().try_into().unwrap();
        VerifyingKey::from_bytes(&bytes).unwrap()
    }

    fn signed_response(
        signer: &Ed25519Signer,
        session_ref: &str,
        participant_id: &str,
        joining_agent: &str,
        nonce: &str,
        signed_at: &str,
    ) -> serde_json::Value {
        let canonical =
            join_challenge_canonical(session_ref, participant_id, joining_agent, nonce, signed_at);
        let sig = signer.sign(&canonical).unwrap();
        serde_json::json!({
            "nonce": nonce,
            "signed_at": signed_at,
            "signature": URL_SAFE_NO_PAD.encode(sig),
        })
    }

    #[test]
    fn canonical_is_deterministic_and_binds_every_field() {
        let base = join_challenge_canonical(
            "ssn_1",
            "art_p1",
            "agentpk",
            "nonce1",
            "2026-08-06T00:00:00Z",
        );
        assert_eq!(
            base,
            join_challenge_canonical(
                "ssn_1",
                "art_p1",
                "agentpk",
                "nonce1",
                "2026-08-06T00:00:00Z"
            ),
        );
        assert_ne!(
            base,
            join_challenge_canonical(
                "ssn_2",
                "art_p1",
                "agentpk",
                "nonce1",
                "2026-08-06T00:00:00Z"
            ),
            "session_ref must bind"
        );
        assert_ne!(
            base,
            join_challenge_canonical(
                "ssn_1",
                "art_p2",
                "agentpk",
                "nonce1",
                "2026-08-06T00:00:00Z"
            ),
            "participant_id must bind"
        );
        assert_ne!(
            base,
            join_challenge_canonical(
                "ssn_1",
                "art_p1",
                "otherpk",
                "nonce1",
                "2026-08-06T00:00:00Z"
            ),
            "joining_agent must bind"
        );
        assert_ne!(
            base,
            join_challenge_canonical(
                "ssn_1",
                "art_p1",
                "agentpk",
                "nonce2",
                "2026-08-06T00:00:00Z"
            ),
            "nonce must bind"
        );
        assert_ne!(
            base,
            join_challenge_canonical(
                "ssn_1",
                "art_p1",
                "agentpk",
                "nonce1",
                "2026-08-06T01:00:00Z"
            ),
            "signed_at must bind"
        );
    }

    #[test]
    fn canonical_resists_separator_injection() {
        // Pipe-containing fields must not collide with a differently-split
        // canonical -- every variable field is digest-folded.
        let a = join_challenge_canonical("ssn|1", "art|p1", "pk", "n", "2026-08-06T00:00:00Z");
        let b = join_challenge_canonical("ssn", "1|art|p1", "pk", "n", "2026-08-06T00:00:00Z");
        assert_ne!(a, b);
    }

    #[test]
    fn valid_response_verifies() {
        let s = signer();
        let vk = vk_of(&s);
        let resp = signed_response(
            &s,
            "ssn_1",
            "art_p1",
            "agentpk",
            "n_abc",
            "2026-08-06T00:00:00Z",
        );
        let signed_at =
            check_join_challenge(&resp, "ssn_1", "art_p1", "agentpk", "n_abc", &vk).unwrap();
        assert_eq!(signed_at, "2026-08-06T00:00:00Z");
    }

    #[test]
    fn wrong_nonce_is_rejected() {
        let s = signer();
        let vk = vk_of(&s);
        let resp = signed_response(
            &s,
            "ssn_1",
            "art_p1",
            "agentpk",
            "n_abc",
            "2026-08-06T00:00:00Z",
        );
        // Host expects a DIFFERENT nonce than the one actually signed.
        let err =
            check_join_challenge(&resp, "ssn_1", "art_p1", "agentpk", "n_other", &vk).unwrap_err();
        assert!(err.contains("does not match"), "got: {err}");
    }

    #[test]
    fn wrong_signer_is_rejected() {
        let s = signer();
        let other = Ed25519Signer::from_bytes("imposter", &[42u8; 32]).unwrap();
        let vk = vk_of(&other);
        let resp = signed_response(
            &s,
            "ssn_1",
            "art_p1",
            "agentpk",
            "n_abc",
            "2026-08-06T00:00:00Z",
        );
        let err =
            check_join_challenge(&resp, "ssn_1", "art_p1", "agentpk", "n_abc", &vk).unwrap_err();
        assert!(err.contains("INVALID"), "got: {err}");
    }

    #[test]
    fn replayed_response_for_a_different_participant_is_rejected() {
        let s = signer();
        let vk = vk_of(&s);
        let resp = signed_response(
            &s,
            "ssn_1",
            "art_p1",
            "agentpk",
            "n_abc",
            "2026-08-06T00:00:00Z",
        );
        // Same nonce, same signer, but a DIFFERENT participant_id -- the
        // signature was over art_p1's canonical bytes, not art_p2's.
        let err =
            check_join_challenge(&resp, "ssn_1", "art_p2", "agentpk", "n_abc", &vk).unwrap_err();
        assert!(err.contains("INVALID"), "got: {err}");
    }
}
