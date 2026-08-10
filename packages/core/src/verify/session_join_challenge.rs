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

/// Minimum nonce length, in characters.
///
/// A challenge nonce is a replay guard: its whole job is to be unguessable by
/// anyone who did not just receive it. `n_8f2a` -- the value used in our own
/// help text -- is 6 characters and enumerable in microseconds. An attacker
/// who can guess the nonce can have the joining agent's key sign it in
/// advance, and the "liveness" proof then demonstrates nothing beyond
/// possession of a document, which is exactly what the challenge exists to
/// improve on.
///
/// 32 hex characters is 128 bits, matching the invitation nonce.
pub const MIN_NONCE_LEN: usize = 32;

/// Reject a nonce too weak to serve as a replay guard.
///
/// Called at BOTH ends -- minting and verifying -- because a host that mints
/// well while accepting anything still accepts a nonce an attacker chose.
///
/// This checks shape, not provenance. It cannot tell a `OsRng` nonce from a
/// counter formatted to look like one, and it cannot detect reuse (see the
/// note on `check_join_challenge`). It rules out the failure that actually
/// happens: a human typing something short because the flag asked for a value
/// and nothing said what kind.
pub fn validate_nonce(nonce: &str) -> Result<(), String> {
    if nonce.len() < MIN_NONCE_LEN {
        return Err(format!(
            "challenge nonce is {} characters; at least {MIN_NONCE_LEN} are required.\n  \
             A short nonce can be guessed and pre-signed, which makes the liveness \
             proof prove nothing.\n  Mint one with: treeship session mint-challenge",
            nonce.len()
        ));
    }
    // A long string of one repeated character is long and still guessable.
    let distinct: std::collections::HashSet<char> = nonce.chars().collect();
    if distinct.len() < 8 {
        return Err(format!(
            "challenge nonce uses only {} distinct characters; it is long but \
             predictable.\n  Mint one with: treeship session mint-challenge",
            distinct.len()
        ));
    }
    Ok(())
}

/// Mint a 128-bit challenge nonce.
///
/// `OsRng`, not `thread_rng`: this is a security value, and the codebase's own
/// rule is that ids used for collision-avoidance may use `thread_rng` while
/// anything acting as a key, nonce, or token must not.
pub fn mint_nonce() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

#[cfg(test)]
mod nonce_tests {
    use super::*;

    #[test]
    fn minted_nonces_are_128_bit_hex_and_unique() {
        let a = mint_nonce();
        assert_eq!(a.len(), 32, "expected 32 hex chars (128 bits)");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(validate_nonce(&a).is_ok());
        // 1000 draws with no collision is not proof of entropy, but a
        // counter or a constant would fail it immediately.
        let set: std::collections::HashSet<String> = (0..1000).map(|_| mint_nonce()).collect();
        assert_eq!(set.len(), 1000, "minted nonces collided");
    }

    /// The exact value from our own `--help` examples. If the docs suggest a
    /// nonce the validator rejects, one of the two is wrong -- and it is the
    /// docs.
    #[test]
    fn the_nonce_from_our_help_text_is_rejected() {
        assert!(validate_nonce("n_8f2a").is_err());
    }

    #[test]
    fn long_but_predictable_is_rejected() {
        assert!(validate_nonce(&"a".repeat(64)).is_err(), "repeated char");
        assert!(validate_nonce(&"abab".repeat(16)).is_err(), "tiny alphabet");
    }

    #[test]
    fn a_real_nonce_passes() {
        assert!(validate_nonce("9f2c4a1b8e5d7061f3a2c9b4e8d17520").is_ok());
    }
}
