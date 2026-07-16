//! Presentation verification primitives: the challenge-response canonical and
//! its check, shared by the CLI (`present` / `verify-presentation`), the WASM
//! verifier, and the SDKs so all agree by construction.
//!
//! Lifted verbatim from packages/cli/src/commands/present.rs. Pure, no I/O.
//! `challenge_canonical` is byte-critical: a single-byte change to its domain
//! separation would silently break every previously signed challenge.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::merkle::{Checkpoint, InclusionProof, MerkleTree};
use crate::statements::parse_rfc3339_to_unix;
use crate::trust::TrustRootStore;

/// The canonical bytes a challenge response signs (the handshake).
///
/// Domain-separated and pipe-delimited: every variable-length,
/// externally-supplied field is folded into a sha256 digest so no field can
/// inject separators and shift the others (the verifier's nonce is arbitrary
/// text). Binding all four fields means a challenge signature cannot be
/// replayed across protocols (domain tag), across agents or cards (their
/// digests), or across challenges (the nonce digest); `signed_at` is bound so
/// the reported freshness is bearer-signed, not bearer-editable.
pub fn challenge_canonical(agent: &str, card_id: &str, nonce: &str, signed_at: &str) -> Vec<u8> {
    let d = |s: &str| hex::encode(Sha256::digest(s.as_bytes()));
    format!(
        "v1|presentation-challenge|{}|{}|{}|{signed_at}",
        d(agent),
        d(card_id),
        d(nonce)
    )
    .into_bytes()
}

/// Verify a presentation's challenge block against the nonce THIS verifier
/// issued and the subject key the card verification established. Returns the
/// bearer-signed `signed_at` on success; a specific, honest reason on failure.
/// Pure — unit-tested against real keys.
pub fn check_challenge(
    challenge: &serde_json::Value,
    agent: &str,
    card_id: &str,
    expected_nonce: &str,
    card_keyid: &str,
    subject: &VerifyingKey,
) -> Result<String, String> {
    let nonce = challenge
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or("challenge block carries no nonce")?;
    if nonce != expected_nonce {
        return Err(
            "challenge nonce does not match the one you issued — this response answers a DIFFERENT challenge (replay?)"
                .into(),
        );
    }
    let key_id = challenge
        .get("key_id")
        .and_then(|v| v.as_str())
        .ok_or("challenge block carries no key_id")?;
    if key_id != card_keyid {
        return Err(format!(
            "challenge signed by {key_id}, but the card is bound to {card_keyid}"
        ));
    }
    let signed_at = challenge
        .get("signed_at")
        .and_then(|v| v.as_str())
        .ok_or("challenge block carries no signed_at")?;
    let sig_b64 = challenge
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or("challenge block carries no signature")?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "challenge signature is not valid base64url")?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "challenge signature is not 64 bytes")?;
    let canonical = challenge_canonical(agent, card_id, expected_nonce, signed_at);
    subject
        .verify_strict(&canonical, &Signature::from_bytes(&sig_arr))
        .map_err(|_| "challenge signature INVALID for the card's key".to_string())?;
    Ok(signed_at.to_string())
}

/// Why a presentation's staple did or didn't verify. Core stays free of
/// CLI-specific text; the caller formats a human message from this.
#[derive(Debug, PartialEq, Eq)]
pub enum StapleStatus {
    /// No staple included in the presentation.
    NoStaple,
    /// The checkpoint or the inclusion proof did not parse.
    Unparseable,
    /// Checkpoint signer is not a pinned `hub_checkpoint` root, or the
    /// checkpoint signature is invalid.
    SignerNotTrusted,
    /// Checkpoint verified, but this card's inclusion proof is invalid.
    InclusionInvalid,
    /// Fully verified: checkpoint signature + card inclusion.
    Verified,
}

/// The outcome of verifying a presentation's staple (a checkpoint plus this
/// card's Merkle inclusion proof).
pub struct StapleVerdict {
    pub verified: bool,
    /// The checkpoint index, when a checkpoint was present and parsed.
    pub checkpoint_index: Option<u64>,
    /// The checkpoint signer's public key — surfaced so a caller can suggest
    /// pinning it when the status is `SignerNotTrusted`.
    pub checkpoint_public_key: Option<String>,
    /// Age of the checkpoint at `now_unix`, in seconds.
    pub age_secs: Option<u64>,
    pub status: StapleStatus,
}

/// Verify a presentation's staple against pinned trust roots at `now_unix`.
/// Pure and time-injected: the caller supplies the current time (used only to
/// report the checkpoint's age; verification itself does not depend on it).
pub fn verify_staple(
    pres: &serde_json::Value,
    card_id: &str,
    trust: &TrustRootStore,
    now_unix: u64,
) -> StapleVerdict {
    let Some(staple) = pres.get("staple").filter(|v| !v.is_null()) else {
        return StapleVerdict {
            verified: false,
            checkpoint_index: None,
            checkpoint_public_key: None,
            age_secs: None,
            status: StapleStatus::NoStaple,
        };
    };
    let (Ok(checkpoint), Ok(proof)) = (
        serde_json::from_value::<Checkpoint>(staple.get("checkpoint").cloned().unwrap_or_default()),
        serde_json::from_value::<InclusionProof>(
            staple.get("inclusion_proof").cloned().unwrap_or_default(),
        ),
    ) else {
        return StapleVerdict {
            verified: false,
            checkpoint_index: None,
            checkpoint_public_key: None,
            age_secs: None,
            status: StapleStatus::Unparseable,
        };
    };

    let age = parse_rfc3339_to_unix(&checkpoint.signed_at).map(|t| now_unix.saturating_sub(t));
    let index = Some(checkpoint.index);
    let public_key = Some(checkpoint.public_key.clone());

    if !checkpoint.verify(trust) {
        return StapleVerdict {
            verified: false,
            checkpoint_index: index,
            checkpoint_public_key: public_key,
            age_secs: age,
            status: StapleStatus::SignerNotTrusted,
        };
    }
    let root_hex = checkpoint
        .root
        .strip_prefix("sha256:")
        .unwrap_or(&checkpoint.root);
    if !MerkleTree::verify_proof(checkpoint.merkle_version, root_hex, card_id, &proof) {
        return StapleVerdict {
            verified: false,
            checkpoint_index: index,
            checkpoint_public_key: public_key,
            age_secs: age,
            status: StapleStatus::InclusionInvalid,
        };
    }
    StapleVerdict {
        verified: true,
        checkpoint_index: index,
        checkpoint_public_key: public_key,
        age_secs: age,
        status: StapleStatus::Verified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_canonical_resists_separator_injection() {
        // A nonce containing pipes and field-lookalikes must not collide
        // with a differently-split canonical — every variable field is
        // digest-folded.
        let a = challenge_canonical("agent://a", "art_1", "n|art_2|x", "2026-07-06T12:00:00Z");
        let b = challenge_canonical("agent://a", "art_1|n", "art_2|x", "2026-07-06T12:00:00Z");
        assert_ne!(a, b);
        // And it is deterministic.
        assert_eq!(
            challenge_canonical("agent://a", "art_1", "n", "2026-07-06T12:00:00Z"),
            challenge_canonical("agent://a", "art_1", "n", "2026-07-06T12:00:00Z"),
        );
    }

    fn signed_challenge_block(
        signer: &crate::attestation::Ed25519Signer,
        agent: &str,
        card_id: &str,
        nonce: &str,
    ) -> serde_json::Value {
        use crate::attestation::Signer;
        let signed_at = "2026-07-06T12:00:00Z";
        let sig = signer
            .sign(&challenge_canonical(agent, card_id, nonce, signed_at))
            .unwrap();
        serde_json::json!({
            "nonce": nonce,
            "key_id": signer.key_id(),
            "signed_at": signed_at,
            "signature": URL_SAFE_NO_PAD.encode(sig),
        })
    }

    fn vk_of(signer: &crate::attestation::Ed25519Signer) -> VerifyingKey {
        use crate::attestation::Signer;
        VerifyingKey::from_bytes(&signer.public_key_bytes().try_into().unwrap()).unwrap()
    }

    #[test]
    fn challenge_verifies_and_rejects_all_substitutions() {
        use crate::attestation::Ed25519Signer;
        let agent_key = Ed25519Signer::generate("key_agent").unwrap();
        let other_key = Ed25519Signer::generate("key_other").unwrap();
        let vk = vk_of(&agent_key);

        // Happy path.
        let block = signed_challenge_block(&agent_key, "agent://a", "art_card", "nonce-1");
        assert!(
            check_challenge(&block, "agent://a", "art_card", "nonce-1", "key_agent", &vk).is_ok()
        );

        // Wrong nonce: a captured response must not answer a new challenge.
        assert!(
            check_challenge(&block, "agent://a", "art_card", "nonce-2", "key_agent", &vk)
                .unwrap_err()
                .contains("DIFFERENT challenge")
        );

        // Signed by a different key than the card's.
        let forged = signed_challenge_block(&other_key, "agent://a", "art_card", "nonce-1");
        assert!(
            check_challenge(
                &forged,
                "agent://a",
                "art_card",
                "nonce-1",
                "key_agent",
                &vk
            )
            .is_err(),
            "response signed by a non-card key must reject"
        );

        // Replayed for a DIFFERENT card of the same agent: canonical binds card_id.
        assert!(
            check_challenge(
                &block,
                "agent://a",
                "art_other_card",
                "nonce-1",
                "key_agent",
                &vk
            )
            .unwrap_err()
            .contains("INVALID"),
            "challenge for one card must not vouch for another"
        );

        // Replayed for a DIFFERENT agent: canonical binds the agent URI.
        assert!(
            check_challenge(&block, "agent://b", "art_card", "nonce-1", "key_agent", &vk)
                .unwrap_err()
                .contains("INVALID")
        );

        // Tampered signed_at: freshness is bearer-signed, not bearer-editable.
        let mut aged = block.clone();
        aged["signed_at"] = serde_json::json!("2020-01-01T00:00:00Z");
        assert!(
            check_challenge(&aged, "agent://a", "art_card", "nonce-1", "key_agent", &vk)
                .unwrap_err()
                .contains("INVALID")
        );
    }
}
