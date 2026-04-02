use std::collections::HashMap;
use ed25519_dalek::{VerifyingKey, Verifier as DalekVerifier, Signature as DalekSignature};

use crate::attestation::{
    pae,
    artifact_id_from_pae, digest_from_pae, ArtifactId,
    Ed25519Signer, Signer,
    Envelope,
};

/// The result of a successful verification.
#[derive(Debug)]
pub struct VerifyResult {
    /// Content-addressed ID **re-derived** from the envelope during verification.
    /// If the envelope payload or payloadType was tampered with since signing,
    /// this will differ from any stored artifact ID — a reliable tamper signal.
    pub artifact_id: ArtifactId,

    /// Full SHA-256 digest of the PAE bytes: "sha256:<hex>".
    pub digest: String,

    /// Key IDs whose signatures were successfully verified.
    pub verified_key_ids: Vec<String>,

    /// The payloadType from the envelope.
    pub payload_type: String,
}

/// Error from verification.
#[derive(Debug)]
pub enum VerifyError {
    /// The payload could not be base64-decoded.
    PayloadDecode(String),
    /// A key ID in the envelope has no corresponding trusted public key.
    UnknownKey(String),
    /// A signature was cryptographically invalid.
    InvalidSignature(String),
    /// No valid signature was found from any trusted key (VerifyAny only).
    NoValidSignature,
    /// The signature bytes were malformed (wrong length etc.).
    MalformedSignature(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PayloadDecode(e)      => write!(f, "payload decode: {}", e),
            Self::UnknownKey(id)        => write!(f, "unknown key: {}", id),
            Self::InvalidSignature(id)  => write!(f, "invalid signature for key: {}", id),
            Self::NoValidSignature      => write!(f, "no valid signature from any trusted key"),
            Self::MalformedSignature(e) => write!(f, "malformed signature bytes: {}", e),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Holds trusted public keys and verifies DSSE envelopes against them.
///
/// Separate from `Signer` — signing requires a private key, verification
/// requires only public keys. Verifiers are cheap to clone and pass around.
#[derive(Clone)]
pub struct Verifier {
    /// Map of key_id → VerifyingKey (Ed25519 public key).
    keys: HashMap<String, VerifyingKey>,
}

impl Verifier {
    /// Creates a Verifier with the given trusted key map.
    pub fn new(keys: HashMap<String, VerifyingKey>) -> Self {
        Self { keys }
    }

    /// Convenience: creates a single-key Verifier from an `Ed25519Signer`.
    /// Most useful in tests and local-only workflows.
    pub fn from_signer(signer: &Ed25519Signer) -> Self {
        let mut keys = HashMap::new();
        keys.insert(signer.key_id().to_string(), signer.verifying_key());
        Self { keys }
    }

    /// Adds a trusted public key.
    pub fn add_key(&mut self, key_id: impl Into<String>, pub_key: VerifyingKey) {
        self.keys.insert(key_id.into(), pub_key);
    }

    /// Verifies all signatures in the envelope.
    ///
    /// Returns `Ok(VerifyResult)` only if **every** signature in the envelope
    /// is valid and its key is trusted. Any unknown key or invalid signature
    /// returns `Err`.
    ///
    /// Use this for strict verification where all listed signers must be valid
    /// (e.g., hybrid Ed25519 + ML-DSA in v2 where both are required).
    pub fn verify(&self, envelope: &Envelope) -> Result<VerifyResult, VerifyError> {
        let pae_bytes = self.reconstruct_pae(envelope)?;
        let mut verified = Vec::new();

        for sig in &envelope.signatures {
            let pub_key = self.keys.get(&sig.keyid)
                .ok_or_else(|| VerifyError::UnknownKey(sig.keyid.clone()))?;

            let raw_sig = self.decode_sig(sig)?;
            self.verify_sig(pub_key, &pae_bytes, &raw_sig, &sig.keyid)?;
            verified.push(sig.keyid.clone());
        }

        Ok(self.build_result(pae_bytes, verified, &envelope.payload_type))
    }

    /// Verifies that at least one signature in the envelope is valid from a
    /// trusted key. Signatures from unknown keys are skipped.
    ///
    /// Use this during key rotation when old and new keys may coexist, or
    /// when accepting envelopes from multiple possible signers.
    pub fn verify_any(&self, envelope: &Envelope) -> Result<VerifyResult, VerifyError> {
        let pae_bytes = self.reconstruct_pae(envelope)?;
        let mut verified = Vec::new();

        for sig in &envelope.signatures {
            let pub_key = match self.keys.get(&sig.keyid) {
                Some(k) => k,
                None    => continue, // skip unknown keys
            };
            let raw_sig = match self.decode_sig(sig) {
                Ok(b)  => b,
                Err(_) => continue, // skip malformed sigs
            };
            if self.verify_sig(pub_key, &pae_bytes, &raw_sig, &sig.keyid).is_ok() {
                verified.push(sig.keyid.clone());
            }
        }

        if verified.is_empty() {
            return Err(VerifyError::NoValidSignature);
        }

        Ok(self.build_result(pae_bytes, verified, &envelope.payload_type))
    }

    // --- private helpers ---

    fn reconstruct_pae(&self, envelope: &Envelope) -> Result<Vec<u8>, VerifyError> {
        let payload_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &envelope.payload,
        ).map_err(|e| VerifyError::PayloadDecode(e.to_string()))?;

        Ok(pae(&envelope.payload_type, &payload_bytes))
    }

    fn decode_sig(&self, sig: &crate::attestation::Signature) -> Result<Vec<u8>, VerifyError> {
        base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &sig.sig,
        ).map_err(|e| VerifyError::MalformedSignature(e.to_string()))
    }

    fn verify_sig(
        &self,
        pub_key:  &VerifyingKey,
        pae:      &[u8],
        raw_sig:  &[u8],
        key_id:   &str,
    ) -> Result<(), VerifyError> {
        let sig_bytes: [u8; 64] = raw_sig.try_into()
            .map_err(|_| VerifyError::MalformedSignature(
                format!("signature for {} is {} bytes, expected 64", key_id, raw_sig.len())
            ))?;

        let dalek_sig = DalekSignature::from_bytes(&sig_bytes);

        pub_key.verify(pae, &dalek_sig)
            .map_err(|_| VerifyError::InvalidSignature(key_id.to_string()))
    }

    fn build_result(
        &self,
        pae_bytes:    Vec<u8>,
        verified:     Vec<String>,
        payload_type: &str,
    ) -> VerifyResult {
        VerifyResult {
            artifact_id:     artifact_id_from_pae(&pae_bytes),
            digest:          digest_from_pae(&pae_bytes),
            verified_key_ids: verified,
            payload_type:    payload_type.to_string(),
        }
    }
}

/// Convenience: verify an envelope with a single known public key.
pub fn verify_with_key(
    envelope: &Envelope,
    key_id:   &str,
    pub_key:  VerifyingKey,
) -> Result<VerifyResult, VerifyError> {
    let mut keys = HashMap::new();
    keys.insert(key_id.to_string(), pub_key);
    let v = Verifier::new(keys);
    v.verify_any(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{sign, Ed25519Signer};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    struct TestStmt { actor: String, action: String }

    const PT: &str = "application/vnd.treeship.action.v1+json";

    fn stmt() -> TestStmt {
        TestStmt { actor: "agent://researcher".into(), action: "tool.call".into() }
    }

    fn make_signer() -> Ed25519Signer {
        Ed25519Signer::generate("key_test_01").unwrap()
    }

    // --- round-trip ---

    #[test]
    fn verify_roundtrip() {
        let signer   = make_signer();
        let verifier = Verifier::from_signer(&signer);
        let signed   = sign(PT, &stmt(), &signer).unwrap();
        let result   = verifier.verify(&signed.envelope).unwrap();

        assert_eq!(result.artifact_id, signed.artifact_id);
        assert_eq!(result.digest, signed.digest);
        assert_eq!(result.verified_key_ids, vec!["key_test_01"]);
        assert_eq!(result.payload_type, PT);
    }

    #[test]
    fn verify_any_roundtrip() {
        let signer   = make_signer();
        let verifier = Verifier::from_signer(&signer);
        let signed   = sign(PT, &stmt(), &signer).unwrap();
        verifier.verify_any(&signed.envelope).unwrap();
    }

    // --- tamper detection ---

    #[test]
    fn tampered_payload_fails() {
        let signer   = make_signer();
        let verifier = Verifier::from_signer(&signer);
        let signed   = sign(PT, &stmt(), &signer).unwrap();

        // Replace the payload with different content. The signature was
        // computed over PAE(original_payload) — after tampering the PAE
        // is different and the signature fails.
        let malicious = TestStmt { actor: "agent://attacker".into(), action: "steal".into() };
        let malicious_bytes = serde_json::to_vec(&malicious).unwrap();

        let mut tampered = signed.envelope.clone();
        tampered.payload = URL_SAFE_NO_PAD.encode(malicious_bytes);

        let err = verifier.verify(&tampered).unwrap_err();
        assert!(
            matches!(err, VerifyError::InvalidSignature(_)),
            "Expected InvalidSignature, got: {}", err
        );
    }

    #[test]
    fn tampered_payload_type_fails() {
        let signer   = make_signer();
        let verifier = Verifier::from_signer(&signer);
        let signed   = sign("application/vnd.treeship.action.v1+json", &stmt(), &signer).unwrap();

        // Change the payloadType without re-signing.
        // PAE includes payloadType, so the reconstructed PAE ≠ signed PAE.
        let mut tampered = signed.envelope.clone();
        tampered.payload_type = "application/vnd.treeship.approval.v1+json".into();

        assert!(
            verifier.verify(&tampered).is_err(),
            "verify must fail when payloadType is tampered"
        );
    }

    // --- key rejection ---

    #[test]
    fn wrong_key_fails() {
        let signer      = make_signer();
        // Build a verifier with a different keypair but the same key_id.
        // Simulates an attacker substituting their public key.
        let wrong       = Ed25519Signer::generate("key_test_01").unwrap();
        let verifier    = Verifier::from_signer(&wrong);

        let signed = sign(PT, &stmt(), &signer).unwrap();
        assert!(
            verifier.verify(&signed.envelope).is_err(),
            "verify with wrong public key must fail"
        );
    }

    #[test]
    fn unknown_key_fails() {
        let signer   = make_signer();
        let verifier = Verifier::new(HashMap::new()); // no keys

        let signed = sign(PT, &stmt(), &signer).unwrap();
        assert!(
            verifier.verify(&signed.envelope).is_err(),
            "verify with no trusted keys must fail"
        );
    }

    #[test]
    fn verify_any_skips_unknown_keys() {
        let signer   = make_signer();
        // Verifier only knows about key_test_01
        let verifier = Verifier::from_signer(&signer);

        // Envelope only has key_test_01 — verifier should accept it
        let signed = sign(PT, &stmt(), &signer).unwrap();
        let result = verifier.verify_any(&signed.envelope).unwrap();
        assert_eq!(result.verified_key_ids.len(), 1);
    }

    #[test]
    fn verify_any_all_unknown_fails() {
        let signer   = make_signer();
        let verifier = Verifier::new(HashMap::new());
        let signed   = sign(PT, &stmt(), &signer).unwrap();
        assert!(matches!(
            verifier.verify_any(&signed.envelope).unwrap_err(),
            VerifyError::NoValidSignature
        ));
    }

    // --- ID consistency ---

    #[test]
    fn artifact_id_matches_sign() {
        let signer   = make_signer();
        let verifier = Verifier::from_signer(&signer);
        let signed   = sign(PT, &stmt(), &signer).unwrap();
        let verified = verifier.verify(&signed.envelope).unwrap();

        // The ID is derived from the same PAE bytes during both sign and verify.
        // A mismatch here means the envelope was tampered with between sign and verify.
        assert_eq!(
            signed.artifact_id, verified.artifact_id,
            "ID from sign and verify must match"
        );
    }

    // --- multi-key verifier ---

    #[test]
    fn multi_key_verifier() {
        let s1 = Ed25519Signer::generate("key_1").unwrap();
        let s2 = Ed25519Signer::generate("key_2").unwrap();

        let mut verifier = Verifier::from_signer(&s1);
        verifier.add_key("key_2", s2.verifying_key());

        // Sign with s1 — verifier knows both keys, should accept
        let signed = sign(PT, &stmt(), &s1).unwrap();
        let result = verifier.verify(&signed.envelope).unwrap();
        assert_eq!(result.verified_key_ids, vec!["key_1"]);

        // Sign with s2 — should also work
        let signed2 = sign(PT, &stmt(), &s2).unwrap();
        let result2 = verifier.verify(&signed2.envelope).unwrap();
        assert_eq!(result2.verified_key_ids, vec!["key_2"]);
    }

    // --- serialization ---

    #[test]
    fn json_marshal_unmarshal() {
        let signer   = make_signer();
        let verifier = Verifier::from_signer(&signer);
        let signed   = sign(PT, &stmt(), &signer).unwrap();

        let json     = signed.envelope.to_json().unwrap();
        let restored = Envelope::from_json(&json).unwrap();

        let result = verifier.verify(&restored).unwrap();
        assert_eq!(result.artifact_id, signed.artifact_id);
    }
}
