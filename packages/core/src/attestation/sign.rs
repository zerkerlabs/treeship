use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Serialize;

use crate::attestation::{
    pae,
    artifact_id_from_pae, digest_from_pae, ArtifactId,
    Signer,
    Envelope, Signature,
};

/// The result of a successful `sign` call.
#[derive(Debug)]
pub struct SignResult {
    /// The sealed DSSE envelope — ready to store or transmit.
    pub envelope: Envelope,

    /// The content-addressed artifact ID derived from the PAE bytes.
    /// Stored alongside the envelope. Recomputed during verification —
    /// if the content was tampered with, the recomputed ID will differ.
    pub artifact_id: ArtifactId,

    /// The full SHA-256 digest of the PAE bytes: "sha256:<hex>".
    pub digest: String,
}

/// Signs a statement and returns a sealed DSSE envelope.
///
/// # Steps
///
/// 1. Serialize `statement` to compact JSON bytes.
/// 2. Construct `PAE(payload_type, json_bytes)`.
/// 3. Sign the PAE bytes with `signer` — **never** the raw JSON.
/// 4. base64url-encode the payload and signature.
/// 5. Derive the content-addressed artifact ID from the PAE bytes.
///
/// # Errors
///
/// Returns an error if serialization or signing fails.
///
/// # Examples
///
/// ```
/// use serde::Serialize;
/// use treeship_core::attestation::{sign, Ed25519Signer};
///
/// #[derive(Serialize)]
/// struct Action { actor: String, action: String }
///
/// let signer = Ed25519Signer::generate("key_test").unwrap();
/// let stmt   = Action { actor: "agent://test".into(), action: "tool.call".into() };
/// let result = sign("application/vnd.treeship.action.v1+json", &stmt, &signer).unwrap();
///
/// assert!(result.artifact_id.starts_with("art_"));
/// assert!(result.digest.starts_with("sha256:"));
/// ```
pub fn sign<T: Serialize>(
    payload_type: &str,
    statement:    &T,
    signer:       &dyn Signer,
) -> Result<SignResult, SignError> {
    if payload_type.is_empty() {
        return Err(SignError("payload_type must not be empty".into()));
    }

    // 1. Serialize to compact JSON — no indentation, deterministic field order
    //    within a struct (Rust's serde_json serializes fields in declaration order).
    let payload_bytes = serde_json::to_vec(statement)
        .map_err(|e| SignError(format!("serialize statement: {}", e)))?;

    // 2. Build the PAE byte string. This is what gets signed.
    let pae_bytes = pae(payload_type, &payload_bytes);

    // 3. Sign the PAE bytes.
    let raw_sig = signer
        .sign(&pae_bytes)
        .map_err(|e| SignError(format!("sign: {}", e)))?;

    // 4. Build the DSSE envelope.
    let envelope = Envelope {
        payload:      URL_SAFE_NO_PAD.encode(&payload_bytes),
        payload_type: payload_type.to_string(),
        signatures: vec![Signature {
            keyid: signer.key_id().to_string(),
            sig:   URL_SAFE_NO_PAD.encode(&raw_sig),
        }],
    };

    // 5. Derive ID and digest from the PAE bytes — same bytes that were signed.
    let artifact_id = artifact_id_from_pae(&pae_bytes);
    let digest      = digest_from_pae(&pae_bytes);

    Ok(SignResult { envelope, artifact_id, digest })
}

/// Error from the sign operation.
#[derive(Debug)]
pub struct SignError(pub String);

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "attestation sign: {}", self.0)
    }
}

impl std::error::Error for SignError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{Ed25519Signer, Verifier};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestStmt {
        #[serde(rename = "type")]
        type_:  String,
        actor:  String,
        action: String,
    }

    fn make_signer() -> Ed25519Signer {
        Ed25519Signer::generate("key_test_01").unwrap()
    }

    const TEST_PT: &str = "application/vnd.treeship.action.v1+json";

    fn make_stmt() -> TestStmt {
        TestStmt {
            type_:  "treeship/action/v1".into(),
            actor:  "agent://researcher".into(),
            action: "tool.call".into(),
        }
    }

    #[test]
    fn sign_produces_envelope() {
        let signer = make_signer();
        let result = sign(TEST_PT, &make_stmt(), &signer).unwrap();
        assert!(!result.envelope.payload.is_empty());
        assert_eq!(result.envelope.payload_type, TEST_PT);
        assert_eq!(result.envelope.signatures.len(), 1);
        assert_eq!(result.envelope.signatures[0].keyid, "key_test_01");
    }

    #[test]
    fn artifact_id_format() {
        let signer = make_signer();
        let r      = sign(TEST_PT, &make_stmt(), &signer).unwrap();
        assert!(r.artifact_id.starts_with("art_"), "must start with art_: {}", r.artifact_id);
        assert_eq!(r.artifact_id.len(), 36, "art_ + 32 hex: {}", r.artifact_id);
    }

    #[test]
    fn digest_format() {
        let signer = make_signer();
        let r      = sign(TEST_PT, &make_stmt(), &signer).unwrap();
        assert!(r.digest.starts_with("sha256:"), "must start with sha256:");
        assert_eq!(r.digest.len(), 71, "sha256: + 64 hex: {}", r.digest);
    }

    #[test]
    fn empty_payload_type_errors() {
        let signer = make_signer();
        assert!(sign("", &make_stmt(), &signer).is_err());
    }

    #[test]
    fn id_matches_verify() {
        // The ID derived during sign must equal the ID re-derived during verify.
        let signer   = make_signer();
        let verifier = Verifier::from_signer(&signer);
        let signed   = sign(TEST_PT, &make_stmt(), &signer).unwrap();
        let verified = verifier.verify(&signed.envelope).unwrap();
        assert_eq!(signed.artifact_id, verified.artifact_id);
    }

    #[test]
    fn digest_matches_verify() {
        let signer   = make_signer();
        let verifier = Verifier::from_signer(&signer);
        let signed   = sign(TEST_PT, &make_stmt(), &signer).unwrap();
        let verified = verifier.verify(&signed.envelope).unwrap();
        assert_eq!(signed.digest, verified.digest);
    }

    #[test]
    fn payload_roundtrip() {
        let signer = make_signer();
        let original = make_stmt();
        let r      = sign(TEST_PT, &original, &signer).unwrap();
        let decoded: TestStmt = r.envelope.unmarshal_statement().unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn id_deterministic() {
        // Two calls with identical content must produce the same ID.
        let signer = make_signer();
        let r1     = sign(TEST_PT, &make_stmt(), &signer).unwrap();
        let r2     = sign(TEST_PT, &make_stmt(), &signer).unwrap();
        assert_eq!(r1.artifact_id, r2.artifact_id);
    }

    #[test]
    fn id_differs_by_content() {
        let signer = make_signer();
        let s1     = TestStmt { type_: "treeship/action/v1".into(), actor: "a".into(), action: "x".into() };
        let s2     = TestStmt { type_: "treeship/action/v1".into(), actor: "b".into(), action: "x".into() };
        let r1     = sign(TEST_PT, &s1, &signer).unwrap();
        let r2     = sign(TEST_PT, &s2, &signer).unwrap();
        assert_ne!(r1.artifact_id, r2.artifact_id);
    }

    #[test]
    fn id_differs_by_payload_type() {
        let signer = make_signer();
        let r1 = sign("application/vnd.treeship.action.v1+json",   &make_stmt(), &signer).unwrap();
        let r2 = sign("application/vnd.treeship.approval.v1+json",  &make_stmt(), &signer).unwrap();
        assert_ne!(r1.artifact_id, r2.artifact_id);
    }

    #[test]
    fn json_serialization_roundtrip() {
        let signer   = make_signer();
        let verifier = Verifier::from_signer(&signer);
        let signed   = sign(TEST_PT, &make_stmt(), &signer).unwrap();

        let json     = signed.envelope.to_json().unwrap();
        let restored = Envelope::from_json(&json).unwrap();

        // The restored envelope must still verify correctly.
        let result = verifier.verify(&restored).unwrap();
        assert_eq!(result.artifact_id, signed.artifact_id);
    }
}
