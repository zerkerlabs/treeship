use sha2::{Digest as Sha2Digest, Sha256};

/// A content-addressed artifact ID.
///
/// Format: `"art_" + hex(sha256(pae_bytes)[..16])`
///
/// The ID is derived from the PAE bytes that were signed, so:
/// - Same content always produces the same ID
/// - Different content always produces a different ID
/// - Collisions require breaking SHA-256
/// - A lookup by ID is an implicit integrity check
///
/// This is categorically different from ULID-style IDs which have no
/// relationship to content and allow a compromised store to serve
/// different content at the same ID.
pub type ArtifactId = String;

/// Derives a content-addressed artifact ID from PAE bytes.
///
/// This is called after signing — the PAE bytes are fixed once
/// payloadType and payload are determined.
///
/// # Examples
///
/// ```
/// use treeship_core::attestation::{pae, artifact_id_from_pae};
///
/// let pae_bytes = pae("application/vnd.treeship.action.v1+json", b"{}");
/// let id = artifact_id_from_pae(&pae_bytes);
/// assert!(id.starts_with("art_"));
/// assert_eq!(id.len(), 36); // "art_" + 32 hex chars
/// ```
pub fn artifact_id_from_pae(pae: &[u8]) -> ArtifactId {
    let digest = Sha256::digest(pae);
    // Take first 16 bytes (128 bits) — collision-resistant at any
    // conceivable scale of artifact production.
    format!("art_{}", hex::encode(&digest[..16]))
}

/// Returns the full SHA-256 digest of the PAE bytes as "sha256:<hex>".
///
/// Stored on each artifact for reference and used in MMR leaf hashes.
pub fn digest_from_pae(pae: &[u8]) -> String {
    let digest = Sha256::digest(pae);
    format!("sha256:{}", hex::encode(&digest))
}

/// Validates an artifact ID format. Returns the ID unchanged if valid,
/// or an error describing why it is invalid.
pub fn parse_artifact_id(id: &str) -> Result<ArtifactId, String> {
    if !id.starts_with("art_") {
        return Err(format!(
            "invalid artifact id {:?}: must start with 'art_'",
            id
        ));
    }
    let hex_part = &id[4..];
    if hex_part.len() != 32 {
        return Err(format!(
            "invalid artifact id {:?}: hex part must be 32 chars, got {}",
            id,
            hex_part.len()
        ));
    }
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid artifact id {:?}: hex part contains non-hex characters",
            id
        ));
    }
    Ok(id.to_string())
}

// hex encoding helper — avoids adding the hex crate as a full dep
// by inlining what we need. We use it from sha2's output (fixed-size arrays).
mod hex {
    const CHARS: &[u8] = b"0123456789abcdef";

    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for &b in bytes {
            s.push(CHARS[(b >> 4) as usize] as char);
            s.push(CHARS[(b & 0xf) as usize] as char);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::pae;

    fn test_pae() -> Vec<u8> {
        pae(
            "application/vnd.treeship.action.v1+json",
            br#"{"type":"treeship/action/v1","actor":"agent://test"}"#,
        )
    }

    #[test]
    fn id_starts_with_prefix() {
        let id = artifact_id_from_pae(&test_pae());
        assert!(id.starts_with("art_"), "ID must start with 'art_': {}", id);
    }

    #[test]
    fn id_correct_length() {
        let id = artifact_id_from_pae(&test_pae());
        assert_eq!(id.len(), 36, "ID must be 36 chars ('art_' + 32 hex): {}", id);
    }

    #[test]
    fn id_deterministic() {
        // Same PAE bytes always produce the same ID.
        let p = test_pae();
        assert_eq!(artifact_id_from_pae(&p), artifact_id_from_pae(&p));
    }

    #[test]
    fn id_different_for_different_content() {
        let a = pae("application/vnd.treeship.action.v1+json", b"{\"actor\":\"a\"}");
        let b = pae("application/vnd.treeship.action.v1+json", b"{\"actor\":\"b\"}");
        assert_ne!(
            artifact_id_from_pae(&a),
            artifact_id_from_pae(&b),
            "Different content must produce different IDs"
        );
    }

    #[test]
    fn id_different_for_different_type() {
        let payload = b"{}";
        let a = pae("application/vnd.treeship.action.v1+json", payload);
        let b = pae("application/vnd.treeship.approval.v1+json", payload);
        assert_ne!(
            artifact_id_from_pae(&a),
            artifact_id_from_pae(&b),
            "Different payloadType must produce different IDs"
        );
    }

    #[test]
    fn digest_format() {
        let d = digest_from_pae(&test_pae());
        assert!(d.starts_with("sha256:"), "digest must start with sha256:");
        assert_eq!(d.len(), 7 + 64, "sha256: + 64 hex chars");
    }

    #[test]
    fn parse_valid() {
        let id = artifact_id_from_pae(&test_pae());
        assert!(parse_artifact_id(&id).is_ok(), "valid ID should parse: {}", id);
    }

    #[test]
    fn parse_invalid_cases() {
        let bad = [
            "",
            "notanid",
            "art_",
            "bnd_abc123",
            "art_tooshort",
            "art_gggggggggggggggggggggggggggggggg", // non-hex
        ];
        for id in bad {
            assert!(
                parse_artifact_id(id).is_err(),
                "should reject {:?}",
                id
            );
        }
    }
}
