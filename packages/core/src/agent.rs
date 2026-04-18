//! Agent Identity Certificate schema.
//!
//! An Agent Identity Certificate is a signed credential that proves who an
//! agent is and what it is authorized to do. Produced once when an agent
//! registers, lives permanently with the agent. The TLS certificate
//! equivalent for AI agents.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature as DalekSignature, Verifier as DalekVerifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Agent identity: who the agent is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIdentity {
    pub agent_name: String,
    pub ship_id: String,
    pub public_key: String,
    pub issuer: String,
    pub issued_at: String,
    pub valid_until: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Agent capabilities: what tools and services the agent is authorized to use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCapabilities {
    /// Authorized MCP tool names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolCapability>,
    /// Authorized API endpoints.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api_endpoints: Vec<String>,
    /// Authorized MCP server names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mcp_servers: Vec<String>,
}

/// A single authorized tool with optional description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCapability {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Agent declaration: scope constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDeclaration {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bounded_actions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalation_required: Vec<String>,
}

/// The complete Agent Certificate -- identity + capabilities + declaration
/// with a signature over the canonical JSON of all three.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCertificate {
    pub r#type: String, // "treeship/agent-certificate/v1"
    /// Schema version. Absent on pre-v0.9.0 certificates (treated as "0").
    /// Set to "1" for v0.9.0+. Informational only in v0.9.0; future versions
    /// may use this to gate verification rule selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,
    pub identity: AgentIdentity,
    pub capabilities: AgentCapabilities,
    pub declaration: AgentDeclaration,
    pub signature: CertificateSignature,
}

/// Signature over the certificate content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateSignature {
    pub algorithm: String,     // "ed25519"
    pub key_id: String,
    pub public_key: String,    // base64url-encoded Ed25519 public key
    pub signature: String,     // base64url-encoded Ed25519 signature
    pub signed_fields: String, // "identity+capabilities+declaration"
}

pub const CERTIFICATE_TYPE: &str = "treeship/agent-certificate/v1";

/// Current certificate schema version. Certificates without this field are
/// treated as schema "0" and verified under legacy rules (pre-v0.9.0 shape).
pub const CERTIFICATE_SCHEMA_VERSION: &str = "1";

/// Resolve a schema_version Option to its effective string, defaulting to
/// "0" when absent. Centralizing this avoids the legacy default leaking out
/// across call sites.
pub fn effective_schema_version(field: Option<&str>) -> &str {
    field.unwrap_or("0")
}

/// Errors verifying an `AgentCertificate` signature.
#[derive(Debug)]
pub enum CertificateVerifyError {
    /// Public key in `signature.public_key` was not valid base64url or wrong length.
    BadPublicKey(String),
    /// Signature bytes were not valid base64url or wrong length.
    BadSignature(String),
    /// Could not reconstruct canonical signed payload.
    PayloadEncode(String),
    /// Signature did not verify against the embedded public key.
    InvalidSignature,
    /// Signature algorithm is not supported (only `ed25519` is recognized).
    UnsupportedAlgorithm(String),
    /// `signed_fields` does not name the expected payload composition.
    UnsupportedSignedFields(String),
}

impl std::fmt::Display for CertificateVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPublicKey(s) => write!(f, "certificate public key: {s}"),
            Self::BadSignature(s) => write!(f, "certificate signature bytes: {s}"),
            Self::PayloadEncode(s) => write!(f, "certificate canonical encoding: {s}"),
            Self::InvalidSignature => write!(f, "certificate signature did not verify"),
            Self::UnsupportedAlgorithm(s) => write!(f, "certificate algorithm '{s}' not supported"),
            Self::UnsupportedSignedFields(s) => {
                write!(f, "certificate signed_fields '{s}' not recognized")
            }
        }
    }
}

impl std::error::Error for CertificateVerifyError {}

/// The signed payload composition used by v0.x agent certificates.
const SIGNED_FIELDS_V1: &str = "identity+capabilities+declaration";

/// Verify the Ed25519 signature on an `AgentCertificate` against the public
/// key embedded in `signature.public_key`. Reconstructs the same canonical
/// JSON the issuer signed and checks the bytes match.
///
/// This does NOT check certificate validity (issued_at / valid_until) or
/// chain to a trusted issuer. Validity is the cross-verifier's job; trust
/// chaining is out of scope for v0.9.0.
pub fn verify_certificate(cert: &AgentCertificate) -> Result<(), CertificateVerifyError> {
    if cert.signature.algorithm != "ed25519" {
        return Err(CertificateVerifyError::UnsupportedAlgorithm(
            cert.signature.algorithm.clone(),
        ));
    }
    if cert.signature.signed_fields != SIGNED_FIELDS_V1 {
        return Err(CertificateVerifyError::UnsupportedSignedFields(
            cert.signature.signed_fields.clone(),
        ));
    }

    let pk_bytes = URL_SAFE_NO_PAD
        .decode(&cert.signature.public_key)
        .map_err(|e| CertificateVerifyError::BadPublicKey(e.to_string()))?;
    let pk_arr: [u8; 32] = pk_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CertificateVerifyError::BadPublicKey(format!("expected 32 bytes, got {}", pk_bytes.len())))?;
    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| CertificateVerifyError::BadPublicKey(e.to_string()))?;

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&cert.signature.signature)
        .map_err(|e| CertificateVerifyError::BadSignature(e.to_string()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| CertificateVerifyError::BadSignature(format!("expected 64 bytes, got {}", sig_bytes.len())))?;
    let signature = DalekSignature::from_bytes(&sig_arr);

    // Reconstruct the canonical signed payload exactly as the issuer did:
    // {identity, capabilities, declaration} serialized with serde_json (which
    // preserves struct field declaration order).
    let payload = serde_json::json!({
        "identity": cert.identity,
        "capabilities": cert.capabilities,
        "declaration": cert.declaration,
    });
    let canonical = serde_json::to_vec(&payload)
        .map_err(|e| CertificateVerifyError::PayloadEncode(e.to_string()))?;

    verifying_key
        .verify(&canonical, &signature)
        .map_err(|_| CertificateVerifyError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_certificate(schema_version: Option<&str>) -> AgentCertificate {
        AgentCertificate {
            r#type: CERTIFICATE_TYPE.into(),
            schema_version: schema_version.map(|s| s.to_string()),
            identity: AgentIdentity {
                agent_name: "agent-007".into(),
                ship_id: "ship_demo".into(),
                public_key: "pk_b64".into(),
                issuer: "ship://ship_demo".into(),
                issued_at: "2026-04-15T00:00:00Z".into(),
                valid_until: "2026-10-15T00:00:00Z".into(),
                model: None,
                description: None,
            },
            capabilities: AgentCapabilities {
                tools: vec![ToolCapability { name: "Bash".into(), description: None }],
                api_endpoints: vec![],
                mcp_servers: vec![],
            },
            declaration: AgentDeclaration {
                bounded_actions: vec!["Bash".into()],
                forbidden: vec![],
                escalation_required: vec![],
            },
            signature: CertificateSignature {
                algorithm: "ed25519".into(),
                key_id: "key_demo".into(),
                public_key: "pk_b64".into(),
                signature: "sig_b64".into(),
                signed_fields: "identity+capabilities+declaration".into(),
            },
        }
    }

    #[test]
    fn legacy_certificate_round_trips_byte_identical() {
        // schema_version=None mimics a pre-v0.9.0 certificate. Re-serializing
        // must skip the field entirely so the original bytes (and therefore
        // any signature over those bytes if a future format binds them) is
        // preserved.
        let cert = sample_certificate(None);
        let bytes = serde_json::to_vec(&cert).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(!s.contains("schema_version"),
            "legacy cert must omit schema_version, got: {s}");

        let parsed: AgentCertificate = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed.schema_version.is_none());
        let reserialized = serde_json::to_vec(&parsed).unwrap();
        assert_eq!(bytes, reserialized);
        assert_eq!(effective_schema_version(parsed.schema_version.as_deref()), "0");
    }

    #[test]
    fn verify_certificate_round_trip() {
        // Mint a cert, sign it the way the CLI does, then call verify.
        use crate::attestation::{Ed25519Signer, Signer};
        let signer = Ed25519Signer::generate("key_demo").unwrap();
        let pk_b64 = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());

        let identity = AgentIdentity {
            agent_name: "agent-007".into(),
            ship_id: "ship_x".into(),
            public_key: pk_b64.clone(),
            issuer: "ship://ship_x".into(),
            issued_at: "2026-04-15T00:00:00Z".into(),
            valid_until: "2027-04-15T00:00:00Z".into(),
            model: None,
            description: None,
        };
        let capabilities = AgentCapabilities {
            tools: vec![ToolCapability { name: "Bash".into(), description: None }],
            api_endpoints: vec![],
            mcp_servers: vec![],
        };
        let declaration = AgentDeclaration {
            bounded_actions: vec!["Bash".into()],
            forbidden: vec![],
            escalation_required: vec![],
        };
        let payload = serde_json::json!({
            "identity": identity, "capabilities": capabilities, "declaration": declaration,
        });
        let canonical = serde_json::to_vec(&payload).unwrap();
        let sig = signer.sign(&canonical).unwrap();

        let cert = AgentCertificate {
            r#type: CERTIFICATE_TYPE.into(),
            schema_version: Some(CERTIFICATE_SCHEMA_VERSION.into()),
            identity,
            capabilities,
            declaration,
            signature: CertificateSignature {
                algorithm: "ed25519".into(),
                key_id: "key_demo".into(),
                public_key: pk_b64,
                signature: URL_SAFE_NO_PAD.encode(sig),
                signed_fields: "identity+capabilities+declaration".into(),
            },
        };

        verify_certificate(&cert).expect("freshly-signed cert must verify");
    }

    #[test]
    fn verify_certificate_detects_tampered_payload() {
        use crate::attestation::{Ed25519Signer, Signer};
        let signer = Ed25519Signer::generate("key_demo").unwrap();
        let pk_b64 = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());

        let identity = AgentIdentity {
            agent_name: "agent-007".into(),
            ship_id: "ship_x".into(),
            public_key: pk_b64.clone(),
            issuer: "ship://ship_x".into(),
            issued_at: "2026-04-15T00:00:00Z".into(),
            valid_until: "2027-04-15T00:00:00Z".into(),
            model: None,
            description: None,
        };
        let capabilities = AgentCapabilities {
            tools: vec![ToolCapability { name: "Bash".into(), description: None }],
            api_endpoints: vec![],
            mcp_servers: vec![],
        };
        let declaration = AgentDeclaration {
            bounded_actions: vec!["Bash".into()],
            forbidden: vec![],
            escalation_required: vec![],
        };
        let payload = serde_json::json!({
            "identity": identity, "capabilities": capabilities, "declaration": declaration,
        });
        let canonical = serde_json::to_vec(&payload).unwrap();
        let sig = signer.sign(&canonical).unwrap();

        // Tamper: expand the tools list AFTER signing. Signature was computed
        // over the smaller list so it should no longer verify.
        let evil_caps = AgentCapabilities {
            tools: vec![
                ToolCapability { name: "Bash".into(), description: None },
                ToolCapability { name: "DropDatabase".into(), description: None },
            ],
            api_endpoints: vec![],
            mcp_servers: vec![],
        };

        let cert = AgentCertificate {
            r#type: CERTIFICATE_TYPE.into(),
            schema_version: Some(CERTIFICATE_SCHEMA_VERSION.into()),
            identity,
            capabilities: evil_caps,
            declaration,
            signature: CertificateSignature {
                algorithm: "ed25519".into(),
                key_id: "key_demo".into(),
                public_key: pk_b64,
                signature: URL_SAFE_NO_PAD.encode(sig),
                signed_fields: "identity+capabilities+declaration".into(),
            },
        };

        let err = verify_certificate(&cert).unwrap_err();
        assert!(matches!(err, CertificateVerifyError::InvalidSignature),
            "expected InvalidSignature, got: {err}");
    }

    #[test]
    fn verify_certificate_rejects_unsupported_algorithm() {
        let mut cert = sample_certificate(Some(CERTIFICATE_SCHEMA_VERSION));
        cert.signature.algorithm = "rsa-pss-sha256".into();
        let err = verify_certificate(&cert).unwrap_err();
        assert!(matches!(err, CertificateVerifyError::UnsupportedAlgorithm(_)));
    }

    #[test]
    fn current_certificate_carries_schema_version_one() {
        let cert = sample_certificate(Some(CERTIFICATE_SCHEMA_VERSION));
        let bytes = serde_json::to_vec(&cert).unwrap();
        let s = std::str::from_utf8(&bytes).unwrap();
        assert!(s.contains(r#""schema_version":"1""#),
            "current cert must include schema_version=1, got: {s}");
        let parsed: AgentCertificate = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(effective_schema_version(parsed.schema_version.as_deref()), "1");
    }
}
