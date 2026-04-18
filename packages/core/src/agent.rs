//! Agent Identity Certificate schema.
//!
//! An Agent Identity Certificate is a signed credential that proves who an
//! agent is and what it is authorized to do. Produced once when an agent
//! registers, lives permanently with the agent. The TLS certificate
//! equivalent for AI agents.

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
