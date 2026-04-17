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
