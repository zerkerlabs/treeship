//! Agent Identity Certificate: treeship agent register
//!
//! Produces a .agent package containing identity.json, capabilities.json,
//! declaration.json, and certificate.html.

use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use treeship_core::agent::*;

use crate::{ctx, printer::Printer};

/// Register an agent and produce a .agent package.
pub fn register(
    name: &str,
    tools: Vec<String>,
    model: Option<String>,
    valid_days: u32,
    description: Option<String>,
    forbidden: Vec<String>,
    escalation: Vec<String>,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let signer = ctx.keys.default_signer()?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let issued_at = treeship_core::statements::unix_to_rfc3339(now_secs);
    let valid_until = treeship_core::statements::unix_to_rfc3339(
        now_secs + (valid_days as u64) * 86400,
    );

    let pub_key_bytes = signer.public_key_bytes();
    let pub_key_b64 = URL_SAFE_NO_PAD.encode(&pub_key_bytes);

    // Build identity
    let identity = AgentIdentity {
        agent_name: name.into(),
        ship_id: ctx.config.ship_id.clone(),
        public_key: pub_key_b64.clone(),
        issuer: format!("ship://{}", ctx.config.ship_id),
        issued_at: issued_at.clone(),
        valid_until: valid_until.clone(),
        model: model.clone(),
        description: description.clone(),
    };

    // Build capabilities
    let capabilities = AgentCapabilities {
        tools: tools.iter().map(|t| ToolCapability {
            name: t.clone(),
            description: None,
        }).collect(),
        api_endpoints: Vec::new(),
        mcp_servers: Vec::new(),
    };

    // Build declaration
    let declaration = AgentDeclaration {
        bounded_actions: tools.clone(),
        forbidden,
        escalation_required: escalation,
    };

    // Sign: canonical JSON of identity + capabilities + declaration
    let payload = serde_json::json!({
        "identity": identity,
        "capabilities": capabilities,
        "declaration": declaration,
    });
    let canonical = serde_json::to_vec(&payload)?;
    let sig_bytes = signer.sign(&canonical)?;
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig_bytes);

    let certificate = AgentCertificate {
        r#type: CERTIFICATE_TYPE.into(),
        schema_version: Some(CERTIFICATE_SCHEMA_VERSION.into()),
        identity: identity.clone(),
        capabilities: capabilities.clone(),
        declaration: declaration.clone(),
        signature: CertificateSignature {
            algorithm: "ed25519".into(),
            key_id: signer.key_id().to_string(),
            public_key: pub_key_b64,
            signature: sig_b64,
            signed_fields: "identity+capabilities+declaration".into(),
        },
    };

    // Write .agent package. Sanitize name to prevent path traversal:
    // strip path separators, .., and non-alphanumeric chars (except dash/underscore).
    let safe_name: String = name
        .replace(' ', "-")
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    if safe_name.is_empty() {
        return Err("agent name must contain at least one alphanumeric character".into());
    }
    let pkg_name = format!("{}.agent", safe_name);
    let pkg_dir = std::env::current_dir()?.join(&pkg_name);
    std::fs::create_dir_all(&pkg_dir)?;

    // identity.json
    let identity_json = serde_json::to_string_pretty(&identity)?;
    std::fs::write(pkg_dir.join("identity.json"), &identity_json)?;

    // capabilities.json
    let capabilities_json = serde_json::to_string_pretty(&capabilities)?;
    std::fs::write(pkg_dir.join("capabilities.json"), &capabilities_json)?;

    // declaration.json
    let declaration_json = serde_json::to_string_pretty(&declaration)?;
    std::fs::write(pkg_dir.join("declaration.json"), &declaration_json)?;

    // certificate.html
    let cert_json = serde_json::to_string_pretty(&certificate)?;
    let safe_json = cert_json.replace('<', r"\u003c");
    let html = CERTIFICATE_TEMPLATE.replace("__CERTIFICATE_JSON__", &safe_json);
    std::fs::write(pkg_dir.join("certificate.html"), html.as_bytes())?;

    // Also write the full certificate.json
    let full_json = serde_json::to_string_pretty(&certificate)?;
    std::fs::write(pkg_dir.join("certificate.json"), &full_json)?;

    printer.blank();
    printer.success("agent certificate created", &[]);
    printer.info(&format!("  agent:      {}", name));
    printer.info(&format!("  ship:       {}", ctx.config.ship_id));
    printer.info(&format!("  tools:      {}", tools.len()));
    printer.info(&format!("  valid:      {} days (until {})", valid_days, valid_until));
    printer.info(&format!("  package:    {}", pkg_dir.display()));
    printer.blank();
    printer.hint(&format!("open {}/certificate.html", pkg_dir.display()));
    printer.blank();

    Ok(())
}

/// Certificate HTML template. Same design system as preview.html.
const CERTIFICATE_TEMPLATE: &str = include_str!("certificate_template.html");
