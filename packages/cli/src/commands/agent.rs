//! Agent Identity Certificate: treeship agent register
//!
//! Produces a .agent package containing identity.json, capabilities.json,
//! declaration.json, and certificate.html. As of v0.9.8, also writes an
//! Agent Card into the workspace's card store at `.treeship/agents/<id>.json`
//! so the same registration is visible to `treeship agents` without the user
//! having to run anything else.

use std::path::Path;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};

use treeship_core::agent::*;

use crate::commands::cards::{self, AgentCard, CardCapabilities, CardProvenance, CardStatus};
use crate::commands::discovery::{
    AgentSurface, ConnectionMode, CoverageLevel,
};
use crate::{ctx, printer::Printer};

/// Map a user-supplied agent name (e.g. "claude-code", "hermes") to the
/// canonical `AgentSurface`. Falls back to `ShellWrap` for unknown names so
/// `treeship agent register --name my-custom-bot` still gets a card.
fn surface_from_name(name: &str) -> (AgentSurface, Vec<ConnectionMode>, CoverageLevel) {
    match name.to_ascii_lowercase().as_str() {
        "claude-code" | "claude" => (
            AgentSurface::ClaudeCode,
            vec![ConnectionMode::NativeHook, ConnectionMode::Mcp],
            CoverageLevel::High,
        ),
        "cursor" | "cursor-agent" => (
            AgentSurface::CursorAgent,
            vec![ConnectionMode::Mcp],
            CoverageLevel::Medium,
        ),
        "cline" => (
            AgentSurface::Cline,
            vec![ConnectionMode::Mcp],
            CoverageLevel::Medium,
        ),
        "codex" => (
            AgentSurface::Codex,
            vec![ConnectionMode::Mcp, ConnectionMode::ShellWrap],
            CoverageLevel::Medium,
        ),
        "hermes" => (
            AgentSurface::Hermes,
            vec![ConnectionMode::Skill, ConnectionMode::Mcp],
            CoverageLevel::Medium,
        ),
        "openclaw" => (
            AgentSurface::OpenClaw,
            vec![ConnectionMode::Skill, ConnectionMode::Mcp],
            CoverageLevel::Medium,
        ),
        "ninjatech-superninja" | "superninja" => (
            AgentSurface::NinjatechSuperninja,
            vec![ConnectionMode::Mcp, ConnectionMode::GitReconcile],
            CoverageLevel::Basic,
        ),
        "ninjatech-ninja-dev" | "ninja-dev" => (
            AgentSurface::NinjatechNinjaDev,
            vec![ConnectionMode::Mcp, ConnectionMode::ShellWrap],
            CoverageLevel::Medium,
        ),
        "generic-mcp" => (
            AgentSurface::GenericMcp,
            vec![ConnectionMode::Mcp],
            CoverageLevel::Medium,
        ),
        _ => (
            AgentSurface::ShellWrap,
            vec![ConnectionMode::ShellWrap, ConnectionMode::GitReconcile],
            CoverageLevel::Basic,
        ),
    }
}

fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    treeship_core::statements::unix_to_rfc3339(secs)
}


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

    // v0.9.8: also write an Agent Card into the workspace card store.
    // Same data, different file -- the .agent package is the portable
    // signed certificate users hand off; the card is the local trust
    // object Treeship uses to show "this agent exists in this workspace,
    // here's its status." Status starts at NeedsReview because the user
    // explicitly asked for the agent (provenance: registered) but hasn't
    // confirmed they want Treeship to act on it.
    let agents_dir = cards::agents_dir_for(&ctx.config_path);
    let workspace = ctx
        .config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let host = cards::local_hostname();
    let (surface, connection_modes, coverage) = surface_from_name(name);
    let agent_id = cards::derive_agent_id(surface, &host, &workspace);

    // Pin the certificate by its on-disk content digest. If the .agent
    // package is later edited (rotation, re-sign, etc), the digest will
    // diverge and `treeship agents review` can flag it.
    let cert_digest = {
        let mut h = Sha256::new();
        h.update(full_json.as_bytes());
        let bytes = h.finalize();
        let mut hex = String::with_capacity(64);
        for byte in &bytes[..] {
            use std::fmt::Write;
            write!(hex, "{byte:02x}").ok();
        }
        format!("sha256:{hex}")
    };

    let now = now_rfc3339();
    let card = AgentCard {
        agent_id,
        agent_name:            name.to_string(),
        surface,
        connection_modes,
        coverage,
        capabilities: CardCapabilities {
            bounded_tools:       tools.clone(),
            escalation_required: declaration.escalation_required.clone(),
            forbidden:           declaration.forbidden.clone(),
        },
        provenance:            CardProvenance::Registered,
        status:                CardStatus::NeedsReview,
        host,
        workspace:             workspace.to_string_lossy().into_owned(),
        model:                 model.clone(),
        description:           description.clone(),
        certificate_digest:    Some(cert_digest),
        // surface.kind() ("cursor-agent") and harness_id ("cursor") are
        // distinct namespaces; harnesses::recommended_id is the right
        // lookup so cards always point at a real entry in HARNESSES.
        active_harness_id:     crate::commands::harnesses::recommended_id(surface)
            .map(str::to_string),
        latest_session_id:     None,
        latest_receipt_digest: None,
        created_at:            now.clone(),
        updated_at:            now.clone(),
    };
    // upsert preserves any pre-existing session linkage and never demotes
    // a higher-status card.
    let merged = cards::upsert(&agents_dir, card, &now)?;

    // Link the new card into the harness state (PR 5) so
    // `treeship harness inspect <id>` shows which agents reference it.
    // Best-effort -- harness registration failure should not fail
    // certificate creation, since the .agent package + card are the
    // primary outputs.
    if let Some(harness_id) = merged.active_harness_id.clone() {
        let harnesses_dir = crate::commands::harnesses::harnesses_dir_for(&ctx.config_path);
        if let Err(e) = crate::commands::harnesses::link_agent(
            &harnesses_dir,
            &harness_id,
            &merged.agent_id,
            &now,
        ) {
            printer.warn(
                "  could not link card into harness state",
                &[("error", &e.to_string()), ("harness", &harness_id)],
            );
        }
    }

    printer.blank();
    printer.success("agent certificate created", &[]);
    printer.info(&format!("  agent:      {}", name));
    printer.info(&format!("  ship:       {}", ctx.config.ship_id));
    printer.info(&format!("  tools:      {}", tools.len()));
    printer.info(&format!("  valid:      {} days (until {})", valid_days, valid_until));
    printer.info(&format!("  package:    {}", pkg_dir.display()));
    printer.info(&format!("  card:       {} ({})", merged.agent_id, merged.status.label()));
    printer.blank();
    printer.hint(&format!("open {}/certificate.html", pkg_dir.display()));
    printer.dim_info(&format!("  review with: treeship agents review {}", merged.agent_id));
    printer.blank();

    Ok(())
}

/// Certificate HTML template. Same design system as preview.html.
const CERTIFICATE_TEMPLATE: &str = include_str!("certificate_template.html");
