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
use treeship_core::attestation::{sign, Signer};
use treeship_core::statements::{payload_type, ReceiptStatement};
use treeship_core::storage::Record;
use treeship_core::trust::{TrustRoot, TrustRootKind, TrustRootStore};

use crate::commands::cards::{self, AgentCard, CardCapabilities, CardProvenance, CardStatus};
use crate::commands::discovery::{AgentSurface, ConnectionMode, CoverageLevel};
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
/// Mint the protocol-native agent_cert.v1 receipt: the ship key signs an
/// envelope whose payload binds `agent://<name>` to its per-agent public key.
/// Validated against the registered predicate schema before signing
/// (fail-closed). Idempotent per (agent, subject key): an existing cert in
/// the store short-circuits, so register-on-every-boot callers (bridges,
/// `onboard`) never pile up duplicates.
#[allow(clippy::too_many_arguments)]
fn mint_cert_receipt(
    ctx: &ctx::Ctx,
    name: &str,
    subject_key_id: &str,
    subject_pub_b64: &str,
    issued_at: &str,
    valid_until: &str,
    model: Option<&str>,
    description: Option<&str>,
    signer: &dyn Signer,
) -> Result<(), Box<dyn std::error::Error>> {
    let agent_uri = format!("agent://{name}");
    let receipt_pt = payload_type("receipt");

    // Idempotency scan: one cert per (agent, subject key).
    for entry in ctx.storage.list_by_type(&receipt_pt) {
        let Ok(rec) = ctx.storage.read(&entry.id) else { continue };
        let Ok(stmt) = rec.envelope.unmarshal_statement::<ReceiptStatement>() else { continue };
        if stmt.kind != "agent_cert.v1" {
            continue;
        }
        let Some(p) = stmt.payload else { continue };
        if p.get("agent").and_then(|v| v.as_str()) == Some(agent_uri.as_str())
            && p.get("subject_key_id").and_then(|v| v.as_str()) == Some(subject_key_id)
        {
            return Ok(());
        }
    }

    let payload = serde_json::json!({
        "agent": agent_uri,
        "subject_key_id": subject_key_id,
        "subject_public_key": subject_pub_b64,
        "issuer": format!("ship://{}", ctx.config.ship_id),
        "issued_at": issued_at,
        "valid_until": valid_until,
        "model": model,
        "description": description,
    });
    treeship_core::predicates::validate("agent_cert.v1", Some(&payload))
        .map_err(|e| format!("agent_cert.v1 validation failed: {e}"))?;

    let mut stmt = ReceiptStatement::new(
        &format!("ship://{}", ctx.config.ship_id),
        "agent_cert.v1",
    );
    stmt.payload = Some(payload);

    let result = sign(&receipt_pt, &stmt, signer)?;
    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest,
        payload_type: receipt_pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    None,
        envelope:     result.envelope,
        hub_url:      None,
    })?;
    Ok(())
}

pub fn register(
    name: &str,
    tools: Vec<String>,
    model: Option<String>,
    valid_days: u32,
    description: Option<String>,
    forbidden: Vec<String>,
    escalation: Vec<String>,
    own_key: bool,
    quiet: bool,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    // The ship's default key is the issuer: it signs the certificate.
    let signer = ctx.keys.default_signer()?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    let issued_at = treeship_core::statements::unix_to_rfc3339(now_secs);
    let valid_until =
        treeship_core::statements::unix_to_rfc3339(now_secs + (valid_days as u64) * 86400);

    let ship_pub_b64 = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());

    // Subject key. With --own-key, mint a dedicated per-agent key and certify
    // THAT as the agent's identity (the ship still signs as issuer). Without
    // the flag, the subject is the ship key -- the legacy behavior, unchanged.
    //
    // Idempotent: if this agent already has a registered per-agent key, reuse
    // it instead of minting a second one. This lets callers that run on every
    // startup (the MCP/A2A bridges) register safely without piling up keys.
    let (subject_pub_b64, agent_key_id, key_is_new) = if own_key {
        let agents_dir = cards::agents_dir_for(&ctx.config_path);
        if let Some(existing) =
            cards::registered_key_for_actor(&agents_dir, &format!("agent://{name}"))
        {
            let pub_bytes = ctx.keys.public_key(&existing)?;
            (URL_SAFE_NO_PAD.encode(&pub_bytes), Some(existing), false)
        } else {
            let agent_key = ctx.keys.generate(false)?;
            (
                URL_SAFE_NO_PAD.encode(&agent_key.public_key),
                Some(agent_key.id.to_string()),
                true,
            )
        }
    } else {
        (ship_pub_b64.clone(), None, false)
    };

    // Build identity (subject = the agent's own key when --own-key)
    let identity = AgentIdentity {
        agent_name: name.into(),
        ship_id: ctx.config.ship_id.clone(),
        public_key: subject_pub_b64.clone(),
        issuer: format!("ship://{}", ctx.config.ship_id),
        issued_at: issued_at.clone(),
        valid_until: valid_until.clone(),
        model: model.clone(),
        description: description.clone(),
    };

    // Build capabilities
    let capabilities = AgentCapabilities {
        tools: tools
            .iter()
            .map(|t| ToolCapability {
                name: t.clone(),
                description: None,
            })
            .collect(),
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
            // Issuer = the ship's key (it signed the canonical bytes).
            key_id: signer.key_id().to_string(),
            public_key: ship_pub_b64.clone(),
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

    // Full certificate JSON, needed for the certificate digest below regardless
    // of whether the portable .agent package is written to disk.
    let full_json = serde_json::to_string_pretty(&certificate)?;

    // --quiet skips the on-disk .agent package. Programmatic callers (the
    // MCP/A2A bridges, which register on every startup) do not want a `.agent`
    // directory dropped into the user's working directory each time; they only
    // need the card + key + pin, which happen below regardless.
    let pkg_dir: Option<std::path::PathBuf> = if quiet {
        None
    } else {
        Some(std::env::current_dir()?.join(format!("{}.agent", safe_name)))
    };
    if let Some(pkg_dir) = &pkg_dir {
        std::fs::create_dir_all(pkg_dir)?;

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
        std::fs::write(pkg_dir.join("certificate.json"), &full_json)?;
    }

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
    let agent_id = cards::derive_agent_id(name, surface, &host, &workspace);

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

    // Pin the per-agent key under AgentCert (only with a NEWLY-minted --own-key
    // key) so that verify (and verify-capability) can treat this agent's actions
    // as key-bound rather than self-asserted, once attest signs with it. A
    // reused key is already pinned, so re-registering does not duplicate roots.
    if key_is_new {
        if let Some(kid) = &agent_key_id {
            let mut trust = TrustRootStore::open_default_or_empty()?;
            trust.add(TrustRoot {
                key_id: kid.clone(),
                public_key: format!("ed25519:{subject_pub_b64}"),
                kind: TrustRootKind::AgentCert,
                label: name.to_string(),
                added_at: now.clone(),
            });
            trust.save(&TrustRootStore::default_path())?;
        }
    }

    // Protocol-native certificate: a typed agent_cert.v1 receipt whose
    // ENVELOPE signature by the ship key IS the certification (the .agent
    // package cert above is the human-portable rendering; this is the wire
    // artifact). It is the intermediate link of the trust chain — a remote
    // verifier who pins only the ship key verifies this envelope, reads the
    // subject key out of it, and can then verify the agent's card and
    // receipts without pinning the leaf (registry-topology spec, slice 1).
    // `publish` pushes it with the resolvable set. Idempotent: one cert per
    // (agent, subject key) in the store; a reused key re-registering does
    // not mint duplicates.
    if let Some(kid) = &agent_key_id {
        mint_cert_receipt(
            &ctx,
            name,
            kid,
            &subject_pub_b64,
            &issued_at,
            &valid_until,
            model.as_deref(),
            description.as_deref(),
            signer.as_ref(),
        )?;
    }

    let card = AgentCard {
        agent_id,
        agent_name: name.to_string(),
        surface,
        connection_modes,
        coverage,
        capabilities: CardCapabilities {
            bounded_tools: tools.clone(),
            escalation_required: declaration.escalation_required.clone(),
            forbidden: declaration.forbidden.clone(),
        },
        provenance: CardProvenance::Registered,
        status: CardStatus::NeedsReview,
        host,
        workspace: workspace.to_string_lossy().into_owned(),
        model: model.clone(),
        description: description.clone(),
        certificate_digest: Some(cert_digest),
        key_id: agent_key_id.clone(),
        // surface.kind() ("cursor-agent") and harness_id ("cursor") are
        // distinct namespaces; harnesses::recommended_id is the right
        // lookup so cards always point at a real entry in HARNESSES.
        active_harness_id: crate::commands::harnesses::recommended_id(surface).map(str::to_string),
        latest_session_id: None,
        latest_receipt_digest: None,
        created_at: now.clone(),
        updated_at: now.clone(),
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
    printer.info(&format!(
        "  valid:      {} days (until {})",
        valid_days, valid_until
    ));
    if let Some(dir) = &pkg_dir {
        printer.info(&format!("  package:    {}", dir.display()));
    }
    printer.info(&format!(
        "  card:       {} ({})",
        merged.agent_id,
        merged.status.label()
    ));
    if let Some(kid) = &agent_key_id {
        printer.info(&format!("  agent key:  {kid} (pinned under AgentCert)"));
    }
    printer.blank();
    if let Some(dir) = &pkg_dir {
        printer.hint(&format!("open {}/certificate.html", dir.display()));
    }
    printer.dim_info(&format!(
        "  review with: treeship agents review {}",
        merged.agent_id
    ));
    printer.blank();

    Ok(())
}

/// Certificate HTML template. Same design system as preview.html.
const CERTIFICATE_TEMPLATE: &str = include_str!("certificate_template.html");
