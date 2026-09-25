//! The kill switch. `treeship halt <actor>` signs a `halt.v1` receipt and
//! writes a marker the enforcement points read; `treeship halt --lift
//! <actor>` signs the lift and clears the marker. Both are artifacts in the
//! session, so the record shows when the switch was thrown and by whom.
//!
//! What it reaches: every tool call the harness routes through hooks (the
//! Claude Code plugin's PreToolUse gate) and, under TREESHIP_STRICT=1, the
//! MCP bridge. What it does not reach: a process an agent started outside
//! those paths. The docs say so; this module does not pretend otherwise.
//!
//! Only the workspace's own key signs a halt. A halt file written by hand
//! without a matching signed artifact is ignored by `halt list`, and the
//! gate only honours markers that name an artifact it can read.

use std::path::{Path, PathBuf};

use treeship_core::attestation::Verifier;
use treeship_core::statements::{payload_type, ReceiptStatement};
use treeship_core::storage::Record;

use crate::ctx;
use crate::printer::{Format, Printer};

pub const ALL: &str = "*";

/// `<config_dir>/halts/`, beside the keystore this halt was signed with.
pub fn halts_dir_for(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("halts")
}

fn marker_name(actor: &str) -> String {
    if actor == ALL {
        return "_all.json".to_string();
    }
    let safe: String = actor
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("{safe}.json")
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Marker {
    pub actor: String,
    pub halt: String,
    pub issued_at: String,
    pub reason: Option<String>,
    pub key_id: String,
}

fn read_marker(dir: &Path, actor: &str) -> Option<Marker> {
    let raw = std::fs::read_to_string(dir.join(marker_name(actor))).ok()?;
    serde_json::from_str(&raw).ok()
}

/// A verifier holding only this workspace's own key. A halt or a lift
/// counts only when its envelope verifies under it; the record's `key_id`
/// field is unsigned metadata and is not consulted.
fn own_key_verifier(ctx: &ctx::Ctx, own_key: &str) -> Option<Verifier> {
    let bytes = ctx.keys.public_key(own_key).ok()?;
    let arr: [u8; 32] = bytes.as_slice().try_into().ok()?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&arr).ok()?;
    let mut v = Verifier::new(std::collections::HashMap::new());
    v.add_key(own_key.to_string(), vk);
    Some(v)
}

/// A `halt.v1` statement from a record file, only when the envelope
/// verifies under this workspace's key.
fn own_halt_statement(ctx: &ctx::Ctx, verifier: &Verifier, id: &str) -> Option<ReceiptStatement> {
    let rec = ctx.storage.read(id).ok()?;
    verifier.verify_any(&rec.envelope).ok()?;
    let stmt = rec
        .envelope
        .unmarshal_statement::<ReceiptStatement>()
        .ok()?;
    (stmt.kind == "halt.v1").then_some(stmt)
}

/// The signed lift for `halt_id`, if this workspace's key signed one. A
/// marker names a halt; the lift is the artifact that ends it. Whoever can
/// restore a saved marker file cannot re-arm a halt the ship has lifted,
/// because the lift is in the store and the marker is not an order on its
/// own (retest 0.31.7, T20). The store is read from disk, not through
/// `index.json`: rolling that unsigned cache back alongside the marker
/// re-armed the halt while the lift sat on disk the whole time (retest
/// 0.31.8). Only an envelope that verifies under the ship key counts.
pub fn lift_for(ctx: &ctx::Ctx, halt_id: &str, own_key: &str) -> Option<String> {
    let verifier = own_key_verifier(ctx, own_key)?;
    for id in ctx.storage.scan_ids() {
        let Some(stmt) = own_halt_statement(ctx, &verifier, &id) else {
            continue;
        };
        let Some(p) = stmt.payload.as_ref() else {
            continue;
        };
        if p.get("action").and_then(|v| v.as_str()) == Some("lift")
            && p.get("halt").and_then(|v| v.as_str()) == Some(halt_id)
        {
            return Some(id);
        }
    }
    None
}

/// Why a marker is not an order.
pub enum MarkerRejected {
    /// The halt it names is not on disk, is not a halt, or does not verify
    /// under this workspace's key.
    NotSignedHere,
    /// A signed lift ends it.
    LiftedBy(String),
}

/// Whether a marker is an order this workspace honours: it names a halt on
/// disk that verifies under this workspace's key, and no signed lift names
/// that halt.
fn marker_status(ctx: &ctx::Ctx, m: &Marker, own_key: &str) -> Result<(), MarkerRejected> {
    let Some(verifier) = own_key_verifier(ctx, own_key) else {
        return Err(MarkerRejected::NotSignedHere);
    };
    let is_halt = own_halt_statement(ctx, &verifier, &m.halt)
        .and_then(|s| s.payload)
        .map(|p| p.get("action").and_then(|v| v.as_str()) == Some("halt"))
        .unwrap_or(false);
    if !is_halt {
        return Err(MarkerRejected::NotSignedHere);
    }
    match lift_for(ctx, &m.halt, own_key) {
        Some(lift) => Err(MarkerRejected::LiftedBy(lift)),
        None => Ok(()),
    }
}

/// Active halt for `actor`, honouring a workspace-wide halt too. The marker
/// must name an artifact in this store, signed by this workspace's key, and
/// no signed lift may exist for it. A stale marker for a lifted halt is
/// removed on sight.
pub fn active_halt(ctx: &ctx::Ctx, actor: &str) -> Option<Marker> {
    let dir = halts_dir_for(&ctx.config_path);
    let own_key = ctx.keys.default_signer().ok()?.key_id().to_string();
    for who in [actor, ALL] {
        if let Some(m) = read_marker(&dir, who) {
            match marker_status(ctx, &m, &own_key) {
                Ok(()) => return Some(m),
                Err(MarkerRejected::LiftedBy(_)) => {
                    let _ = std::fs::remove_file(dir.join(marker_name(who)));
                }
                Err(MarkerRejected::NotSignedHere) => {}
            }
        }
    }
    None
}

fn sign_order(
    ctx: &ctx::Ctx,
    action: &str,
    actor: &str,
    reason: Option<&str>,
    halt_id: Option<&str>,
    parent: Option<String>,
) -> Result<(String, String, String), Box<dyn std::error::Error>> {
    let issued_at = crate::commands::verify::now_rfc3339();
    let mut payload = serde_json::Map::new();
    payload.insert("schema".into(), "halt.v1".into());
    payload.insert("action".into(), action.into());
    payload.insert("actor".into(), actor.into());
    if let Some(r) = reason {
        payload.insert("reason".into(), r.into());
    }
    if let Some(h) = halt_id {
        payload.insert("halt".into(), h.into());
    }
    payload.insert("issued_at".into(), issued_at.clone().into());
    let payload = serde_json::Value::Object(payload);
    treeship_core::predicates::validate("halt.v1", Some(&payload))
        .map_err(|e| format!("invalid halt: {e}"))?;

    let mut stmt = ReceiptStatement::new(format!("ship://{}", ctx.config.ship_id), "halt.v1");
    stmt.payload = Some(payload);
    // The parent goes inside the signature, not only into storage metadata:
    // a walk through this receipt checks the signed edge.
    stmt.parent_id = parent.clone();
    let signer = ctx.keys.default_signer()?;
    let signed = treeship_core::attestation::sign(&payload_type("receipt"), &stmt, &*signer)?;
    ctx.storage.write(&Record {
        artifact_id: signed.artifact_id.clone(),
        digest: signed.digest.clone(),
        payload_type: signed.envelope.payload_type.clone(),
        key_id: signer.key_id().to_string(),
        signed_at: issued_at.clone(),
        parent_id: parent,
        envelope: signed.envelope.clone(),
        hub_url: None,
        anchors: Vec::new(),
    })?;
    Ok((signed.artifact_id, issued_at, signer.key_id().to_string()))
}

/// Chain onto the active session's head when there is one, so the halt is
/// sealed in order with the actions it stopped.
fn session_parent(ctx: &ctx::Ctx) -> Option<String> {
    let manifest = crate::commands::session::load_session()?;
    crate::commands::session::session_chain_head(ctx, manifest.root_artifact_id.as_deref())
}

pub fn halt(
    actor: &str,
    reason: Option<&str>,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    if actor != ALL && !actor.contains("://") {
        return Err(
            format!("actor must be a URI such as agent://{actor}, or * for every actor").into(),
        );
    }
    if let Some(m) = active_halt(&ctx, actor) {
        if m.actor == actor {
            return Err(format!(
                "{actor} is already halted by {} ({}); lift it first with:\n  treeship halt --lift {actor}",
                m.halt, m.issued_at
            )
            .into());
        }
    }
    let parent = session_parent(&ctx);
    let (id, issued_at, key_id) = sign_order(&ctx, "halt", actor, reason, None, parent)?;
    let dir = halts_dir_for(&ctx.config_path);
    std::fs::create_dir_all(&dir)?;
    let marker = Marker {
        actor: actor.to_string(),
        halt: id.clone(),
        issued_at: issued_at.clone(),
        reason: reason.map(str::to_string),
        key_id,
    };
    std::fs::write(
        dir.join(marker_name(actor)),
        serde_json::to_string_pretty(&marker)?,
    )?;

    if printer.format == Format::Json {
        printer.json(&serde_json::json!({
            "status": "halted", "actor": actor, "halt": id, "issued_at": issued_at, "reason": reason,
        }));
    } else {
        printer.success(
            if actor == ALL {
                "every actor halted"
            } else {
                "actor halted"
            },
            &[
                ("actor", actor),
                ("halt", &id),
                ("issued_at", &issued_at),
                ("reason", reason.unwrap_or("(none)")),
            ],
        );
        printer.hint("every tool call the harness routes through hooks is now refused and signed as blocked.v1; a process started outside the hooks is not reached");
        printer.hint(&format!("treeship halt --lift {actor}   to lift it"));
        printer.blank();
    }
    Ok(())
}

pub fn lift(
    actor: &str,
    reason: Option<&str>,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let dir = halts_dir_for(&ctx.config_path);
    let Some(m) = active_halt(&ctx, actor).filter(|m| m.actor == actor) else {
        return Err(format!("{actor} is not halted\n  run: treeship halt list").into());
    };
    let parent = session_parent(&ctx);
    let (id, issued_at, _) = sign_order(&ctx, "lift", actor, reason, Some(&m.halt), parent)?;
    std::fs::remove_file(dir.join(marker_name(actor)))?;
    if printer.format == Format::Json {
        printer.json(&serde_json::json!({
            "status": "lifted", "actor": actor, "lift": id, "halt": m.halt, "issued_at": issued_at,
        }));
    } else {
        printer.success(
            "halt lifted",
            &[
                ("actor", actor),
                ("lift", &id),
                ("halt", &m.halt),
                ("issued_at", &issued_at),
            ],
        );
        printer.blank();
    }
    Ok(())
}

pub fn list(config: Option<&str>, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let dir = halts_dir_for(&ctx.config_path);
    let own_key = ctx.keys.default_signer()?.key_id().to_string();
    let mut rows = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for e in entries.flatten() {
            let Ok(raw) = std::fs::read_to_string(e.path()) else {
                continue;
            };
            let Ok(m) = serde_json::from_str::<Marker>(&raw) else {
                continue;
            };
            let (honoured, lifted_by) = match marker_status(&ctx, &m, &own_key) {
                Ok(()) => (true, None),
                Err(MarkerRejected::LiftedBy(lift)) => (false, Some(lift)),
                Err(MarkerRejected::NotSignedHere) => (false, None),
            };
            if lifted_by.is_some() {
                // The marker outlived its halt (restored from a backup, or
                // copied in): the signed lift is the order that stands.
                let _ = std::fs::remove_file(e.path());
            }
            rows.push(serde_json::json!({
                "actor": m.actor, "halt": m.halt, "issued_at": m.issued_at,
                "reason": m.reason, "honoured": honoured, "lifted_by": lifted_by,
            }));
        }
    }
    rows.sort_by(|a, b| a["issued_at"].as_str().cmp(&b["issued_at"].as_str()));
    if printer.format == Format::Json {
        printer.json(&serde_json::json!({ "halts": rows }));
        return Ok(());
    }
    if rows.is_empty() {
        printer.info("no active halts");
        return Ok(());
    }
    for r in &rows {
        // Say which of the two reasons applies: "not signed here" sent a
        // reader to check an artifact that was on disk and verified fine,
        // when the marker had in fact been lifted (retest 0.31.8).
        let tag = if r["honoured"].as_bool().unwrap_or(false) {
            String::new()
        } else if let Some(lift) = r["lifted_by"].as_str() {
            format!("  (IGNORED: lifted by {lift}; the signed lift stands)")
        } else {
            "  (IGNORED: its halt is not on disk as a halt.v1 signed by this workspace's key)"
                .to_string()
        };
        printer.info(&format!(
            "{}  halted {}  {}  {}{}",
            r["actor"].as_str().unwrap_or(""),
            r["issued_at"].as_str().unwrap_or(""),
            r["halt"].as_str().unwrap_or(""),
            r["reason"].as_str().unwrap_or(""),
            tag
        ));
    }
    Ok(())
}
