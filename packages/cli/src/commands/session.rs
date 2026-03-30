use std::path::{Path, PathBuf};

use treeship_core::{
    attestation::sign,
    statements::{ActionStatement, payload_type},
    storage::Record,
};

use crate::{ctx, printer::Printer};

/// Set file permissions to 0600 (owner read/write only) on Unix.
#[cfg(unix)]
fn set_restrictive_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_restrictive_permissions(_path: &Path) {
    // No-op on non-unix platforms
}

// ---------------------------------------------------------------------------
// Session manifest (persisted as .treeship/session.json)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct SessionManifest {
    pub session_id: String,
    pub name: Option<String>,
    pub actor: String,
    pub started_at: String,
    pub started_at_ms: u64,
    pub artifact_count: u64,
    pub root_artifact_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn session_path() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".treeship").join("session.json");
        if candidate.exists() {
            return Some(candidate);
        }
        // Also check if .treeship dir exists here (for creating a new session)
        let ts_dir = dir.join(".treeship");
        if ts_dir.is_dir() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn session_dir() -> Option<PathBuf> {
    session_path().and_then(|p| p.parent().map(|d| d.to_path_buf()))
}

fn generate_session_id() -> String {
    let mut buf = [0u8; 8];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut buf);
    format!("ssn_{}", hex::encode(buf))
}

fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    treeship_core::statements::unix_to_rfc3339(secs)
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn format_duration_ms(ms: u64) -> String {
    let secs = ms / 1000;
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        format!("{}h{}m", h, m)
    }
}

pub fn load_session() -> Option<SessionManifest> {
    let path = session_path()?;
    if !path.exists() {
        return None;
    }
    let data = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

fn write_last(storage_dir: &str, artifact_id: &str) {
    let last_path = Path::new(storage_dir).join(".last");
    let _ = std::fs::write(&last_path, artifact_id);
    set_restrictive_permissions(&last_path);
}

fn resolve_last(storage_dir: &str) -> Option<String> {
    if let Ok(env_parent) = std::env::var("TREESHIP_PARENT") {
        if !env_parent.is_empty() {
            return Some(env_parent);
        }
    }
    let last_path = Path::new(storage_dir).join(".last");
    if let Ok(contents) = std::fs::read_to_string(&last_path) {
        let trimmed = contents.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    None
}

/// Count artifacts in the chain from .last back to root_artifact_id.
fn count_chain_artifacts(ctx: &ctx::Ctx, root_id: &str) -> u64 {
    let last_path = Path::new(&ctx.config.storage_dir).join(".last");
    let current_id = match std::fs::read_to_string(&last_path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return 0,
    };

    if current_id == root_id {
        return 0;
    }

    let mut count = 0u64;
    let mut cursor = current_id;
    for _ in 0..1000 {
        if cursor == root_id {
            break;
        }
        count += 1;
        match ctx.storage.read(&cursor) {
            Ok(record) => match record.parent_id {
                Some(pid) => cursor = pid,
                None => break,
            },
            Err(_) => break,
        }
    }
    count
}

// ---------------------------------------------------------------------------
// session start
// ---------------------------------------------------------------------------

pub fn start(
    name: Option<String>,
    actor: Option<String>,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check for existing session
    if let Some(existing) = load_session() {
        return Err(format!(
            "session already active: {} ({})\n\n  run: treeship session close",
            existing.session_id,
            existing.name.unwrap_or_default()
        ).into());
    }

    let ts_dir = match session_dir() {
        Some(d) => d,
        None => return Err("no .treeship directory found -- run treeship init first".into()),
    };

    let ctx = ctx::open(config)?;

    let session_id = generate_session_id();
    let actor_uri = actor.unwrap_or_else(|| format!("ship://{}", ctx.config.ship_id));
    let now = now_rfc3339();
    let now_ms = epoch_ms();

    // Create the session-start action artifact
    let parent_id = resolve_last(&ctx.config.storage_dir);

    let meta = serde_json::json!({
        "session_start": true,
        "session_id": session_id,
        "name": name,
    });

    let mut stmt = ActionStatement::new(&actor_uri, "session.start");
    stmt.parent_id = parent_id.clone();
    stmt.meta = Some(meta);

    let signer = ctx.keys.default_signer()?;
    let pt = payload_type("action");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id,
        envelope:     result.envelope,
        hub_url:      None,
    })?;

    write_last(&ctx.config.storage_dir, &result.artifact_id);

    // Write session manifest
    let manifest = SessionManifest {
        session_id: session_id.clone(),
        name: name.clone(),
        actor: actor_uri.clone(),
        started_at: now.clone(),
        started_at_ms: now_ms,
        artifact_count: 0,
        root_artifact_id: Some(result.artifact_id.clone()),
    };

    let session_path = ts_dir.join("session.json");
    let json = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(&session_path, &json)?;
    set_restrictive_permissions(&session_path);

    // Print output
    printer.blank();
    printer.success("session started", &[]);
    printer.info(&format!("  id:     {}", session_id));
    if let Some(ref n) = name {
        printer.info(&format!("  name:   {}", n));
    }
    printer.info(&format!("  actor:  {}", actor_uri));
    printer.blank();
    printer.hint("treeship session status  to check progress");
    printer.hint("treeship session close   when done");
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// session status
// ---------------------------------------------------------------------------

pub fn status(
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = match load_session() {
        Some(m) => m,
        None => {
            printer.blank();
            printer.dim_info("  no active session");
            printer.blank();
            printer.hint("treeship session start --name \"my task\"");
            printer.blank();
            return Ok(());
        }
    };

    let ctx = ctx::open(config)?;

    // Verify the root artifact actually exists in storage
    let root_verified = if let Some(ref root_id) = manifest.root_artifact_id {
        ctx.storage.read(root_id).is_ok()
    } else {
        false
    };

    // Don't trust session.json counts -- verify from artifact chain
    let artifact_count = match &manifest.root_artifact_id {
        Some(root_id) => count_chain_artifacts(&ctx, root_id),
        None => 0,
    };

    if !root_verified {
        if manifest.root_artifact_id.is_some() {
            printer.warn("session root artifact not found in storage (file may have been modified)", &[]);
        }
    }

    if artifact_count != manifest.artifact_count && manifest.artifact_count != 0 {
        printer.warn("session artifact count mismatch (file may have been modified)", &[]);
    }

    let elapsed_ms = epoch_ms().saturating_sub(manifest.started_at_ms);
    let elapsed_str = format_duration_ms(elapsed_ms);

    printer.blank();
    printer.section("session");
    printer.info(&format!("  id:        {}", manifest.session_id));
    if let Some(ref name) = manifest.name {
        printer.info(&format!("  name:      {}", name));
    }
    printer.info(&format!("  actor:     {}", manifest.actor));
    printer.info(&format!("  started:   {} ({} ago)", manifest.started_at, elapsed_str));
    printer.info(&format!("  receipts:  {} (verified from chain)", artifact_count));
    printer.blank();
    printer.hint("treeship session close --summary \"what was done\"");
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// session close
// ---------------------------------------------------------------------------

pub fn close(
    summary: Option<String>,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = match load_session() {
        Some(m) => m,
        None => {
            return Err("no active session to close".into());
        }
    };

    let ctx = ctx::open(config)?;

    // Verify the root artifact actually exists in storage
    if let Some(ref root_id) = manifest.root_artifact_id {
        if ctx.storage.read(root_id).is_err() {
            printer.warn("session root artifact not found in storage (file may have been modified)", &[]);
        }
    }

    // Don't trust session.json counts -- verify from artifact chain
    let artifact_count = match &manifest.root_artifact_id {
        Some(root_id) => count_chain_artifacts(&ctx, root_id),
        None => 0,
    };

    if artifact_count != manifest.artifact_count && manifest.artifact_count != 0 {
        printer.warn("session artifact count mismatch (file may have been modified)", &[]);
    }

    let elapsed_ms = epoch_ms().saturating_sub(manifest.started_at_ms);

    // Create session-close action artifact
    let parent_id = resolve_last(&ctx.config.storage_dir);

    let meta = serde_json::json!({
        "session_close": true,
        "session_id": manifest.session_id,
        "summary": summary,
        "artifact_count": artifact_count,
        "duration_ms": elapsed_ms,
    });

    let mut stmt = ActionStatement::new(&manifest.actor, "session.close");
    stmt.parent_id = parent_id.clone();
    stmt.meta = Some(meta);

    let signer = ctx.keys.default_signer()?;
    let pt = payload_type("action");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id,
        envelope:     result.envelope,
        hub_url:      None,
    })?;

    write_last(&ctx.config.storage_dir, &result.artifact_id);

    // Remove session.json
    if let Some(path) = session_path() {
        let _ = std::fs::remove_file(&path);
    }

    // Print output
    let elapsed_str = format_duration_ms(elapsed_ms);

    printer.blank();
    printer.success("session closed", &[]);
    printer.info(&format!("  id:       {}", manifest.session_id));
    printer.info(&format!("  duration: {}", elapsed_str));
    printer.info(&format!("  receipts: {}", artifact_count));
    printer.blank();
    printer.hint(&format!("treeship verify {} --full  to see the chain", result.artifact_id));
    printer.hint(&format!("treeship dock push {}      to share", result.artifact_id));
    printer.blank();

    Ok(())
}
