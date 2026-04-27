use std::path::{Path, PathBuf};

use treeship_core::{
    attestation::sign,
    statements::{ActionStatement, ApprovalStatement, payload_type},
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
// Pending approval file format
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct PendingApproval {
    pub command: String,
    pub label: String,
    #[serde(default)]
    pub actor: Option<String>,
    pub requested_at: String,
    pub requested_at_ms: u64,
    #[serde(default)]
    pub rule: Option<String>,
    #[serde(default)]
    pub approved: bool,
    #[serde(default)]
    pub denied: bool,
    #[serde(default)]
    pub nonce: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pending_dir() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let ts_dir = dir.join(".treeship");
        if ts_dir.is_dir() {
            let pending = ts_dir.join("pending");
            return Some(pending);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn ensure_pending_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = pending_dir().ok_or("no .treeship directory found")?;
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// List pending approval files, sorted newest first.
fn list_pending_files() -> Vec<(PathBuf, PendingApproval)> {
    let dir = match pending_dir() {
        Some(d) => d,
        None => return vec![],
    };

    if !dir.exists() {
        return vec![];
    }

    let mut entries: Vec<(PathBuf, PendingApproval)> = Vec::new();

    if let Ok(read_dir) = std::fs::read_dir(&dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(data) = std::fs::read_to_string(&path) {
                    if let Ok(pending) = serde_json::from_str::<PendingApproval>(&data) {
                        // Skip already approved/denied
                        if !pending.approved && !pending.denied {
                            // Skip if older than 1 hour
                            let now_ms = epoch_ms();
                            if now_ms.saturating_sub(pending.requested_at_ms) < 3_600_000 {
                                entries.push((path, pending));
                            } else {
                                // Clean up expired
                                let _ = std::fs::remove_file(&path);
                            }
                        }
                    }
                }
            }
        }
    }

    // Sort newest first
    entries.sort_by(|a, b| b.1.requested_at_ms.cmp(&a.1.requested_at_ms));
    entries
}

fn generate_nonce() -> String {
    let mut buf = [0u8; 12];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut buf);
    format!("nce_{}", hex::encode(buf))
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    treeship_core::statements::unix_to_rfc3339(secs)
}

fn format_relative(ms_ago: u64) -> String {
    let secs = ms_ago / 1000;
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else {
        format!("{}h ago", secs / 3600)
    }
}

// ---------------------------------------------------------------------------
// Public: write a pending approval file (called from hook.rs)
// ---------------------------------------------------------------------------

pub fn write_pending(
    command: &str,
    label: &str,
    actor: Option<&str>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = ensure_pending_dir()?;
    let now_ms = epoch_ms();
    let filename = format!("pending_{}.json", now_ms);
    let path = dir.join(&filename);

    let pending = PendingApproval {
        command: command.to_string(),
        label: label.to_string(),
        actor: actor.map(|s| s.to_string()),
        requested_at: now_rfc3339(),
        requested_at_ms: now_ms,
        rule: None,
        approved: false,
        denied: false,
        nonce: None,
    };

    let json = serde_json::to_string_pretty(&pending)?;
    std::fs::write(&path, &json)?;
    set_restrictive_permissions(&path);
    Ok(path)
}

/// Check if a command has been approved (look for matching .approved file).
/// Cross-checks the approval nonce against the artifact store to prevent
/// tampering with the pending JSON file.
pub fn check_approved(command: &str) -> Option<String> {
    let dir = pending_dir()?;
    if !dir.exists() {
        return None;
    }

    if let Ok(read_dir) = std::fs::read_dir(&dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(data) = std::fs::read_to_string(&path) {
                    if let Ok(pending) = serde_json::from_str::<PendingApproval>(&data) {
                        if pending.approved && pending.command == command {
                            // Cross-check: verify an approval artifact with this nonce
                            // exists in storage. Don't trust the pending file alone.
                            if let Some(ref nonce) = pending.nonce {
                                if !verify_approval_artifact_exists(nonce) {
                                    // Approval file says approved but no matching artifact
                                    // exists -- possible tampering
                                    let _ = std::fs::remove_file(&path);
                                    continue;
                                }
                            } else {
                                // No nonce in approval -- invalid
                                let _ = std::fs::remove_file(&path);
                                continue;
                            }
                            let nonce = pending.nonce.clone();
                            // Consume the approval (single-use)
                            let _ = std::fs::remove_file(&path);
                            return nonce;
                        }
                    }
                }
            }
        }
    }
    None
}

/// Verify that an approval artifact with the given nonce exists in storage.
fn verify_approval_artifact_exists(nonce: &str) -> bool {
    // Walk the storage directory looking for an approval artifact that
    // contains this nonce. This is a simple scan -- acceptable for the
    // typical number of artifacts in a local store.
    let ts_dir = match pending_dir() {
        Some(d) => d.parent().map(|p| p.to_path_buf()),
        None => None,
    };
    let storage_dir = match ts_dir {
        Some(ref ts) => ts.join("artifacts"),
        None => return false,
    };
    if !storage_dir.exists() {
        return false;
    }
    if let Ok(entries) = std::fs::read_dir(&storage_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(data) = std::fs::read_to_string(&path) {
                    // Check if this artifact contains the nonce
                    if data.contains(nonce) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// treeship pending
// ---------------------------------------------------------------------------

pub fn pending(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let entries = list_pending_files();

    if entries.is_empty() {
        printer.blank();
        printer.dim_info("  no pending approvals");
        printer.blank();
        return Ok(());
    }

    let now_ms = epoch_ms();

    printer.blank();
    printer.section(&format!("Pending approvals ({})", entries.len()));
    printer.blank();

    for (i, (_path, pa)) in entries.iter().enumerate() {
        let idx = i + 1;
        let ago = format_relative(now_ms.saturating_sub(pa.requested_at_ms));
        printer.info(&format!("  {}. {}", idx, pa.command));
        printer.dim_info(&format!(
            "     label: {}  |  requested {}",
            pa.label, ago
        ));
        printer.hint(&format!("treeship approve {}", idx));
        printer.blank();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// treeship approve [N]
// ---------------------------------------------------------------------------

pub fn approve(
    n: Option<usize>,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = list_pending_files();

    if entries.is_empty() {
        return Err("no pending approvals".into());
    }

    let idx = n.unwrap_or(1);
    if idx == 0 || idx > entries.len() {
        return Err(format!(
            "invalid index {}. {} pending approval(s)",
            idx,
            entries.len()
        ).into());
    }

    let (path, mut pa) = entries[idx - 1].clone();

    let ctx = ctx::open(config)?;

    // Generate approval nonce
    let nonce = generate_nonce();

    // Create an ApprovalStatement artifact
    let approver = {
        // Try config actor, fall back to ship id
        format!("ship://{}", ctx.config.ship_id)
    };

    let mut stmt = ApprovalStatement::new(&approver, &nonce);
    stmt.description = Some(format!("approve: {}", pa.label));
    stmt.meta = Some(serde_json::json!({
        "command": pa.command,
        "label": pa.label,
    }));

    let signer = ctx.keys.default_signer()?;
    let pt = payload_type("approval");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    None,
        envelope:     result.envelope,
        hub_url:      None,
    })?;

    // Mark the pending file as approved with the nonce
    pa.approved = true;
    pa.nonce = Some(nonce.clone());
    let json = serde_json::to_string_pretty(&pa)?;
    std::fs::write(&path, &json)?;
    set_restrictive_permissions(&path);

    // Print
    printer.blank();
    printer.success("approved", &[]);
    printer.info(&format!("  command:  {}", pa.command));
    printer.info(&format!("  nonce:    {}  (binding token)", nonce));
    printer.blank();
    printer.dim_info("  The command will now proceed.");
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// treeship deny [N]
// ---------------------------------------------------------------------------

pub fn deny(
    n: Option<usize>,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = list_pending_files();

    if entries.is_empty() {
        return Err("no pending approvals".into());
    }

    let idx = n.unwrap_or(1);
    if idx == 0 || idx > entries.len() {
        return Err(format!(
            "invalid index {}. {} pending approval(s)",
            idx,
            entries.len()
        ).into());
    }

    let (path, pa) = entries[idx - 1].clone();

    let ctx = ctx::open(config)?;

    // Create a denial action artifact
    let actor = format!("ship://{}", ctx.config.ship_id);

    let meta = serde_json::json!({
        "denied": true,
        "command": pa.command,
        "label": pa.label,
    });

    let mut stmt = ActionStatement::new(&actor, "approval.denied");
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
        parent_id:    None,
        envelope:     result.envelope,
        hub_url:      None,
    })?;

    // Remove the pending file
    let _ = std::fs::remove_file(&path);

    // Print
    printer.blank();
    printer.failure(&format!("denied  {}", pa.command), &[]);
    printer.blank();

    Ok(())
}
