use std::path::{Path, PathBuf};

use treeship_core::rules::ProjectConfig;
use treeship_core::{
    attestation::sign,
    statements::{ActionStatement, payload_type},
    storage::Record,
};

use crate::{ctx, printer::Printer};

/// Find .treeship/config.yaml by walking up from cwd.
fn find_project_config() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".treeship").join("config.yaml");
        if candidate.exists() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Pre-hook: called before a command runs.
///
/// - If no project config, exit silently.
/// - If command matches a rule, write .pending_hook state.
/// - If rule requires approval, block.
pub fn pre(command: &str, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = match find_project_config() {
        Some(p) => p,
        None => return Ok(()), // no project config, nothing to do
    };

    let project = ProjectConfig::load(&config_path)?;
    let matched = match project.match_command(command) {
        Some(m) => m,
        None => return Ok(()), // no rule matched
    };

    // If approval is required, check for an existing approval file
    let ts_dir = config_path.parent().unwrap_or(Path::new(".treeship"));
    if matched.require_approval {
        let pending_path = ts_dir.join(".pending_approval");
        // Write what's pending so `treeship approve` can pick it up
        let pending = serde_json::json!({
            "command": command,
            "label": matched.label,
            "timestamp": now_rfc3339(),
        });
        std::fs::write(&pending_path, serde_json::to_string_pretty(&pending)?)?;

        printer.info(&format!(
            "  {} {} requires approval",
            printer.yellow("!"),
            matched.label,
        ));
        printer.info(&format!("    run: treeship approve"));
        // Exit with code 1 to block the command
        std::process::exit(1);
    }

    // Store pre-execution state for post-hook
    let pending_hook = serde_json::json!({
        "command": command,
        "label": matched.label,
        "timestamp": now_rfc3339(),
        "git_head": git_head_sha(),
        "start_ms": epoch_ms(),
    });

    let pending_path = ts_dir.join(".pending_hook");
    std::fs::write(&pending_path, serde_json::to_string(&pending_hook)?)?;

    Ok(())
}

/// Post-hook: called after a command completes.
///
/// Reads .pending_hook, creates a receipt, writes .last, cleans up.
pub fn post(
    exit_code: i32,
    _command: Option<&str>,
    config_override: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = match find_project_config() {
        Some(p) => p,
        None => return Ok(()),
    };

    let ts_dir = config_path.parent().unwrap_or(Path::new(".treeship"));
    let pending_path = ts_dir.join(".pending_hook");

    if !pending_path.exists() {
        return Ok(()); // no pending hook -- command wasn't matched
    }

    let pending_data = std::fs::read_to_string(&pending_path)?;
    let pending: serde_json::Value = serde_json::from_str(&pending_data)?;

    // Clean up immediately so a crash doesn't leave stale state
    let _ = std::fs::remove_file(&pending_path);

    let command = pending["command"].as_str().unwrap_or("unknown").to_string();
    let label = pending["label"].as_str().unwrap_or("action").to_string();
    let start_ms = pending["start_ms"].as_u64().unwrap_or(0);
    let git_before = pending["git_head"].as_str().map(|s| s.to_string());

    // Elapsed time
    let now_ms = epoch_ms();
    let elapsed_ms = if now_ms > start_ms { now_ms - start_ms } else { 0 };

    // Open treeship context (loads keys + storage)
    let ctx = ctx::open(config_override)?;

    let actor_uri = {
        // Try to get actor from project config
        let project = ProjectConfig::load(&config_path).ok();
        project
            .map(|p| p.session.actor.clone())
            .unwrap_or_else(|| format!("ship://{}", ctx.config.ship_id))
    };

    // Resolve parent via .last file (auto-chain)
    let parent_id = resolve_last(&ctx.config.storage_dir);

    // Git state after
    let git_after = git_head_sha();

    // Build meta
    let mut meta = serde_json::json!({
        "command": command,
        "exitCode": exit_code,
        "elapsedMs": elapsed_ms,
        "source": "hook",
    });

    if let Some(ref gb) = git_before {
        meta["git_before"] = serde_json::Value::String(gb.clone());
    }
    if let Some(ref ga) = git_after {
        meta["git_after"] = serde_json::Value::String(ga.clone());
    }

    // Sign the action
    let mut stmt = ActionStatement::new(&actor_uri, &label);
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
        parent_id:    parent_id,
        envelope:     result.envelope,
        hub_url:      None,
    })?;

    // Write .last for auto-chaining
    write_last(&ctx.config.storage_dir, &result.artifact_id);

    // Brief one-line output
    let short_id = if result.artifact_id.len() > 14 {
        &result.artifact_id[..14]
    } else {
        &result.artifact_id
    };

    let elapsed_str = format_elapsed_ms(elapsed_ms);

    printer.info(&format!(
        "  {} {}  {}  exit {}  ({})",
        printer.green("ok"),
        short_id,
        truncate_command(&command, 30),
        exit_code,
        elapsed_str,
    ));

    Ok(())
}

// ---- helpers ---------------------------------------------------------------

fn resolve_last(storage_dir: &str) -> Option<String> {
    // Check TREESHIP_PARENT env var first
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

fn write_last(storage_dir: &str, artifact_id: &str) {
    let last_path = Path::new(storage_dir).join(".last");
    let _ = std::fs::write(&last_path, artifact_id);
}

fn git_head_sha() -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

fn now_rfc3339() -> String {
    // Simple RFC 3339 timestamp without pulling in chrono
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Approximate: good enough for a timestamp string
    // We just need something sortable, not calendar-precise
    format!("{}Z", secs)
}

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn format_elapsed_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else {
        let secs = ms as f64 / 1000.0;
        if secs < 60.0 {
            format!("{:.1}s", secs)
        } else {
            let mins = ms / 60_000;
            let rem = (ms % 60_000) / 1000;
            format!("{}m{}s", mins, rem)
        }
    }
}

fn truncate_command(cmd: &str, max: usize) -> String {
    if cmd.len() <= max {
        cmd.to_string()
    } else {
        format!("{}...", &cmd[..max - 3])
    }
}
