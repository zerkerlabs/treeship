use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use treeship_core::{
    attestation::sign,
    rules::ProjectConfig,
    statements::{ActionStatement, payload_type},
    storage::Record,
};

use crate::{ctx, printer::Printer};

// ---------------------------------------------------------------------------
// PID file locking
// ---------------------------------------------------------------------------

/// Acquire an exclusive lock on the PID file. Returns the open file handle
/// which must be held for the lifetime of the daemon process. The lock is
/// automatically released when the process exits or crashes.
fn acquire_pid_lock(pid_path: &Path) -> Result<std::fs::File, Box<dyn std::error::Error>> {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(pid_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        let ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            return Err("daemon already running (PID file locked)".into());
        }
    }

    // Set restrictive permissions on PID file
    set_restrictive_permissions(pid_path);

    Ok(file)
}

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
// Paths
// ---------------------------------------------------------------------------

fn ts_dir() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".treeship");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn pid_path(ts: &Path) -> PathBuf {
    ts.join("daemon.pid")
}

fn log_path(ts: &Path) -> PathBuf {
    ts.join("daemon.log")
}

fn config_yaml_path(ts: &Path) -> PathBuf {
    ts.join("config.yaml")
}

// ---------------------------------------------------------------------------
// Running check
// ---------------------------------------------------------------------------

fn read_pid(ts: &Path) -> Option<u32> {
    let p = pid_path(ts);
    if !p.exists() {
        return None;
    }
    let txt = std::fs::read_to_string(&p).ok()?;
    txt.trim().parse::<u32>().ok()
}

fn is_running(ts: &Path) -> bool {
    match read_pid(ts) {
        None => false,
        Some(pid) => process_alive(pid),
    }
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    // kill -0 checks if process exists
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    // On non-unix, just trust the PID file
    true
}

/// Read the PID file start time as an approximation of daemon start.
/// We store epoch seconds alongside the PID.
fn read_start_time(ts: &Path) -> Option<u64> {
    let p = pid_path(ts);
    let txt = std::fs::read_to_string(&p).ok()?;
    let parts: Vec<&str> = txt.trim().split_whitespace().collect();
    if parts.len() >= 2 {
        parts[1].parse::<u64>().ok()
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Daemon log
// ---------------------------------------------------------------------------

fn daemon_log(ts: &Path, msg: &str) {
    let path = log_path(ts);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let now = epoch_secs();
        let _ = writeln!(f, "[{}] {}", now, msg);
    }
}

// ---------------------------------------------------------------------------
// File snapshots
// ---------------------------------------------------------------------------

fn snapshot_files(root: &Path, ts: &Path) -> HashMap<PathBuf, SystemTime> {
    let mut map = HashMap::new();
    snapshot_recurse(root, ts, &mut map, 0);
    map
}

fn snapshot_recurse(dir: &Path, ts: &Path, map: &mut HashMap<PathBuf, SystemTime>, depth: u32) {
    if depth > 10 {
        return; // safety limit
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip hidden dirs, .treeship, .git, node_modules, target
        if name_str.starts_with('.')
            || name_str == "node_modules"
            || name_str == "target"
            || name_str == "__pycache__"
        {
            continue;
        }

        if path.is_dir() {
            snapshot_recurse(&path, ts, map, depth + 1);
        } else if path.is_file() {
            if let Ok(meta) = std::fs::metadata(&path) {
                if let Ok(mtime) = meta.modified() {
                    map.insert(path, mtime);
                }
            }
        }
    }
}

fn diff_snapshots(
    old: &HashMap<PathBuf, SystemTime>,
    new: &HashMap<PathBuf, SystemTime>,
) -> Vec<PathBuf> {
    let mut changed = Vec::new();
    for (path, mtime) in new {
        match old.get(path) {
            Some(old_mtime) if old_mtime == mtime => {}
            _ => changed.push(path.clone()),
        }
    }
    changed
}

/// Compute a simple content digest for a file (sha256 hex, first 16 chars).
fn content_digest(path: &Path) -> String {
    use sha2::{Sha256, Digest};
    match std::fs::read(path) {
        Ok(data) => {
            let hash = Sha256::digest(&data);
            let hex = hex::encode(hash);
            format!("sha256:{}", &hex[..16.min(hex.len())])
        }
        Err(_) => "sha256:unknown".to_string(),
    }
}

/// Make a path relative to root for matching against config rules.
fn relative_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .to_string()
}

// ---------------------------------------------------------------------------
// Auto-attest a file change
// ---------------------------------------------------------------------------

fn attest_file_change(
    ctx: &ctx::Ctx,
    path: &Path,
    rel_path: &str,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let actor_uri = format!("ship://{}", ctx.config.ship_id);
    let parent_id = resolve_last(&ctx.config.storage_dir);
    let digest = content_digest(path);

    let meta = serde_json::json!({
        "path": rel_path,
        "content_digest": digest,
        "source": "daemon",
    });

    let mut stmt = ActionStatement::new(&actor_uri, label);
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

    Ok(())
}

// ---------------------------------------------------------------------------
// Auto-push helpers
// ---------------------------------------------------------------------------

fn should_auto_push(project: &ProjectConfig) -> bool {
    if let Some(ref hub) = project.hub {
        hub.auto_push
    } else {
        false
    }
}

fn auto_push_new_artifacts(
    _ctx: &ctx::Ctx,
    ts: &Path,
) {
    // For v1: just log that auto-push would happen.
    // Actual push requires the hub module; we note it and move on.
    daemon_log(ts, "auto-push: would push new artifacts (not implemented in v1)");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_last(storage_dir: &str) -> Option<String> {
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
    set_restrictive_permissions(&last_path);
}

fn epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        format!("{}h {}m", h, m)
    }
}

// Signal handling note:
// The daemon relies on PID file removal for graceful shutdown.
// The stop command removes the PID file and sends SIGTERM on unix.
// The main loop checks for PID file existence each iteration.

// ---------------------------------------------------------------------------
// daemon start
// ---------------------------------------------------------------------------

pub fn start(
    config: Option<&str>,
    foreground: bool,
    no_push: bool,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ts = ts_dir().ok_or("no .treeship directory found -- run treeship init first")?;

    if is_running(&ts) {
        let pid = read_pid(&ts).unwrap_or(0);
        return Err(format!("daemon already running (pid {})", pid).into());
    }

    let config_yaml = config_yaml_path(&ts);
    if !config_yaml.exists() {
        return Err("no .treeship/config.yaml found -- run treeship init first".into());
    }

    // Only load config.yaml from trusted locations (must have config.json)
    let config_json = ts.join("config.json");
    if !config_json.exists() {
        return Err("untrusted .treeship directory: config.yaml found without config.json\n\n  Run treeship init to create a trusted configuration.".into());
    }

    // Validate config.yaml is parseable before starting
    let _project = ProjectConfig::load(&config_yaml)?;

    // Open context (loads keys + storage)
    let ctx = ctx::open(config)?;

    // Acquire exclusive lock on PID file before writing
    let pid = std::process::id();
    let start_epoch = epoch_secs();
    let _pid_lock = acquire_pid_lock(&pid_path(&ts))?;

    // Write PID + start epoch to the locked file
    std::fs::write(pid_path(&ts), format!("{} {}", pid, start_epoch))?;

    daemon_log(&ts, &format!("daemon started (pid {})", pid));

    if no_push {
        daemon_log(&ts, "auto-push disabled via --no-push flag");
    }

    printer.blank();
    printer.success("daemon started", &[("pid", &pid.to_string())]);
    if no_push {
        printer.dim_info("  auto-push disabled (--no-push)");
    }
    printer.blank();

    if !foreground {
        printer.dim_info("  tip: run with & to background: treeship daemon start &");
        printer.blank();
    }

    // Determine project root (parent of .treeship)
    let root = ts.parent().unwrap_or(Path::new(".")).to_path_buf();

    // Initial snapshot
    let mut file_snapshot = snapshot_files(&root, &ts);

    loop {
        std::thread::sleep(Duration::from_secs(2));

        // Check if PID file still exists (stop command removes it)
        if !pid_path(&ts).exists() {
            daemon_log(&ts, "daemon stopping (pid file removed)");
            break;
        }

        // Reload project config each cycle (allows live config changes)
        let project = match ProjectConfig::load(&config_yaml) {
            Ok(p) => p,
            Err(_) => continue, // config broken, skip this cycle
        };

        // Check for file changes
        let new_snapshot = snapshot_files(&root, &ts);
        let changes = diff_snapshots(&file_snapshot, &new_snapshot);

        for change_path in &changes {
            let rel = relative_path(change_path, &root);

            if let Some(match_result) = project.match_path(&rel) {
                daemon_log(&ts, &format!("attesting: {} ({})", rel, match_result.label));

                if let Err(e) = attest_file_change(&ctx, change_path, &rel, &match_result.label) {
                    daemon_log(&ts, &format!("attest error: {}", e));
                }
            }
        }

        file_snapshot = new_snapshot;

        // Auto-push if configured (unless --no-push flag is set)
        if !no_push && should_auto_push(&project) {
            auto_push_new_artifacts(&ctx, &ts);
        }
    }

    // _pid_lock is dropped here, releasing the file lock
    printer.info("  daemon stopped");
    Ok(())
}

// ---------------------------------------------------------------------------
// daemon stop
// ---------------------------------------------------------------------------

pub fn stop(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ts = ts_dir().ok_or("no .treeship directory found")?;

    let pid = match read_pid(&ts) {
        Some(p) => p,
        None => {
            printer.dim_info("  daemon is not running");
            return Ok(());
        }
    };

    // Remove PID file -- the daemon loop will notice and exit
    let _ = std::fs::remove_file(pid_path(&ts));

    daemon_log(&ts, &format!("stop requested for pid {}", pid));

    // On unix, also send SIGTERM as a courtesy
    #[cfg(unix)]
    {
        unsafe {
            libc::kill(pid as libc::pid_t, libc::SIGTERM);
        }
    }

    printer.blank();
    printer.success("daemon stopped", &[("pid", &pid.to_string())]);
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// daemon status
// ---------------------------------------------------------------------------

pub fn status(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ts = ts_dir().ok_or("no .treeship directory found")?;

    printer.blank();
    printer.section("daemon");

    if is_running(&ts) {
        let pid = read_pid(&ts).unwrap_or(0);
        let uptime_str = match read_start_time(&ts) {
            Some(start) => {
                let now = epoch_secs();
                format_uptime(now.saturating_sub(start))
            }
            None => "unknown".to_string(),
        };
        printer.info(&format!(
            "  {} running  pid {}  (uptime: {})",
            printer.green("●"),
            pid,
            uptime_str,
        ));
    } else {
        // Clean up stale PID file if process is dead
        if pid_path(&ts).exists() {
            let _ = std::fs::remove_file(pid_path(&ts));
        }
        printer.info(&format!("  {} stopped", printer.dim("○")));
        printer.blank();
        printer.hint("treeship daemon start");
    }

    printer.blank();
    Ok(())
}

// ---------------------------------------------------------------------------
// Public helpers (used by status.rs and doctor.rs)
// ---------------------------------------------------------------------------

/// Check if the daemon is running. Returns (running, pid, uptime_secs).
pub fn daemon_info() -> (bool, Option<u32>, Option<u64>) {
    let ts = match ts_dir() {
        Some(t) => t,
        None => return (false, None, None),
    };

    let pid = read_pid(&ts);
    let running = pid.map(|p| process_alive(p)).unwrap_or(false);
    let uptime = if running {
        read_start_time(&ts).map(|start| epoch_secs().saturating_sub(start))
    } else {
        None
    };

    (running, pid, uptime)
}
