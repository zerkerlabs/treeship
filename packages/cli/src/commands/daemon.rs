use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use treeship_core::{
    attestation::sign,
    rules::ProjectConfig,
    session::{
        EventLog, EventType, SessionEvent, SessionManifest,
        event::{generate_event_id, generate_span_id, generate_trace_id},
    },
    statements::{ActionStatement, payload_type},
    storage::Record,
};

use crate::{ctx, printer::Printer};

/// File timestamps captured per snapshot.
/// `mtime` advances on writes; `atime` advances on content reads
/// (subject to the filesystem's `atime` policy: `relatime`/`strictatime`/`noatime`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileTimes {
    mtime: SystemTime,
    atime: SystemTime,
}

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

fn snapshot_files(root: &Path, ts: &Path) -> HashMap<PathBuf, FileTimes> {
    let mut map = HashMap::new();
    snapshot_recurse(root, ts, &mut map, 0);
    map
}

fn snapshot_recurse(dir: &Path, ts: &Path, map: &mut HashMap<PathBuf, FileTimes>, depth: u32) {
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

        // Skip hidden dirs, .treeship, .git, node_modules, target.
        // Note: this means dotfiles like .env are NOT walked by the recurse
        // loop. The daemon's main loop watches them separately via
        // sensitive-file polling so they still get atime tracking.
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
                let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                let atime = meta.accessed().unwrap_or(mtime);
                map.insert(path, FileTimes { mtime, atime });
            }
        }
    }
}

/// Snapshot dotfiles at the project root that match an `on: access` rule.
///
/// The main `snapshot_recurse` skips hidden files and directories so .git
/// and .treeship don't pollute the watch set. But sensitive files like
/// .env, .env.local, .aws/credentials live in those skipped paths. This
/// pass walks the root directory only and includes dotfiles whose path
/// matches an access rule, plus a small set of well-known sensitive
/// subdirectories one level deep.
fn snapshot_sensitive_files(
    root: &Path,
    project: &ProjectConfig,
    map: &mut HashMap<PathBuf, FileTimes>,
) {
    // 1. Dotfiles at the project root.
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.starts_with('.') {
                continue; // already covered by snapshot_recurse
            }
            let rel = relative_path(&path, root);
            if matches_access_rule(project, &rel) {
                if let Ok(meta) = std::fs::metadata(&path) {
                    let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                    let atime = meta.accessed().unwrap_or(mtime);
                    map.insert(path, FileTimes { mtime, atime });
                }
            }
        }
    }

    // 2. Well-known sensitive dot-directories one level deep.
    for dotdir in &[".aws", ".ssh", ".gnupg", ".docker", ".kube"] {
        let dir_path = root.join(dotdir);
        if !dir_path.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&dir_path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                let rel = relative_path(&path, root);
                if matches_access_rule(project, &rel) {
                    if let Ok(meta) = std::fs::metadata(&path) {
                        let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                        let atime = meta.accessed().unwrap_or(mtime);
                        map.insert(path, FileTimes { mtime, atime });
                    }
                }
            }
        }
    }
}

/// Returns true if the given relative path matches a configured rule with `on: access`.
fn matches_access_rule(project: &ProjectConfig, rel_path: &str) -> bool {
    project
        .match_path(rel_path)
        .map(|m| m.on == "access")
        .unwrap_or(false)
}

/// Result of comparing two file snapshots.
#[derive(Debug, Default)]
struct SnapshotDiff {
    /// Files whose mtime advanced (writes / new files).
    written: Vec<PathBuf>,
    /// Files whose atime advanced but mtime did not (pure reads).
    read: Vec<PathBuf>,
}

fn diff_snapshots(
    old: &HashMap<PathBuf, FileTimes>,
    new: &HashMap<PathBuf, FileTimes>,
) -> SnapshotDiff {
    let mut diff = SnapshotDiff::default();
    for (path, new_times) in new {
        match old.get(path) {
            None => {
                // New file -- treat as a write.
                diff.written.push(path.clone());
            }
            Some(old_times) => {
                let mtime_changed = old_times.mtime != new_times.mtime;
                let atime_changed = old_times.atime != new_times.atime;
                if mtime_changed {
                    diff.written.push(path.clone());
                }
                // Emit a read whenever atime advanced, even if mtime also
                // changed. Without this, a touch/write after a secret read
                // would suppress the atime-only signal entirely, and
                // on:access rules would never fire for that file.
                if atime_changed {
                    diff.read.push(path.clone());
                }
            }
        }
    }
    diff
}

// ---------------------------------------------------------------------------
// Session event integration
// ---------------------------------------------------------------------------

/// Load the active session manifest if one is present at `.treeship/session.json`.
fn load_active_session(ts: &Path) -> Option<SessionManifest> {
    let path = ts.join("session.json");
    if !path.exists() {
        return None;
    }
    let data = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Open the EventLog for the active session, if any.
fn open_active_event_log(ts: &Path) -> Option<(SessionManifest, EventLog)> {
    let manifest = load_active_session(ts)?;
    let evt_dir = ts.join("sessions").join(&manifest.session_id);
    let log = EventLog::open(&evt_dir).ok()?;
    Some((manifest, log))
}

/// Emit an `agent.read_file` event to the active session's event log.
///
/// Best-effort: returns false if no session is active or the append fails.
/// The event is tagged with `capture_confidence: "inferred"` because atime
/// detection cannot distinguish a real content read from filesystem
/// metadata operations on some platforms.
fn emit_read_event(
    ts: &Path,
    rel_path: &str,
    content_digest_str: Option<String>,
    label: &str,
) -> bool {
    let (manifest, log) = match open_active_event_log(ts) {
        Some(pair) => pair,
        None => return false,
    };

    let host_id = local_host_id();
    let trace_id = generate_trace_id();

    let meta = serde_json::json!({
        "capture_confidence": "inferred",
        "source": "daemon-atime",
        "label": label,
    });

    let mut event = SessionEvent {
        session_id: manifest.session_id.clone(),
        event_id: generate_event_id(),
        timestamp: now_rfc3339_daemon(),
        sequence_no: 0, // set by EventLog::append
        trace_id,
        span_id: generate_span_id(),
        parent_span_id: None,
        agent_id: manifest.actor.clone(),
        agent_instance_id: "daemon".into(),
        agent_name: "treeship-daemon".into(),
        agent_role: Some("watcher".into()),
        host_id,
        tool_runtime_id: None,
        event_type: EventType::AgentReadFile {
            file_path: rel_path.into(),
            digest: content_digest_str,
        },
        artifact_ref: None,
        meta: Some(meta),
    };

    log.append(&mut event).is_ok()
}

/// RFC3339 timestamp helper for daemon-emitted events.
fn now_rfc3339_daemon() -> String {
    let secs = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    treeship_core::statements::unix_to_rfc3339(secs)
}

/// Best-effort host ID derived from `hostname` command.
fn local_host_id() -> String {
    std::env::var("TREESHIP_HOST_ID").unwrap_or_else(|_| {
        std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|h| format!("host_{}", h.trim().replace('.', "_")))
            .unwrap_or_else(|| "host_unknown".into())
    })
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

    // Initial snapshot (regular tree + sensitive dotfiles)
    let initial_project = ProjectConfig::load(&config_yaml).ok();
    let mut file_snapshot = snapshot_files(&root, &ts);
    if let Some(ref proj) = initial_project {
        snapshot_sensitive_files(&root, proj, &mut file_snapshot);
    }

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

        // Check for file changes (regular tree + sensitive dotfiles)
        let mut new_snapshot = snapshot_files(&root, &ts);
        snapshot_sensitive_files(&root, &project, &mut new_snapshot);
        let diff = diff_snapshots(&file_snapshot, &new_snapshot);

        // ── Writes: existing attestation flow ─────────────────────────
        for change_path in &diff.written {
            let rel = relative_path(change_path, &root);

            if let Some(match_result) = project.match_path(&rel) {
                // Skip pure-access rules in the write loop -- those are handled below.
                if match_result.on == "access" {
                    continue;
                }
                daemon_log(&ts, &format!("attesting: {} ({})", rel, match_result.label));

                if let Err(e) = attest_file_change(&ctx, change_path, &rel, &match_result.label) {
                    daemon_log(&ts, &format!("attest error: {}", e));
                }
            }
        }

        // ── Reads: emit AgentReadFile events to active session ────────
        // Only fires for paths matching a rule with `on: access`. The detection
        // is best-effort and tagged `capture_confidence: inferred` because
        // atime semantics vary by filesystem (relatime, noatime, etc).
        for read_path in &diff.read {
            let rel = relative_path(read_path, &root);
            if let Some(match_result) = project.match_path(&rel) {
                if match_result.on != "access" {
                    continue;
                }

                let digest = Some(content_digest(read_path));
                let emitted = emit_read_event(&ts, &rel, digest, &match_result.label);

                if emitted {
                    daemon_log(&ts, &format!("read event: {} ({})", rel, match_result.label));
                } else {
                    // No active session -- still log the alert if configured.
                    daemon_log(&ts, &format!("read detected (no active session): {} ({})", rel, match_result.label));
                }

                if match_result.alert {
                    daemon_log(&ts, &format!("ALERT: sensitive file accessed: {}", rel));
                }
            }
        }

        file_snapshot = new_snapshot;

        // Auto-push if configured (unless --no-push flag is set)
        if !no_push && should_auto_push(&project) {
            auto_push_new_artifacts(&ctx, &ts);
        }

        // ZK: Process proof job queue (background, non-blocking)
        #[cfg(feature = "zk")]
        {
            process_proof_queue(&ts, &ctx);
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
// ZK proof job queue (background proving)
// ---------------------------------------------------------------------------

/// Process any pending proof jobs. Called each daemon cycle.
/// Proof jobs are created when sessions close with zk.auto_prove enabled.
#[cfg(feature = "zk")]
fn process_proof_queue(ts: &std::path::Path, ctx: &crate::ctx::Ctx) {
    let queue_dir = ts.join("proof_queue");
    if !queue_dir.exists() {
        return;
    }

    let entries = match std::fs::read_dir(&queue_dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map_or(true, |e| e != "json") {
            continue;
        }

        // Lock file prevents concurrent processing of the same job.
        // Stale locks (>30 min) from crashed daemons are cleaned up.
        let lock_path = path.with_extension("lock");
        if lock_path.exists() {
            // Check if lock is stale (older than 30 minutes)
            if let Ok(metadata) = std::fs::metadata(&lock_path) {
                if let Ok(modified) = metadata.modified() {
                    let age = std::time::SystemTime::now()
                        .duration_since(modified)
                        .unwrap_or_default();
                    if age.as_secs() > 1800 {
                        daemon_log(ts, &format!("removing stale lock: {:?}", lock_path));
                        let _ = std::fs::remove_file(&lock_path);
                    } else {
                        continue; // Lock is fresh, skip
                    }
                } else {
                    continue;
                }
            } else {
                continue;
            }
        }

        // Create lock file before processing
        if std::fs::write(&lock_path, format!("{}", std::process::id())).is_err() {
            continue;
        }

        // Read the proof job
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => {
                let _ = std::fs::remove_file(&lock_path);
                continue;
            }
        };

        let job: serde_json::Value = match serde_json::from_str(&content) {
            Ok(j) => j,
            Err(_) => {
                let _ = std::fs::remove_file(&lock_path);
                continue;
            }
        };

        let session_id = job["session_id"].as_str().unwrap_or("unknown");
        let root_id = job["root_artifact_id"].as_str().map(|s| s.to_string());
        let tip_id = job["tip_artifact_id"].as_str().map(|s| s.to_string());
        daemon_log(ts, &format!("proving chain for session {} (root: {:?}, tip: {:?})", session_id, root_id, tip_id));

        // Run the proof. Pass root_artifact_id and tip_artifact_id from the
        // job so the prover knows the exact session boundaries (session.json
        // is already deleted and .last may have advanced).
        let silent_printer = crate::printer::Printer::new(crate::printer::Format::Text, true, true);
        match super::prove::prove_chain_with_root(session_id, root_id.as_deref(), tip_id.as_deref(), None, &silent_printer) {
            Ok(()) => {
                daemon_log(ts, &format!("chain proof complete for {}", session_id));

                // Update the latest Merkle checkpoint with the proof summary
                update_checkpoint_with_proof(ts, session_id);

                // Auto-push proof to Hub if attached
                if ctx.config.is_attached() {
                    daemon_log(ts, &format!("pushing proof for {} to Hub", session_id));
                }

                // Success: remove the job
                let _ = std::fs::remove_file(&path);
            }
            Err(e) => {
                daemon_log(ts, &format!("chain proof failed for {}: {}", session_id, e));
                // Keep the job for retry. Increment attempt counter.
                let attempts = job["attempts"].as_u64().unwrap_or(0) + 1;
                if attempts >= 3 {
                    // Move to dead-letter after 3 attempts
                    daemon_log(ts, &format!("moving failed job {} to dead-letter (3 attempts)", session_id));
                    let dead_dir = ts.join("proof_queue").join("dead");
                    let _ = std::fs::create_dir_all(&dead_dir);
                    let _ = std::fs::rename(&path, dead_dir.join(path.file_name().unwrap_or_default()));
                } else {
                    // Update attempts counter, keep for retry
                    let mut updated = job.clone();
                    updated["attempts"] = serde_json::json!(attempts);
                    updated["last_error"] = serde_json::json!(e.to_string());
                    let _ = std::fs::write(&path, serde_json::to_vec_pretty(&updated).unwrap_or_default());
                }
            }
        }

        // Remove lock (always). Job only removed on success.
        let _ = std::fs::remove_file(&lock_path);
    }
}

/// Update the latest Merkle checkpoint with a ZK proof summary.
/// Called by the daemon after a chain proof completes successfully.
#[cfg(feature = "zk")]
fn update_checkpoint_with_proof(ts: &std::path::Path, session_id: &str) {
    use treeship_core::merkle::checkpoint::{Checkpoint, ChainProofSummary};

    let merkle_dir = home::home_dir()
        .unwrap_or_default()
        .join(".treeship")
        .join("merkle")
        .join("checkpoints");

    let latest_path = merkle_dir.join("latest.json");
    if !latest_path.exists() {
        daemon_log(ts, "no checkpoint found to update with proof");
        return;
    }

    let bytes = match std::fs::read(&latest_path) {
        Ok(b) => b,
        Err(e) => {
            daemon_log(ts, &format!("failed to read checkpoint: {}", e));
            return;
        }
    };

    let mut checkpoint: Checkpoint = match serde_json::from_slice(&bytes) {
        Ok(cp) => cp,
        Err(e) => {
            daemon_log(ts, &format!("failed to parse checkpoint: {}", e));
            return;
        }
    };

    // Load the proof result
    let proof_path = format!("{}.chain.zkproof", session_id);
    if let Ok(proof_bytes) = std::fs::read(&proof_path) {
        if let Ok(proof) = serde_json::from_slice::<treeship_zk_risc0::ChainProofResult>(&proof_bytes) {
            let now = super::prove::now_rfc3339_approx();
            checkpoint.zk_proof = Some(ChainProofSummary {
                image_id: proof.image_id.clone(),
                // Only report what the zkVM actually verified.
                // chain_intact and all_digests_valid come from the proof.
                // Signature and nonce checks are NOT yet part of the
                // RISC Zero guest, so we report false to stay honest.
                all_signatures_valid: false,   // not verified in zkVM yet
                chain_intact: proof.chain_intact,
                approval_nonces_matched: false, // not verified in zkVM yet
                artifact_count: proof.artifact_count as u64,
                public_key_digest: String::new(),
                proved_at: now,
            });

            // Write updated checkpoint back
            if let Ok(updated) = serde_json::to_vec_pretty(&checkpoint) {
                let _ = std::fs::write(&latest_path, updated);
                daemon_log(ts, &format!("checkpoint updated with proof for {}", session_id));
            }
        }
    }
}

/// Enqueue a proof job. Called by session close when zk.auto_prove is enabled.
#[cfg(feature = "zk")]
pub fn enqueue_proof_job(session_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    enqueue_proof_job_with_root(session_id, None, None)
}

/// Enqueue a proof job with the session's root_artifact_id and tip preserved.
/// The root ID is needed by the daemon to know where the chain starts,
/// and the tip ID captures the chain head at session close time, since
/// session.json and .last may change after this call.
#[cfg(feature = "zk")]
pub fn enqueue_proof_job_with_root(
    session_id: &str,
    root_artifact_id: Option<&str>,
    tip_artifact_id: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let ts = ts_dir().ok_or("no .treeship directory found")?;
    let queue_dir = ts.join("proof_queue");
    std::fs::create_dir_all(&queue_dir)?;

    let job = serde_json::json!({
        "session_id": session_id,
        "root_artifact_id": root_artifact_id,
        "tip_artifact_id": tip_artifact_id,
        "created_at": crate::commands::prove::now_rfc3339_approx(),
    });

    let job_path = queue_dir.join(format!("{}.json", session_id));
    std::fs::write(&job_path, serde_json::to_vec_pretty(&job)?)?;

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn diff_detects_new_files_as_writes() {
        let old: HashMap<PathBuf, FileTimes> = HashMap::new();
        let mut new = HashMap::new();
        new.insert(
            PathBuf::from("src/main.rs"),
            FileTimes { mtime: t(100), atime: t(100) },
        );

        let diff = diff_snapshots(&old, &new);
        assert_eq!(diff.written.len(), 1);
        assert_eq!(diff.read.len(), 0);
        assert_eq!(diff.written[0], PathBuf::from("src/main.rs"));
    }

    #[test]
    fn diff_detects_mtime_advance_as_write() {
        // When only mtime changes (atime stays the same), it's a pure write.
        let path = PathBuf::from("src/lib.rs");
        let mut old = HashMap::new();
        old.insert(path.clone(), FileTimes { mtime: t(100), atime: t(100) });
        let mut new = HashMap::new();
        new.insert(path.clone(), FileTimes { mtime: t(200), atime: t(100) });

        let diff = diff_snapshots(&old, &new);
        assert_eq!(diff.written.len(), 1);
        assert_eq!(diff.read.len(), 0);
    }

    #[test]
    fn diff_detects_atime_advance_only_as_read() {
        // mtime stays the same, atime advances -- pure read
        let path = PathBuf::from(".env");
        let mut old = HashMap::new();
        old.insert(path.clone(), FileTimes { mtime: t(100), atime: t(100) });
        let mut new = HashMap::new();
        new.insert(path.clone(), FileTimes { mtime: t(100), atime: t(150) });

        let diff = diff_snapshots(&old, &new);
        assert_eq!(diff.written.len(), 0);
        assert_eq!(diff.read.len(), 1);
        assert_eq!(diff.read[0], PathBuf::from(".env"));
    }

    #[test]
    fn diff_ignores_unchanged_files() {
        let path = PathBuf::from("README.md");
        let mut old = HashMap::new();
        old.insert(path.clone(), FileTimes { mtime: t(100), atime: t(100) });
        let mut new = HashMap::new();
        new.insert(path.clone(), FileTimes { mtime: t(100), atime: t(100) });

        let diff = diff_snapshots(&old, &new);
        assert_eq!(diff.written.len(), 0);
        assert_eq!(diff.read.len(), 0);
    }

    #[test]
    fn diff_emits_both_write_and_read_when_both_change() {
        // When mtime AND atime both advance, the file appears in BOTH
        // lists so on:access rules still fire even when a write happened
        // concurrently (e.g. touch after a secret read).
        let path = PathBuf::from("src/foo.rs");
        let mut old = HashMap::new();
        old.insert(path.clone(), FileTimes { mtime: t(100), atime: t(100) });
        let mut new = HashMap::new();
        new.insert(path.clone(), FileTimes { mtime: t(200), atime: t(250) });

        let diff = diff_snapshots(&old, &new);
        assert_eq!(diff.written.len(), 1);
        assert_eq!(diff.read.len(), 1);
    }

    #[test]
    fn matches_access_rule_uses_on_field() {
        let yaml = r#"
treeship:
  version: 1
session:
  actor: "human://test"
attest:
  paths:
    - path: "*.env*"
      on: "access"
      label: "env file access"
      alert: true
    - path: "src/**"
      on: "write"
      label: "code change"
"#;
        let project = ProjectConfig::from_yaml(yaml).unwrap();
        assert!(matches_access_rule(&project, ".env"));
        assert!(matches_access_rule(&project, ".env.local"));
        assert!(!matches_access_rule(&project, "src/main.rs")); // write rule, not access
        assert!(!matches_access_rule(&project, "README.md"));   // no rule
    }
}
