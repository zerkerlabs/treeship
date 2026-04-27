use std::path::{Path, PathBuf};

use treeship_core::{
    attestation::sign,
    session::{
        self, EventLog, EventType, SessionEvent, ReceiptComposer,
        build_package,
        event::{generate_event_id, generate_span_id, generate_trace_id},
    },
    statements::{ActionStatement, payload_type},
    storage::Record,
};

// Re-export the core SessionManifest so status.rs and others keep working.
pub use treeship_core::session::SessionManifest;

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

fn sessions_dir() -> Option<PathBuf> {
    session_dir().map(|d| d.join("sessions"))
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

    // Crash recovery: if session.json is missing but session.closing exists,
    // a prior `session close` was interrupted after freezing but before the
    // package was written. Restore the manifest so a retry of `session close`
    // can finish the job.
    if !path.exists() {
        if let Some(ts_dir) = path.parent() {
            let closing = ts_dir.join("session.closing");
            if closing.exists() {
                let _ = std::fs::rename(&closing, &path);
            }
        }
    }

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

/// Get the host ID for the current machine.
pub(crate) fn local_host_id() -> String {
    // Use PropagationContext's approach: read from env or derive from hostname
    std::env::var("TREESHIP_HOST_ID").unwrap_or_else(|_| {
        std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|h| format!("host_{}", h.trim().replace('.', "_")))
            .unwrap_or_else(|| "host_unknown".into())
    })
}

/// Create a base SessionEvent for this session.
fn base_event(
    session_id: &str,
    agent_id: &str,
    agent_instance_id: &str,
    agent_name: &str,
    trace_id: &str,
    host_id: &str,
    event_type: EventType,
) -> SessionEvent {
    SessionEvent {
        session_id: session_id.into(),
        event_id: generate_event_id(),
        timestamp: now_rfc3339(),
        sequence_no: 0, // Set by EventLog::append
        trace_id: trace_id.into(),
        span_id: generate_span_id(),
        parent_span_id: None,
        agent_id: agent_id.into(),
        agent_instance_id: agent_instance_id.into(),
        agent_name: agent_name.into(),
        agent_role: Some("operator".into()),
        host_id: host_id.into(),
        tool_runtime_id: None,
        event_type,
        artifact_ref: None,
        meta: None,
    }
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
    let trace_id = generate_trace_id();
    let host_id = local_host_id();

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

    // Write session manifest (using core SessionManifest)
    let manifest = SessionManifest::new(
        session_id.clone(),
        actor_uri.clone(),
        now.clone(),
        now_ms,
    );
    let mut manifest = manifest;
    manifest.name = name.clone();
    manifest.root_artifact_id = Some(result.artifact_id.clone());
    manifest.authorized_tools = super::declare::read_authorized_tools();

    let session_path = ts_dir.join("session.json");
    let json = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(&session_path, &json)?;
    set_restrictive_permissions(&session_path);

    // Initialize event log and write session.started event
    let evt_dir = ts_dir.join("sessions").join(&session_id);
    let event_log = EventLog::open(&evt_dir)?;
    let mut evt = base_event(
        &session_id, &actor_uri, "operator", "treeship-cli",
        &trace_id, &host_id, EventType::SessionStarted,
    );
    event_log.append(&mut evt)?;

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

/// Quiet existence probe for shell scripts. Prints nothing.
/// Exit 0 if a session is active, exit 1 if not.
///
/// Used by hooks (SessionStart, SessionEnd, PostToolUse) and monitors that
/// need to gate behavior on "is there an active session right now?" without
/// the noise of full `session status` output. The default `status` command
/// returns Ok(()) in both branches (it's a human-facing report), which is
/// the wrong shape for shell-script `if` checks -- they would always pass.
///
/// Note: takes no config argument because `load_session()` reads the
/// project-local session marker directly from cwd, not from the global
/// config. This intentionally diverges from `status` (which opens the
/// config-backed Ctx for verifying receipt integrity); for a pure
/// existence probe we don't need the full context.
pub fn status_check() -> Result<(), Box<dyn std::error::Error>> {
    if load_session().is_some() {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

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

    // Check event log
    let evt_dir = session_dir()
        .map(|d| d.join("sessions").join(&manifest.session_id));
    let event_count = evt_dir
        .and_then(|d| EventLog::open(&d).ok())
        .map(|log| log.event_count())
        .unwrap_or(0);

    printer.blank();
    printer.section("session");
    printer.info(&format!("  id:        {}", manifest.session_id));
    if let Some(ref name) = manifest.name {
        printer.info(&format!("  name:      {}", name));
    }
    printer.info(&format!("  actor:     {}", manifest.actor));
    printer.info(&format!("  started:   {} ({} ago)", manifest.started_at, elapsed_str));
    printer.info(&format!("  receipts:  {} (verified from chain)", artifact_count));
    printer.info(&format!("  events:    {}", event_count));
    printer.blank();
    printer.hint("treeship session close --summary \"what was done\"");
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// session status --watch (live TUI)
// ---------------------------------------------------------------------------

pub fn watch(
    config: Option<&str>,
    _printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::collections::BTreeMap;

    /// Strip terminal escape sequences and control characters from a string
    /// to prevent injected ANSI codes from hijacking the TUI display.
    fn sanitize(s: &str) -> String {
        s.chars().filter(|c| !c.is_control() || *c == '\n').collect()
    }

    /// UTF-8-safe truncation: truncate to at most `max` chars, not bytes.
    fn trunc(s: &str, max: usize) -> String {
        let truncated: String = s.chars().take(max).collect();
        if s.chars().count() > max { format!("{}...", truncated) } else { truncated }
    }

    /// Guard that disables raw mode on drop (panic, error, or clean exit).
    struct RawModeGuard(bool);
    impl Drop for RawModeGuard {
        fn drop(&mut self) {
            if self.0 { let _ = crossterm::terminal::disable_raw_mode(); }
        }
    }

    let manifest = match load_session() {
        Some(m) => m,
        None => return Err("no active session -- run treeship session start first".into()),
    };

    let ts_dir = session_dir().ok_or("no .treeship directory found")?;
    let evt_dir = ts_dir.join("sessions").join(&manifest.session_id);

    // Setup: enable raw mode for clean Ctrl+C via crossterm event polling.
    // RawModeGuard ensures raw mode is disabled on any exit path (panic, error, clean).
    let is_tty = crossterm::tty::IsTty::is_tty(&std::io::stdout());
    let _guard = if is_tty {
        crossterm::terminal::enable_raw_mode()?;
        RawModeGuard(true)
    } else {
        RawModeGuard(false)
    };

    let mut stdout = std::io::stdout();
    let mut last_count = 0u64;

    loop {
        // Read events
        let log = match EventLog::open(&evt_dir) {
            Ok(l) => l,
            Err(_) => { std::thread::sleep(std::time::Duration::from_secs(2)); continue; }
        };
        let events = log.read_all().unwrap_or_default();
        let event_count = events.len();

        // Compute agent stats
        let mut agents: BTreeMap<String, (String, String, u32, u64, u64)> = BTreeMap::new(); // name -> (model, role, actions, tok_in, tok_out)
        for e in &events {
            let entry = agents.entry(e.agent_instance_id.clone()).or_insert_with(|| {
                (String::new(), String::new(), 0, 0, 0)
            });
            if entry.0.is_empty() { entry.0 = e.agent_name.clone(); }
            if entry.1.is_empty() { entry.1 = e.agent_role.clone().unwrap_or_default(); }
            match &e.event_type {
                EventType::AgentCalledTool { .. } | EventType::AgentCompletedProcess { .. } => { entry.2 += 1; }
                EventType::AgentDecision { model, tokens_in, tokens_out, .. } => {
                    if let Some(m) = model { if !m.is_empty() { entry.0 = m.clone(); } }
                    if let Some(t) = tokens_in { entry.3 += t; }
                    if let Some(t) = tokens_out { entry.4 += t; }
                }
                _ => {}
            }
        }

        // Compute security stats
        let sensitive_reads = events.iter().filter(|e| {
            matches!(&e.event_type, EventType::AgentReadFile { file_path, .. } if
                file_path.contains(".env") || file_path.contains(".ssh") || file_path.contains(".pem") || file_path.contains(".aws"))
        }).count();
        let external_calls = events.iter().filter(|e| matches!(&e.event_type, EventType::AgentConnectedNetwork { .. })).count();
        let failed_cmds = events.iter().filter(|e| {
            matches!(&e.event_type, EventType::AgentCompletedProcess { exit_code: Some(c), .. } if *c != 0)
        }).count();

        // Artifact count (from chain, approximate from events)
        let artifact_count = events.iter().filter(|e| e.artifact_ref.is_some()).count();

        // Clear screen and render
        write!(stdout, "\x1b[2J\x1b[H")?; // clear + home

        // Header
        let elapsed_ms = epoch_ms().saturating_sub(manifest.started_at_ms);
        let elapsed_str = format_duration_ms(elapsed_ms);
        writeln!(stdout, "\x1b[1m SESSION: {}\x1b[0m  \x1b[90m{}\x1b[0m  \x1b[32m{} ago\x1b[0m\r",
            manifest.name.as_deref().unwrap_or("unnamed"),
            manifest.session_id,
            elapsed_str,
        )?;
        writeln!(stdout, "\x1b[90m{}\x1b[0m\r", "\u{2500}".repeat(70))?;
        writeln!(stdout, "\r")?;

        // Agent table
        let colors = ["\x1b[35m", "\x1b[33m", "\x1b[36m", "\x1b[34m", "\x1b[31m"];
        for (i, (id, (name, _role, actions, ti, to))) in agents.iter().enumerate() {
            let c = colors[i % colors.len()];
            let display_name = if name.is_empty() { id.as_str() } else { name.as_str() };
            writeln!(stdout, " {c}\u{25cf}\x1b[0m {:<28} {:>4}      {}k/{}k\r",
                trunc(&sanitize(display_name), 28), actions, ti/1000, to/1000)?;
        }
        writeln!(stdout, "\r")?;

        // Live events (last 15)
        writeln!(stdout, "\x1b[1m LIVE EVENTS\x1b[0m\r")?;
        let start = if events.len() > 15 { events.len() - 15 } else { 0 };
        for e in &events[start..] {
            let time = &e.timestamp[11..19.min(e.timestamp.len())];
            let agent = trunc(&sanitize(&e.agent_name), 14);
            let (ev_label, detail) = match &e.event_type {
                EventType::SessionStarted => ("start".to_string(), "session opened".to_string()),
                EventType::SessionClosed { summary, .. } => ("closed".to_string(), summary.clone().unwrap_or_default()),
                EventType::AgentCalledTool { tool_name, duration_ms, .. } => {
                    (tool_name.clone(), format!("{}ms", duration_ms.unwrap_or(0)))
                }
                EventType::AgentCompletedProcess { process_name, exit_code, duration_ms, .. } => {
                    let status = if *exit_code == Some(0) { "\x1b[32m\u{2713}\x1b[0m" } else { "\x1b[31m\u{2717}\x1b[0m" };
                    (process_name.clone(), format!("{} {}ms", status, duration_ms.unwrap_or(0)))
                }
                EventType::AgentDecision { model, provider, .. } => {
                    let detail = match (model, provider) {
                        (Some(m), Some(p)) => format!("{} via {}", m, p),
                        (Some(m), None) => m.clone(),
                        (None, Some(p)) => format!("via {}", p),
                        (None, None) => String::new(),
                    };
                    ("decision".to_string(), detail)
                }
                EventType::AgentWroteFile { file_path, operation, .. } => {
                    (operation.clone().unwrap_or_else(|| "write".into()), file_path.clone())
                }
                EventType::AgentReadFile { file_path, .. } => ("read".to_string(), file_path.clone()),
                EventType::AgentConnectedNetwork { destination, .. } => ("network".to_string(), destination.clone()),
                EventType::AgentHandoff { to_agent_instance_id, .. } => ("handoff \u{2192}".to_string(), to_agent_instance_id.clone()),
                _ => ("event".to_string(), String::new()),
            };
            let detail_short = trunc(&sanitize(&detail), 40);
            let ev_short = trunc(&sanitize(&ev_label), 14);
            writeln!(stdout, " \x1b[90m{}\x1b[0m  {:<14} \x1b[36m{:<14}\x1b[0m {}\r",
                time, agent, ev_short, detail_short)?;
        }
        writeln!(stdout, "\r")?;

        // Security summary
        writeln!(stdout, "\x1b[1m SECURITY\x1b[0m\r")?;
        let sr = if sensitive_reads == 0 { format!("\x1b[32m\u{2713} 0 sensitive reads\x1b[0m") }
                 else { format!("\x1b[33m\u{26a0} {} sensitive read{}\x1b[0m", sensitive_reads, if sensitive_reads > 1 { "s" } else { "" }) };
        let ec = if external_calls == 0 { format!("\x1b[32m\u{2713} 0 external calls\x1b[0m") }
                 else { format!("\x1b[33m\u{26a0} {} external call{}\x1b[0m", external_calls, if external_calls > 1 { "s" } else { "" }) };
        let fc = if failed_cmds == 0 { format!("\x1b[32m\u{2713} 0 failed commands\x1b[0m") }
                 else { format!("\x1b[31m\u{2717} {} failed command{}\x1b[0m", failed_cmds, if failed_cmds > 1 { "s" } else { "" }) };
        writeln!(stdout, " {}    {}    {}\r", sr, ec, fc)?;
        writeln!(stdout, "\r")?;

        // Merkle progress
        writeln!(stdout, "\x1b[1m VERIFICATION\x1b[0m\r")?;
        writeln!(stdout, " Events: {}    Artifacts: {}    Signatures: {}\r",
            event_count, artifact_count, artifact_count)?;
        writeln!(stdout, "\r")?;
        writeln!(stdout, " \x1b[90mPolling every 2s. Press Ctrl+C to exit.\x1b[0m\r")?;

        stdout.flush()?;
        last_count = event_count as u64;

        // If not a TTY, render one frame and exit
        if !is_tty {
            let _ = crossterm::terminal::disable_raw_mode();
            return Ok(());
        }

        // Wait 2 seconds, but check for Ctrl+C / 'q' every 100ms
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() { break; }
            if crossterm::event::poll(remaining.min(std::time::Duration::from_millis(100)))? {
                if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                    use crossterm::event::KeyCode;
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('c')
                            if key.modifiers.contains(crossterm::event::KeyModifiers::CONTROL)
                               || key.code == KeyCode::Char('q') => {
                            // _guard Drop handles disable_raw_mode
                            println!();
                            return Ok(());
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// session close
// ---------------------------------------------------------------------------

pub fn close(
    summary: Option<String>,
    headline: Option<String>,
    review: Option<String>,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = match load_session() {
        Some(m) => m,
        None => {
            return Err("no active session to close\n\n  Fix: treeship session start --name \"my task\"".into());
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
    let trace_id = generate_trace_id();
    let host_id = local_host_id();

    // Write session.closed event to the event log
    let ts_dir = session_dir().ok_or("no .treeship directory found")?;
    let evt_dir = ts_dir.join("sessions").join(&manifest.session_id);
    let event_log = EventLog::open(&evt_dir)?;

    let mut close_evt = base_event(
        &manifest.session_id, &manifest.actor, "operator", "treeship-cli",
        &trace_id, &host_id,
        EventType::SessionClosed {
            summary: summary.clone(),
            duration_ms: Some(elapsed_ms),
        },
    );
    event_log.append(&mut close_evt)?;

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

    // ── Freeze the session: rename session.json to session.closing ──
    // so the daemon's load_active_session() returns None and stops
    // appending events. This must happen BEFORE reading the event log
    // so no late daemon events sneak in between read_all() and receipt
    // composition.
    //
    // We rename instead of deleting so a crash between here and the
    // successful package write leaves a recoverable marker. On the next
    // `session close` or `session start`, the presence of
    // session.closing signals an incomplete close that can be retried.
    let closing_marker = session_dir()
        .map(|d| d.join("session.closing"));
    if let Some(ref path) = session_path() {
        if let Some(ref marker) = closing_marker {
            let _ = std::fs::rename(path, marker);
        } else {
            let _ = std::fs::remove_file(path);
        }
    }

    // ── Compose Session Receipt and build .treeship package ─────────
    let events = event_log.read_all().unwrap_or_default();

    // Build artifact entries from the chain
    let artifact_entries: Vec<session::receipt::ArtifactEntry> = collect_artifact_entries(&ctx, &manifest);

    // Update manifest for receipt composition
    let mut receipt_manifest = manifest.clone();
    receipt_manifest.status = session::SessionStatus::Completed;
    receipt_manifest.closed_at = Some(now_rfc3339());
    receipt_manifest.summary = summary.clone();

    let mut receipt = ReceiptComposer::compose(&receipt_manifest, &events, artifact_entries);

    // Override narrative with explicit --headline/--review if provided
    if headline.is_some() || review.is_some() {
        let existing = receipt.session.narrative.take().unwrap_or_default();
        receipt.session.narrative = Some(session::receipt::Narrative {
            headline: headline.or(existing.headline),
            summary: existing.summary,
            review: review.or(existing.review),
        });
    }

    // Check for ZK proof files in the session directory or proof_queue.
    // If any .zkproof files exist, set zk_proofs_present = true.
    let zk_present = has_zk_proofs(&ts_dir, &manifest.session_id);
    if zk_present {
        receipt.proofs.zk_proofs_present = true;
    }

    // Build the .treeship package. We capture the path into an Option
    // outside the match so the post-close hints (rendered below the
    // session summary) can reference it as a copy-pasteable argument
    // for `treeship package verify`. Falls back to None if package
    // composition failed; the hint logic below skips local-verify in
    // that case rather than printing a path that doesn't exist.
    let pkg_dir = ts_dir.join("sessions");
    std::fs::create_dir_all(&pkg_dir)?;
    let mut sealed_pkg_path: Option<std::path::PathBuf> = None;

    match build_package(&receipt, &pkg_dir) {
        Ok(pkg_output) => {
            // Package written successfully. Remove the closing marker
            // so start/close don't see a stale incomplete-close signal.
            if let Some(ref marker) = closing_marker {
                let _ = std::fs::remove_file(marker);
            }
            printer.blank();
            printer.success("session receipt composed", &[]);
            printer.info(&format!("  package:   {}", pkg_output.path.display()));
            printer.info(&format!("  digest:    {}", pkg_output.receipt_digest));
            if let Some(ref root) = pkg_output.merkle_root {
                printer.info(&format!("  merkle:    {}", root));
            }
            printer.info(&format!("  files:     {}", pkg_output.file_count));

            sealed_pkg_path = Some(pkg_output.path.clone());

            // Auto-open preview.html if running in a terminal
            let preview_path = pkg_output.path.join("preview.html");
            if preview_path.exists() && crossterm::tty::IsTty::is_tty(&std::io::stdout()) {
                #[cfg(target_os = "macos")]
                { let _ = std::process::Command::new("open").arg(&preview_path).spawn(); }
                #[cfg(target_os = "linux")]
                { let _ = std::process::Command::new("xdg-open").arg(&preview_path).spawn(); }
            }
        }
        Err(e) => {
            printer.warn(&format!("failed to build .treeship package: {e}"), &[]);
            printer.warn("session.closing marker left in place for recovery -- re-run session close to retry", &[]);
        }
    }

    // ── OTel export (best-effort, never fails the close) ────────────
    #[cfg(feature = "otel")]
    {
        if let Some(otel_config) = crate::otel::config::OtelConfig::from_env() {
            let record = ctx.storage.read(&result.artifact_id);
            if let Ok(ref rec) = record {
                let _ = crate::otel::exporter::export_artifact(&otel_config, rec);
            }
        }
    }

    // Print output
    let elapsed_str = format_duration_ms(elapsed_ms);

    printer.blank();
    printer.success("session closed", &[]);
    printer.info(&format!("  id:       {}", manifest.session_id));
    printer.info(&format!("  duration: {}", elapsed_str));
    printer.info(&format!("  receipts: {}", artifact_count));
    printer.info(&format!("  events:   {}", event_log.event_count()));
    printer.blank();

    // Next-step hints. The two paths a user has after a successful
    // close are: (a) verify the sealed receipt locally with no hub
    // dependency, or (b) publish to a hub and get a shareable URL.
    // Surface BOTH so a user who doesn't have a hub attached doesn't
    // hit a dead end, and a user who does isn't pushed toward the
    // local-only path. Falls back to the prior single-artifact hints
    // if package composition failed (sealed_pkg_path is None).
    if let Some(ref pkg_path) = sealed_pkg_path {
        printer.hint(&format!(
            "treeship package verify {}  to verify locally (no hub needed)",
            pkg_path.display(),
        ));
        printer.hint("treeship session report                                              to publish + get a shareable URL (requires `treeship hub attach`)");
    } else {
        printer.hint(&format!("treeship verify {} --full  to see the chain", result.artifact_id));
        printer.hint(&format!("treeship hub push {}      to share", result.artifact_id));
    }

    // ZK: Enqueue chain proof BEFORE deleting session.json so the proof
    // job captures root_artifact_id (the daemon needs it to bound the chain).
    // Also capture the current tip (.last) so the prover walks the correct
    // chain even if new artifacts are appended after session close.
    #[cfg(feature = "zk")]
    {
        let tip_id = resolve_last(&ctx.config.storage_dir);
        if let Ok(()) = super::daemon::enqueue_proof_job_with_root(
            &manifest.session_id,
            manifest.root_artifact_id.as_deref(),
            tip_id.as_deref(),
        ) {
            printer.dim_info("  chain proof queued (generating in background)");
        }
    }

    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// session event -- append a structured event to the active session's log
// ---------------------------------------------------------------------------

pub fn event(
    event_type: &str,
    tool: Option<&str>,
    file: Option<&str>,
    destination: Option<&str>,
    actor: Option<&str>,
    agent_name: Option<&str>,
    duration_ms: Option<u64>,
    exit_code: Option<i32>,
    artifact_id: Option<&str>,
    meta_json: Option<&str>,
    // Inference attribution. Used by agent.decision events to populate
    // AgentNode.model / .provider / .tokens_in / .tokens_out in the
    // session graph. Each falls back to its TREESHIP_* env var (mirrors
    // the wrap command's env handling) so integration hooks can set
    // them once at session start instead of per-event.
    model_arg: Option<&str>,
    provider_arg: Option<&str>,
    tokens_in_arg: Option<u64>,
    tokens_out_arg: Option<u64>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = match load_session() {
        Some(m) => m,
        None => return Err("no active session -- run treeship session start first".into()),
    };

    let ts_dir = session_dir().ok_or("no .treeship directory found")?;
    let evt_dir = ts_dir.join("sessions").join(&manifest.session_id);
    let event_log = EventLog::open(&evt_dir)?;

    let actor_uri = actor.unwrap_or(&manifest.actor);
    let host_id = local_host_id();
    let trace_id = generate_trace_id();
    let a_name = agent_name.unwrap_or("external");

    let et = match event_type {
        "agent.called_tool" => EventType::AgentCalledTool {
            tool_name: tool.unwrap_or("unknown").into(),
            tool_input_digest: None,
            tool_output_digest: None,
            duration_ms,
        },
        "agent.wrote_file" => EventType::AgentWroteFile {
            file_path: file.unwrap_or("unknown").into(),
            digest: None,
            operation: None,
            additions: None,
            deletions: None,
        },
        "agent.read_file" => EventType::AgentReadFile {
            file_path: file.unwrap_or("unknown").into(),
            digest: None,
        },
        "agent.connected_network" => EventType::AgentConnectedNetwork {
            destination: destination.unwrap_or("unknown").into(),
            port: None,
        },
        "agent.completed_process" => EventType::AgentCompletedProcess {
            process_name: tool.unwrap_or("unknown").into(),
            exit_code,
            duration_ms,
            command: None,
        },
        "agent.decision" => {
            // Resolve each field from CLI flag, then env var fallback.
            // Mirrors the precedence the wrap command uses (see
            // commands/wrap.rs::read_decision_env). When neither is set,
            // the field stays None and the receipt simply won't surface
            // it -- caller is responsible for at least providing model.
            let model = model_arg.map(|s| s.to_string())
                .or_else(|| std::env::var("TREESHIP_MODEL").ok());
            let provider = provider_arg.map(|s| s.to_string())
                .or_else(|| std::env::var("TREESHIP_PROVIDER").ok());
            let tokens_in = tokens_in_arg
                .or_else(|| std::env::var("TREESHIP_TOKENS_IN").ok().and_then(|s| s.parse().ok()));
            let tokens_out = tokens_out_arg
                .or_else(|| std::env::var("TREESHIP_TOKENS_OUT").ok().and_then(|s| s.parse().ok()));

            if model.is_none() {
                return Err("agent.decision events require --model (or TREESHIP_MODEL env var)".into());
            }

            EventType::AgentDecision {
                model,
                tokens_in,
                tokens_out,
                provider,
                summary: None,
                confidence: None,
            }
        }
        "agent.handoff" => EventType::AgentHandoff {
            from_agent_instance_id: actor_uri.into(),
            to_agent_instance_id: destination.unwrap_or("unknown").into(),
            artifacts: artifact_id.map(|id| vec![id.into()]).unwrap_or_default(),
        },
        other => {
            return Err(format!("unsupported event type: {other}\n\n  supported: agent.called_tool, agent.wrote_file, agent.read_file, agent.connected_network, agent.completed_process, agent.decision, agent.handoff").into());
        }
    };

    // Merge caller-provided meta with a source marker so receipts can
    // distinguish externally-emitted events from daemon or wrap events.
    // This is NOT a security boundary -- same-user local access is the
    // trust domain, matching the single-key architecture.
    let mut meta_obj = meta_json
        .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    meta_obj.insert("source".into(), serde_json::json!("session-event-cli"));
    let meta = Some(serde_json::Value::Object(meta_obj));

    let mut evt = SessionEvent {
        session_id: manifest.session_id.clone(),
        event_id: generate_event_id(),
        timestamp: now_rfc3339(),
        sequence_no: 0,
        trace_id,
        span_id: generate_span_id(),
        parent_span_id: None,
        agent_id: actor_uri.into(),
        agent_instance_id: a_name.into(),
        agent_name: a_name.into(),
        agent_role: Some("agent".into()),
        host_id,
        tool_runtime_id: None,
        event_type: et,
        artifact_ref: artifact_id.map(|s| s.into()),
        meta,
    };

    event_log.append(&mut evt)?;

    // Output JSON for machine consumption
    let output = serde_json::json!({
        "event_id": evt.event_id,
        "session_id": manifest.session_id,
        "sequence_no": evt.sequence_no,
    });

    printer.info(&serde_json::to_string(&output).unwrap_or_default());

    Ok(())
}

/// Check if ZK proof files exist for this session.
/// Looks for .zkproof files in the .treeship directory and proof_queue.
fn has_zk_proofs(ts_dir: &Path, session_id: &str) -> bool {
    // Check proof_queue for completed proofs
    let queue_dir = ts_dir.join("proof_queue");
    if queue_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&queue_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                if name_str.contains(session_id) && name_str.ends_with(".zkproof") {
                    return true;
                }
            }
        }
    }

    // Check for any .zkproof file with the session_id prefix
    let session_dir = ts_dir.join("sessions").join(session_id);
    if session_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&session_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().ends_with(".zkproof") {
                    return true;
                }
            }
        }
    }

    // Check in the storage directory for session-scoped proof files
    let proof_file = format!("{}.chain.zkproof", session_id);
    if ts_dir.join(&proof_file).exists() {
        return true;
    }

    false
}

// ---------------------------------------------------------------------------
// Collect artifact entries from the chain for receipt composition
// ---------------------------------------------------------------------------

fn collect_artifact_entries(
    ctx: &ctx::Ctx,
    manifest: &SessionManifest,
) -> Vec<session::receipt::ArtifactEntry> {
    let root_id = match &manifest.root_artifact_id {
        Some(id) => id.clone(),
        None => return Vec::new(),
    };

    // Walk chain from .last back to root
    let last_path = Path::new(&ctx.config.storage_dir).join(".last");
    let current_id = match std::fs::read_to_string(&last_path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return Vec::new(),
    };

    let mut cursor = current_id;
    let mut collected = Vec::new();
    for _ in 0..1000 {
        match ctx.storage.read(&cursor) {
            Ok(record) => {
                collected.push(session::receipt::ArtifactEntry {
                    artifact_id: record.artifact_id.clone(),
                    payload_type: record.payload_type.clone(),
                    digest: Some(record.digest.clone()),
                    signed_at: Some(record.signed_at.clone()),
                });
                if cursor == root_id {
                    break;
                }
                match record.parent_id {
                    Some(pid) => cursor = pid,
                    None => break,
                }
            }
            Err(_) => break,
        }
    }

    // Reverse so entries are in chronological order (root first)
    collected.reverse();
    collected
}

// ---------------------------------------------------------------------------
// session report -- upload a session receipt to the configured hub
// ---------------------------------------------------------------------------

/// Locate the most recently closed `.treeship` package directory under
/// `.treeship/sessions/`. Sorts by the `session.ended_at` timestamp inside
/// `receipt.json` rather than filesystem mtime, so touching an older
/// package directory cannot cause the wrong session to be uploaded.
fn find_latest_package() -> Option<(PathBuf, String)> {
    let ts_dir = session_dir()?;
    let sessions_root = ts_dir.join("sessions");
    if !sessions_root.is_dir() {
        return None;
    }

    let mut latest: Option<(PathBuf, String, String)> = None; // (path, id, ended_at)
    for entry in std::fs::read_dir(&sessions_root).ok()?.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        if !path.is_dir() || !name_str.ends_with(".treeship") {
            continue;
        }
        let session_id = name_str.trim_end_matches(".treeship").to_string();
        let receipt_path = path.join("receipt.json");
        if !receipt_path.exists() {
            continue;
        }
        // Parse ended_at from the receipt for stable ordering.
        let ended_at = std::fs::read_to_string(&receipt_path)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| v["session"]["ended_at"].as_str().map(|s| s.to_string()))
            .unwrap_or_default();
        match &latest {
            None => latest = Some((path.clone(), session_id, ended_at)),
            Some((_, _, prev_ended)) if ended_at > *prev_ended => {
                latest = Some((path.clone(), session_id, ended_at));
            }
            _ => {}
        }
    }
    latest.map(|(p, id, _)| (p, id))
}

/// Locate the package directory for an explicit session_id.
fn find_package_for_session(session_id: &str) -> Option<PathBuf> {
    let ts_dir = session_dir()?;
    let pkg = ts_dir.join("sessions").join(format!("{session_id}.treeship"));
    if pkg.join("receipt.json").exists() {
        Some(pkg)
    } else {
        None
    }
}

pub fn report(
    session_id: Option<String>,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Resolve which package to upload.
    let (pkg_dir, resolved_id) = match session_id {
        Some(id) => {
            let pkg = find_package_for_session(&id)
                .ok_or_else(|| format!(
                    "no .treeship package found for session {id}\n\n  expected: .treeship/sessions/{id}.treeship/receipt.json"
                ))?;
            (pkg, id)
        }
        None => find_latest_package().ok_or(
            "no closed sessions found -- run `treeship session close` first",
        )?,
    };

    // 2. Read receipt.json bytes (we PUT them verbatim so the digest is preserved).
    let receipt_path = pkg_dir.join("receipt.json");
    let receipt_bytes = std::fs::read(&receipt_path)
        .map_err(|e| format!("failed to read {}: {e}", receipt_path.display()))?;

    // 3. Resolve the active hub connection.
    //
    // If the user hasn't attached a hub yet they'll hit this path right
    // after a successful `session close`, expecting `session report` to
    // "share the receipt." The default resolve_hub error mentions
    // `treeship hub attach` (a one-time browser flow), but that's a
    // commitment some users don't want to make. Wrap the error with
    // a session-report-specific recovery: hub attach for the share path,
    // OR `package verify` for fully-local verification of the same
    // sealed receipt. Either path keeps the receipt useful.
    let ctx = ctx::open(config)?;
    let (hub_name, hub_entry) = ctx
        .config
        .resolve_hub(None)
        .map_err(|e| -> Box<dyn std::error::Error> {
            format!(
                "{e}\n\n  \
                 To publish (one-time browser flow):\n    \
                 treeship hub attach\n    \
                 treeship session report\n\n  \
                 Or skip publishing and verify the sealed receipt locally:\n    \
                 treeship package verify {}",
                pkg_dir.display(),
            ).into()
        })?;

    let hub_secret_hex = hub_entry
        .hub_secret_key
        .as_deref()
        .ok_or_else(|| -> Box<dyn std::error::Error> {
            format!(
                "no hub_secret_key for connection '{hub_name}' -- run: treeship hub attach\n\n  \
                 Or verify the sealed receipt locally without publishing:\n    \
                 treeship package verify {}",
                pkg_dir.display(),
            ).into()
        })?;

    // 4. Build the PUT URL and DPoP proof.
    let put_url = format!("{}/v1/receipt/{}", hub_entry.endpoint, resolved_id);
    let dpop_jwt = super::hub::build_dpop_jwt(hub_secret_hex, "PUT", &put_url)?;

    // 5. Send the receipt body verbatim with content-type application/json.
    let resp = ureq::put(&put_url)
        .set("Authorization", &format!("DPoP {}", hub_entry.hub_id))
        .set("DPoP", &dpop_jwt)
        .set("Content-Type", "application/json")
        .send_bytes(&receipt_bytes);

    let resp_json: serde_json::Value = match resp {
        Ok(r) => r.into_json()?,
        Err(ureq::Error::Status(code, r)) => {
            let detail: serde_json::Value = r
                .into_json()
                .unwrap_or_else(|_| serde_json::json!({"error": "unknown"}));
            let msg = detail["error"].as_str().unwrap_or("unknown error");
            return Err(format!("hub returned {code}: {msg}").into());
        }
        Err(e) => return Err(format!("failed to upload receipt: {e}").into()),
    };

    let receipt_url = resp_json["receipt_url"]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("https://treeship.dev/receipt/{resolved_id}"));
    let agents = resp_json["agents"].as_u64().unwrap_or(0);
    let events = resp_json["events"].as_u64().unwrap_or(0);

    printer.blank();
    printer.success("session receipt uploaded", &[]);
    printer.info(&format!("  hub:      {}", hub_name));
    printer.info(&format!("  session:  {}", resolved_id));
    printer.info(&format!("  agents:   {}", agents));
    printer.info(&format!("  events:   {}", events));
    printer.blank();
    printer.info(&format!("  receipt:  {}", receipt_url));
    printer.blank();
    printer.hint("share this URL freely -- it never expires and needs no auth");
    printer.blank();

    Ok(())
}
