use std::io::{BufRead, BufReader};
use std::process;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use sha2::{Sha256, Digest};

use treeship_core::{
    attestation::sign,
    session::{
        EventLog, EventType, SessionEvent,
        event::{generate_event_id, generate_span_id, generate_trace_id},
    },
    statements::{ActionStatement, payload_type},
    storage::Record,
};

use crate::{ctx, printer::Printer};

/// Sanitize a command string by redacting tokens, keys, passwords, and other
/// sensitive values that appear as inline environment variables or flags.
fn sanitize_command(cmd: &str) -> String {
    let sensitive_patterns = [
        "KEY=", "TOKEN=", "SECRET=", "PASSWORD=", "PASSWD=", "AUTH=",
        "API_KEY=", "STRIPE_KEY=", "OPENAI_API_KEY=", "CREDENTIAL=",
        "AWS_SECRET", "PRIVATE_KEY=", "ACCESS_KEY=",
        "--api-key=", "--token=", "--secret=", "--password=", "--auth=",
        "--api_key=", "--apikey=",
    ];
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let sanitized: Vec<String> = parts.iter().map(|part| {
        let upper = part.to_uppercase();
        for pattern in &sensitive_patterns {
            if upper.contains(pattern) {
                return "[REDACTED]".to_string();
            }
        }
        part.to_string()
    }).collect();
    sanitized.join(" ")
}

pub fn run(
    actor:     Option<String>,
    action:    Option<String>,
    parent_id: Option<String>,
    push:      bool,
    config:    Option<&str>,
    args:      &[String],     // everything after --
    printer:   &Printer,
) -> Result<(), Box<dyn std::error::Error>> {

    if args.is_empty() {
        return Err(
            "no command given\n\n  usage: treeship wrap [flags] -- <command> [args...]".into()
        );
    }

    let ctx = ctx::open(config)?;

    // The action label defaults to the executable name
    let action_label = action.clone().unwrap_or_else(|| {
        std::path::Path::new(&args[0])
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&args[0])
            .to_string()
    });
    let actor_uri = actor.unwrap_or_else(|| format!("ship://{}", ctx.config.ship_id));

    // ── 2. Auto-chaining: resolve parent_id ────────────────────────────
    let parent_id = resolve_parent(&ctx, parent_id);

    // ── 3. File diff: snapshot git state before ─────────────────────────
    let git_before = git_head_sha();
    let files_before = file_mtimes(".");

    // ── 1. Output digest: capture stdout/stderr while streaming ────────
    let start = Instant::now();

    let mut child = process::Command::new(&args[0])
        .args(&args[1..])
        .stdin(process::Stdio::inherit())
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped())
        .spawn()?;

    // Accumulate output in a shared buffer while printing in real time
    let stdout_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let stderr_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let sb = Arc::clone(&stdout_buf);
    let stdout_thread = std::thread::spawn(move || {
        if let Some(pipe) = stdout_pipe {
            let reader = BufReader::new(pipe);
            for line in reader.lines() {
                if let Ok(l) = line {
                    println!("{}", l);
                    let mut buf = sb.lock().unwrap();
                    buf.extend_from_slice(l.as_bytes());
                    buf.push(b'\n');
                }
            }
        }
    });

    let eb = Arc::clone(&stderr_buf);
    let stderr_thread = std::thread::spawn(move || {
        if let Some(pipe) = stderr_pipe {
            let reader = BufReader::new(pipe);
            for line in reader.lines() {
                if let Ok(l) = line {
                    eprintln!("{}", l);
                    let mut buf = eb.lock().unwrap();
                    buf.extend_from_slice(l.as_bytes());
                    buf.push(b'\n');
                }
            }
        }
    });

    let status = child.wait();
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();

    let elapsed = start.elapsed();
    let elapsed_ms = elapsed.as_millis() as u64;

    let (exit_code, succeeded) = match &status {
        Ok(s)  => (s.code().unwrap_or(-1), s.success()),
        Err(_) => (-1, false),
    };

    // Compute output digest (SHA-256 of stdout + stderr)
    let stdout_data = stdout_buf.lock().unwrap();
    let stderr_data = stderr_buf.lock().unwrap();

    let mut hasher = Sha256::new();
    hasher.update(&*stdout_data);
    hasher.update(&*stderr_data);
    let output_hash = format!("sha256:{}", hex::encode(hasher.finalize()));

    let output_lines = bytecount_lines(&stdout_data) + bytecount_lines(&stderr_data);
    let output_summary = last_nonempty_line(&stdout_data);

    // ── 3. File diff: detect what changed ──────────────────────────────
    let git_after = git_head_sha();
    let files_after = file_mtimes(".");
    let changed_files = diff_files(&files_before, &files_after);
    let files_changed_count = changed_files.len();

    let files_modified: Vec<serde_json::Value> = changed_files.iter().map(|path| {
        let digest = file_sha256(path).unwrap_or_default();
        serde_json::json!({ "path": path, "digest": digest })
    }).collect();

    // Short summary of changed dirs for display
    let files_summary = if changed_files.is_empty() {
        String::new()
    } else {
        let dirs: Vec<String> = changed_files.iter()
            .take(3)
            .map(|p| {
                let path = std::path::Path::new(p);
                path.parent()
                    .and_then(|d| d.file_name())
                    .and_then(|n| n.to_str())
                    .map(|s| format!("{}/", s))
                    .unwrap_or_else(|| p.clone())
            })
            .collect();
        let unique: Vec<String> = {
            let mut seen = std::collections::HashSet::new();
            dirs.into_iter().filter(|d| seen.insert(d.clone())).collect()
        };
        format!("({})", unique.join(", "))
    };

    // ── Build meta and sign ────────────────────────────────────────────
    let raw_command = args.join(" ");
    let safe_command = sanitize_command(&raw_command);
    let mut meta = serde_json::json!({
        "command":        safe_command,
        "exitCode":       exit_code,
        "elapsedMs":      elapsed_ms,
        "output_digest":  output_hash,
        "output_lines":   output_lines,
    });

    if !output_summary.is_empty() {
        meta["output_summary"] = serde_json::Value::String(sanitize_command(&output_summary));
    }
    if files_changed_count > 0 {
        meta["files_changed"] = serde_json::json!(files_changed_count);
        meta["files_modified"] = serde_json::json!(files_modified);
    }
    if let Some(ref gb) = git_before {
        meta["git_before"] = serde_json::Value::String(gb.clone());
    }
    if let Some(ref ga) = git_after {
        meta["git_after"] = serde_json::Value::String(ga.clone());
    }

    let mut stmt = ActionStatement::new(&actor_uri, &action_label);
    stmt.parent_id = parent_id.clone();
    stmt.meta = Some(meta);

    let signer = ctx.keys.default_signer()?;
    let pt     = payload_type("action");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    parent_id.clone(),
        envelope:     result.envelope,
        hub_url:      None,
    })?;

    // ── 2. Auto-chaining: write .last ──────────────────────────────────
    write_last(&ctx.config.storage_dir, &result.artifact_id);

    // ── Emit session events (best-effort, never fails the wrap) ─────
    // If a session is active, emit process start/complete and file-write
    // events so they appear in the Session Receipt.
    emit_wrap_events(&safe_command, &action_label, exit_code, elapsed_ms, &changed_files);

    // ── AgentDecision from env vars (best-effort) ─────────────────
    // If TREESHIP_MODEL (or any of TREESHIP_TOKENS_IN, TREESHIP_TOKENS_OUT,
    // TREESHIP_COST_USD) is set, emit an AgentDecision event so model,
    // token counts, and cost flow into the receipt automatically.
    emit_decision_from_env();

    // ── OTel export (best-effort, never fails the wrap) ─────────────
    #[cfg(feature = "otel")]
    {
        if let Some(otel_config) = crate::otel::config::OtelConfig::from_env() {
            let record = ctx.storage.read(&result.artifact_id);
            if let Ok(ref rec) = record {
                if let Err(e) = crate::otel::exporter::export_artifact(&otel_config, rec) {
                    printer.dim_info(&format!("  otel: {}", e));
                }
            }
        }
    }

    // ── ZK auto-prove (when declaration is active) ──────────────────
    #[cfg(feature = "zk")]
    {
        // Check if there's a .treeship/declaration.json with bounded_actions
        let decl_path = std::path::Path::new(&ctx.config.storage_dir)
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("declaration.json");
        if decl_path.exists() {
            if let Ok(decl_content) = std::fs::read_to_string(&decl_path) {
                if let Ok(decl) = serde_json::from_str::<serde_json::Value>(&decl_content) {
                    if let Some(actions) = decl.get("bounded_actions").and_then(|a| a.as_array()) {
                        let allowed: Vec<String> = actions.iter()
                            .filter_map(|a| a.as_str().map(|s| s.to_string()))
                            .collect();
                        if !allowed.is_empty() {
                            // Write bounded_actions to a temp file so prove_circuit
                            // can load it as the policy path.
                            let policy_result = (|| -> std::result::Result<(), Box<dyn std::error::Error>> {
                                let tmp_dir = tempfile::tempdir()?;
                                let policy_path = tmp_dir.path().join("policy.json");
                                let policy_json = serde_json::to_vec_pretty(&allowed)?;
                                std::fs::write(&policy_path, &policy_json)?;
                                super::prove::prove_circuit(
                                    "policy-checker",
                                    &result.artifact_id,
                                    policy_path.to_str(),
                                    config,
                                    printer,
                                )?;
                                Ok(())
                            })();
                            if let Err(e) = policy_result {
                                printer.dim_info(&format!("  zk proof: {}", e));
                            }
                        }
                    }
                }
            }
        }
    }

    // ── 4. Wire --push ─────────────────────────────────────────────────
    let mut hub_url: Option<String> = None;
    if push {
        if ctx.config.is_attached() {
            match super::hub::push_artifact(&ctx, &result.artifact_id) {
                Ok(pr) => {
                    if !pr.hub_url.is_empty() {
                        hub_url = Some(pr.hub_url);
                    }
                }
                Err(e) => {
                    printer.warn("push failed", &[("error", &e.to_string())]);
                }
            }
        } else {
            printer.warn("not attached, skipping push", &[]);
        }
    }

    // ── 5. Rich CLI output ─────────────────────────────────────────────
    printer.blank();

    let short_id = &result.artifact_id;
    let short_hash = if output_hash.len() > 18 {
        &output_hash[..18]
    } else {
        &output_hash
    };
    let key_id_short = signer.key_id();

    let exit_label = if succeeded {
        "0  passed".to_string()
    } else {
        format!("{}  failed", exit_code)
    };

    let elapsed_str = format_elapsed(elapsed);

    // Output line
    let output_line = if output_summary.is_empty() {
        format!("{}  ({} lines)", short_hash, output_lines)
    } else {
        format!("{}  ({})", short_hash, output_summary)
    };

    // Chain line
    let chain_line = match &parent_id {
        Some(pid) => {
            let step = chain_depth(&ctx, pid);
            let pid_short = if pid.len() > 14 { &pid[..14] } else { pid };
            let aid_short = if short_id.len() > 14 { &short_id[..14] } else { short_id };
            format!("{} -> {}  (step {})", pid_short, aid_short, step)
        }
        None => "root".to_string(),
    };

    // Files line
    let files_line = if files_changed_count > 0 {
        format!("{} modified  {}", files_changed_count, files_summary)
    } else {
        "none detected".to_string()
    };

    let separator = "  ----------------------------------------";

    if succeeded {
        printer.info(&printer.green("+ receipt sealed"));
    } else {
        printer.info(&printer.yellow("+ receipt sealed (non-zero exit)"));
    }

    printer.dim_info(separator);
    printer.info(&format!("  id:       {}", short_id));
    printer.info(&format!("  command:  {}", args.join(" ")));
    printer.info(&format!("  exit:     {}", exit_label));
    printer.info(&format!("  elapsed:  {}", elapsed_str));
    printer.info(&format!("  output:   {}", output_line));
    printer.info(&format!("  files:    {}", files_line));
    printer.info(&format!("  chain:    {}", chain_line));
    printer.info(&format!("  signed:   {}  (ed25519)", key_id_short));

    if let Some(ref url) = hub_url {
        printer.info(&format!("  hub:      {}", url));
    }

    printer.dim_info(separator);
    printer.hint(&format!("treeship verify {}", result.artifact_id));
    if hub_url.is_none() && !push {
        printer.hint(&format!("treeship hub push {}", result.artifact_id));
    }
    printer.blank();

    // Propagate the subprocess exit code
    if let Ok(s) = status {
        if !s.success() {
            if let Some(code) = s.code() {
                process::exit(code);
            }
        }
    }

    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Resolve parent_id with priority: explicit flag > TREESHIP_PARENT env > .last file
fn resolve_parent(ctx: &ctx::Ctx, explicit: Option<String>) -> Option<String> {
    if explicit.is_some() {
        return explicit;
    }
    // Check TREESHIP_PARENT env var
    if let Ok(env_parent) = std::env::var("TREESHIP_PARENT") {
        if !env_parent.is_empty() {
            return Some(env_parent);
        }
    }
    // Read .last file from storage dir
    let last_path = std::path::Path::new(&ctx.config.storage_dir).join(".last");
    if let Ok(contents) = std::fs::read_to_string(&last_path) {
        let trimmed = contents.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    None
}

/// Write the artifact_id to {storage_dir}/.last for auto-chaining.
fn write_last(storage_dir: &str, artifact_id: &str) {
    let last_path = std::path::Path::new(storage_dir).join(".last");
    let _ = std::fs::write(&last_path, artifact_id);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&last_path, std::fs::Permissions::from_mode(0o600));
    }
}

/// Get the current git HEAD sha (short), if in a git repo.
fn git_head_sha() -> Option<String> {
    let output = process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::null())
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Snapshot file modification times in a directory (non-recursive, top-level only).
fn file_mtimes(dir: &str) -> std::collections::HashMap<String, std::time::SystemTime> {
    let mut map = std::collections::HashMap::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if let Ok(mtime) = meta.modified() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    // Skip hidden files and the .treeship directory
                    if !name.starts_with('.') {
                        map.insert(name, mtime);
                    }
                }
            }
        }
    }
    map
}

/// Diff two file mtime snapshots, returning paths that are new or changed.
fn diff_files(
    before: &std::collections::HashMap<String, std::time::SystemTime>,
    after:  &std::collections::HashMap<String, std::time::SystemTime>,
) -> Vec<String> {
    let mut changed = Vec::new();
    for (path, mtime) in after {
        match before.get(path) {
            Some(old_mtime) if old_mtime == mtime => {}
            _ => changed.push(path.clone()),
        }
    }
    changed.sort();
    changed
}

/// SHA-256 hash of a file, returned as "sha256:<hex>".
fn file_sha256(path: &str) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Some(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Count newlines in a byte buffer.
fn bytecount_lines(data: &[u8]) -> usize {
    data.iter().filter(|&&b| b == b'\n').count()
}

/// Get the last non-empty line from a buffer (useful for test summaries).
fn last_nonempty_line(data: &[u8]) -> String {
    let text = String::from_utf8_lossy(data);
    text.lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Walk the parent chain to determine what step number this artifact is.
fn chain_depth(ctx: &ctx::Ctx, parent_id: &str) -> usize {
    let mut depth = 2; // this artifact is step 2 if it has a parent
    let mut current = parent_id.to_string();
    for _ in 0..20 {
        match ctx.storage.read(&current) {
            Ok(record) => {
                match record.parent_id {
                    Some(pid) => {
                        depth += 1;
                        current = pid;
                    }
                    None => break,
                }
            }
            Err(_) => break,
        }
    }
    depth
}

/// Emit session events for a wrapped command. Best-effort: silently skips
/// if no active session exists.
fn emit_wrap_events(
    command: &str,
    process_name: &str,
    exit_code: i32,
    elapsed_ms: u64,
    changed_files: &[String],
) {
    // Find active session
    let manifest = match super::session::load_session() {
        Some(m) => m,
        None => return,
    };
    let ts_dir = match find_treeship_dir() {
        Some(d) => d,
        None => return,
    };
    let evt_dir = ts_dir.join("sessions").join(&manifest.session_id);
    let log = match EventLog::open(&evt_dir) {
        Ok(l) => l,
        Err(_) => return,
    };

    let host_id = super::session::local_host_id();
    let trace_id = generate_trace_id();
    let now = || {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        treeship_core::statements::unix_to_rfc3339(secs)
    };

    let base = |et: EventType| -> SessionEvent {
        SessionEvent {
            session_id: manifest.session_id.clone(),
            event_id: generate_event_id(),
            timestamp: now(),
            sequence_no: 0,
            trace_id: trace_id.clone(),
            span_id: generate_span_id(),
            parent_span_id: None,
            agent_id: manifest.actor.clone(),
            agent_instance_id: "operator".into(),
            agent_name: "treeship-cli".into(),
            agent_role: Some("operator".into()),
            host_id: host_id.clone(),
            tool_runtime_id: None,
            event_type: et,
            artifact_ref: None,
            meta: None,
        }
    };

    // Process completed event (single event since wrap is synchronous)
    let mut evt = base(EventType::AgentCompletedProcess {
        process_name: process_name.into(),
        exit_code: Some(exit_code),
        duration_ms: Some(elapsed_ms),
        command: Some(command.into()),
    });
    let _ = log.append(&mut evt);

    // File write events
    for path in changed_files {
        let mut evt = base(EventType::AgentWroteFile {
            file_path: path.clone(),
            digest: None,
            operation: Some("modified".into()),
            additions: None,
            deletions: None,
        });
        let _ = log.append(&mut evt);
    }
}

/// Read TREESHIP_MODEL, TREESHIP_TOKENS_IN, TREESHIP_TOKENS_OUT,
/// TREESHIP_COST_USD from environment and emit an AgentDecision event
/// if any are present. This allows any agent runtime that sets these
/// env vars to have model, token, and cost data flow into the receipt
/// automatically.
fn emit_decision_from_env() {
    let model = std::env::var("TREESHIP_MODEL").ok();
    let tokens_in: Option<u64> = std::env::var("TREESHIP_TOKENS_IN")
        .ok()
        .and_then(|s| s.parse().ok());
    let tokens_out: Option<u64> = std::env::var("TREESHIP_TOKENS_OUT")
        .ok()
        .and_then(|s| s.parse().ok());
    let cost_usd: Option<f64> = std::env::var("TREESHIP_COST_USD")
        .ok()
        .and_then(|s| s.parse().ok());

    // Only emit if at least one env var is set.
    if model.is_none() && tokens_in.is_none() && tokens_out.is_none() && cost_usd.is_none() {
        return;
    }

    let manifest = match super::session::load_session() {
        Some(m) => m,
        None => return,
    };
    let ts_dir = match find_treeship_dir() {
        Some(d) => d,
        None => return,
    };
    let evt_dir = ts_dir.join("sessions").join(&manifest.session_id);
    let log = match EventLog::open(&evt_dir) {
        Ok(l) => l,
        Err(_) => return,
    };

    let host_id = super::session::local_host_id();
    let now = {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        treeship_core::statements::unix_to_rfc3339(secs)
    };

    let mut event = SessionEvent {
        session_id: manifest.session_id.clone(),
        event_id: generate_event_id(),
        timestamp: now,
        sequence_no: 0,
        trace_id: generate_trace_id(),
        span_id: generate_span_id(),
        parent_span_id: None,
        agent_id: manifest.actor.clone(),
        agent_instance_id: "operator".into(),
        agent_name: "treeship-cli".into(),
        agent_role: Some("operator".into()),
        host_id,
        tool_runtime_id: None,
        event_type: EventType::AgentDecision {
            model,
            tokens_in,
            tokens_out,
            cost_usd,
            summary: None,
            confidence: None,
        },
        artifact_ref: None,
        meta: None,
    };

    let _ = log.append(&mut event);
}

/// Find the .treeship directory by walking up from cwd.
fn find_treeship_dir() -> Option<std::path::PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let ts = dir.join(".treeship");
        if ts.is_dir() {
            return Some(ts);
        }
        if !dir.pop() { return None; }
    }
}

/// Format a Duration as a human-readable elapsed time string.
fn format_elapsed(d: std::time::Duration) -> String {
    let ms = d.as_millis();
    if ms < 1000 {
        format!("{}ms", ms)
    } else {
        let secs = d.as_secs_f64();
        if secs < 60.0 {
            format!("{:.1}s", secs)
        } else {
            let mins = secs as u64 / 60;
            let rem  = secs as u64 % 60;
            format!("{}m{}s", mins, rem)
        }
    }
}
