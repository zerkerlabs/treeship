use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{ctx, printer::Printer};
use treeship_core::rules::ProjectConfig;

// ---------------------------------------------------------------------------
// Check result
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum CheckStatus {
    Pass,
    Fail,
    Info,
}

struct Check {
    status: CheckStatus,
    label: String,
    detail: String,
    suggestion: Option<String>,
}

impl Check {
    fn pass(label: &str, detail: &str) -> Self {
        Self {
            status: CheckStatus::Pass,
            label: label.to_string(),
            detail: detail.to_string(),
            suggestion: None,
        }
    }

    fn fail(label: &str, detail: &str, suggestion: &str) -> Self {
        Self {
            status: CheckStatus::Fail,
            label: label.to_string(),
            detail: detail.to_string(),
            suggestion: Some(suggestion.to_string()),
        }
    }

    fn info(label: &str, detail: &str) -> Self {
        Self {
            status: CheckStatus::Info,
            label: label.to_string(),
            detail: detail.to_string(),
            suggestion: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
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

fn shell_config_path() -> Option<(String, PathBuf)> {
    let shell = std::env::var("SHELL").unwrap_or_default();
    let home = home::home_dir()?;
    if shell.contains("zsh") {
        Some(("zsh".to_string(), home.join(".zshrc")))
    } else if shell.contains("bash") {
        Some(("bash".to_string(), home.join(".bashrc")))
    } else if shell.contains("fish") {
        Some(("fish".to_string(), home.join(".config").join("fish").join("config.fish")))
    } else {
        None
    }
}

fn hook_installed(path: &Path) -> bool {
    if let Ok(contents) = std::fs::read_to_string(path) {
        contents.contains("# Treeship shell hook")
    } else {
        false
    }
}

fn count_artifacts(storage_dir: &str) -> (usize, u64) {
    let dir = Path::new(storage_dir);
    let mut count = 0usize;
    let mut total_bytes = 0u64;

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let name = path.file_name().unwrap_or_default().to_string_lossy();
                // Skip index.json
                if name == "index.json" {
                    continue;
                }
                count += 1;
                if let Ok(meta) = std::fs::metadata(&path) {
                    total_bytes += meta.len();
                }
            }
        }
    }

    (count, total_bytes)
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    }
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

fn epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ---------------------------------------------------------------------------
// doctor run
// ---------------------------------------------------------------------------

pub fn run(
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut checks: Vec<Check> = Vec::new();

    let separator = "──────────────────────────────────────────";

    printer.blank();
    printer.section("Treeship diagnostic check");
    printer.dim_info(separator);

    // 1. Is treeship initialized?
    let ctx_result = ctx::open(config);
    match &ctx_result {
        Ok(ctx) => {
            checks.push(Check::pass(
                "treeship initialized",
                &ctx.config.ship_id,
            ));
        }
        Err(_) => {
            checks.push(Check::fail(
                "treeship not initialized",
                "no config found",
                "treeship init",
            ));
        }
    }

    // 2. Is keypair valid?
    if let Ok(ref ctx) = ctx_result {
        match ctx.keys.default_signer() {
            Ok(signer) => {
                let key_id = signer.key_id();
                let short_key = if key_id.len() > 12 { &key_id[..12] } else { key_id };
                checks.push(Check::pass(
                    "keypair valid",
                    &format!("{} (ed25519)", short_key),
                ));
            }
            Err(e) => {
                checks.push(Check::fail(
                    "keypair invalid",
                    &e.to_string(),
                    "treeship init --force",
                ));
            }
        }
    }

    // 3. Is config.yaml present?
    let ts = ts_dir();
    if let Some(ref ts_path) = ts {
        let config_yaml = ts_path.join("config.yaml");
        if config_yaml.exists() {
            match ProjectConfig::load(&config_yaml) {
                Ok(project) => {
                    let cmd_count = project.attest.commands.len();
                    let path_count = project.attest.paths.len();
                    checks.push(Check::pass(
                        "config.yaml present",
                        &format!("{} command rules, {} path rules", cmd_count, path_count),
                    ));
                }
                Err(e) => {
                    checks.push(Check::fail(
                        "config.yaml invalid",
                        &e.to_string(),
                        "check .treeship/config.yaml syntax",
                    ));
                }
            }
        } else {
            checks.push(Check::fail(
                "config.yaml missing",
                "no project config",
                "treeship init",
            ));
        }
    }

    // 4. Are shell hooks installed?
    match shell_config_path() {
        Some((shell_name, shell_path)) => {
            if hook_installed(&shell_path) {
                let short_path = shell_path.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                checks.push(Check::pass(
                    "shell hooks installed",
                    &format!("{} (~{})", shell_name, short_path),
                ));
            } else {
                checks.push(Check::fail(
                    "shell hooks not installed",
                    &format!("{} detected but no hooks", shell_name),
                    "treeship install",
                ));
            }
        }
        None => {
            checks.push(Check::info(
                "shell hooks",
                "could not detect shell",
            ));
        }
    }

    // 5. Is daemon running?
    let (daemon_running, daemon_pid, daemon_uptime) = super::daemon::daemon_info();
    if daemon_running {
        let pid = daemon_pid.unwrap_or(0);
        let uptime = daemon_uptime.map(|s| format_uptime_secs(s)).unwrap_or_else(|| "unknown".to_string());
        checks.push(Check::pass(
            "daemon running",
            &format!("pid {} (uptime: {})", pid, uptime),
        ));
    } else {
        checks.push(Check::fail(
            "daemon not running",
            "",
            "treeship daemon start",
        ));
    }

    // 6. Is Hub docked?
    if let Ok(ref ctx) = ctx_result {
        match ctx.config.hub.status.as_str() {
            "docked" => {
                let endpoint = ctx.config.hub.endpoint.as_deref().unwrap_or("treeship.dev");
                let dock_id = ctx.config.hub.dock_id.as_deref().unwrap_or("-");
                let short_dock = if dock_id.len() > 12 { &dock_id[..12] } else { dock_id };
                checks.push(Check::pass(
                    "hub docked",
                    &format!("{} ({})", endpoint, short_dock),
                ));

                // 7. Is Hub reachable? (only check if docked)
                let reachable = check_hub_reachable(endpoint);
                if reachable {
                    checks.push(Check::pass(
                        "hub reachable",
                        endpoint,
                    ));
                } else {
                    checks.push(Check::fail(
                        "hub unreachable",
                        &format!("could not reach {}", endpoint),
                        "check network",
                    ));
                }
            }
            _ => {
                checks.push(Check::info(
                    "hub undocked",
                    "not connected to treeship.dev",
                ));
            }
        }
    }

    // 8. Is storage healthy?
    if let Ok(ref ctx) = ctx_result {
        let (count, bytes) = count_artifacts(&ctx.config.storage_dir);
        checks.push(Check::pass(
            "storage healthy",
            &format!("{} artifacts, {}", count, format_bytes(bytes)),
        ));
    }

    // 9. Is there an active session?
    if let Some(manifest) = super::session::load_session() {
        let elapsed_ms = epoch_ms().saturating_sub(manifest.started_at_ms);
        let elapsed_str = format_duration_ms(elapsed_ms);
        let name = manifest.name.as_deref().unwrap_or("unnamed");

        // Count receipts
        let receipt_count = if let Ok(ref ctx) = ctx_result {
            match &manifest.root_artifact_id {
                Some(root_id) => count_chain(ctx, root_id),
                None => 0,
            }
        } else {
            0
        };

        checks.push(Check::pass(
            "active session",
            &format!("{} \"{}\" ({}, {} receipts)", manifest.session_id, name, elapsed_str, receipt_count),
        ));
    } else {
        checks.push(Check::info(
            "no active session",
            "",
        ));
    }

    // Print all checks
    let mut pass_count = 0usize;
    let mut fail_count = 0usize;
    let mut suggestions: Vec<String> = Vec::new();

    for check in &checks {
        let (icon, color_fn): (&str, Box<dyn Fn(&Printer, &str) -> String>) = match check.status {
            CheckStatus::Pass => {
                pass_count += 1;
                ("✓", Box::new(|p: &Printer, s: &str| p.green(s)))
            }
            CheckStatus::Fail => {
                fail_count += 1;
                if let Some(ref sug) = check.suggestion {
                    suggestions.push(sug.clone());
                }
                ("✗", Box::new(|p: &Printer, s: &str| p.red(s)))
            }
            CheckStatus::Info => {
                ("·", Box::new(|p: &Printer, s: &str| p.dim(s)))
            }
        };

        let label_str = color_fn(printer, &format!("{}  {}", icon, check.label));
        if check.detail.is_empty() {
            printer.info(&format!("  {}", label_str));
        } else {
            // Pad label for alignment
            let pad_len = 28usize.saturating_sub(check.label.len() + 4);
            let pad = " ".repeat(pad_len);
            printer.info(&format!("  {}{}  {}", label_str, pad, printer.dim(&check.detail)));
        }
    }

    printer.dim_info(separator);

    // Summary
    if fail_count == 0 {
        printer.info(&format!(
            "  {} passed, all good",
            printer.green(&pass_count.to_string()),
        ));
    } else {
        printer.info(&format!(
            "  {} passed, {} {}",
            printer.green(&pass_count.to_string()),
            printer.red(&fail_count.to_string()),
            if fail_count == 1 { "issue found" } else { "issues found" },
        ));
    }

    // Suggestions
    if !suggestions.is_empty() {
        printer.blank();
        printer.section("Suggestions:");
        for sug in &suggestions {
            printer.hint(sug);
        }
    }

    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// Hub reachability check (timeout 2s)
// ---------------------------------------------------------------------------

fn check_hub_reachable(endpoint: &str) -> bool {
    // Simple TCP connect check with timeout.
    // Parse host:port from endpoint URL.
    let url = endpoint.trim_end_matches('/');
    let (host, port) = if let Some(stripped) = url.strip_prefix("https://") {
        (stripped.split('/').next().unwrap_or(stripped), 443u16)
    } else if let Some(stripped) = url.strip_prefix("http://") {
        (stripped.split('/').next().unwrap_or(stripped), 80u16)
    } else {
        (url.split('/').next().unwrap_or(url), 443u16)
    };

    // Check if host contains a port
    let (host, port) = if let Some(idx) = host.rfind(':') {
        let p = host[idx+1..].parse::<u16>().unwrap_or(port);
        (&host[..idx], p)
    } else {
        (host, port)
    };

    use std::net::{TcpStream, ToSocketAddrs};
    let addr = format!("{}:{}", host, port);
    match addr.to_socket_addrs() {
        Ok(mut addrs) => {
            if let Some(addr) = addrs.next() {
                TcpStream::connect_timeout(&addr, Duration::from_secs(2)).is_ok()
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

fn format_uptime_secs(secs: u64) -> String {
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

/// Count artifacts in chain from .last back to root_id.
fn count_chain(ctx: &ctx::Ctx, root_id: &str) -> u64 {
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
