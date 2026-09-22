//! Anonymous usage telemetry. Opt-out, minimal, and honest about itself.
//!
//! Treeship is local-first: `init`, `attest` and `verify` never touch the
//! network. That makes the project blind to its own adoption, so the CLI
//! sends one small ping to the hub the first time it runs on a machine and at
//! most one more per week after that. Both carry the same seven fields and
//! nothing else:
//!
//! ```json
//! {"schema":"treeship.telemetry.v1","install_id":"ins_<32 hex>","event":"install",
//!  "cli_version":"0.31.5","os":"macos","arch":"aarch64","harness":"claude-code"}
//! ```
//!
//! The install id is 16 random bytes generated here and stored in
//! `~/.treeship/telemetry.json` (mode 0600). It is not a key, not the ship id,
//! not a dock id, and not derived from anything on the machine: it answers
//! "how many machines" and cannot answer "which". No paths, hostnames,
//! usernames, receipts, command lines or IP addresses are sent (the hub does
//! not store the request's IP either).
//!
//! Off switches, any one of which disables every send:
//!
//! - `TREESHIP_NO_TELEMETRY=1`
//! - `DO_NOT_TRACK=1` (the cross-tool convention)
//! - `CI` set to anything (CI runners are not users, and are the reason
//!   registry download counts mean nothing)
//! - `treeship telemetry disable` (writes `"enabled": false` to the state file)
//!
//! A send never blocks a command for long (two seconds on first run, one
//! second for a heartbeat, once a week) and never fails one: every error is
//! swallowed. `treeship telemetry status` shows the id, the state and the
//! exact payload.

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::printer::Printer;

pub const SCHEMA: &str = "treeship.telemetry.v1";
pub const DEFAULT_ENDPOINT: &str = "https://api.treeship.dev";
const STATE_FILE: &str = "telemetry.json";
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(2);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(1);

/// On-disk state, `~/.treeship/telemetry.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct State {
    pub install_id: String,
    pub created_at: u64,
    #[serde(default)]
    pub last_sent_at: Option<u64>,
    /// `None` means enabled; the file only says `false` after `disable`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

/// The wire payload. Field set is closed: the hub rejects unknown fields.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Payload {
    pub schema: &'static str,
    pub install_id: String,
    pub event: &'static str,
    pub cli_version: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
    pub harness: &'static str,
}

/// Why sending is off, if it is. Pure over an environment lookup so it can
/// be tested without touching the process environment.
pub fn disabled_reason_from(env: &dyn Fn(&str) -> Option<String>) -> Option<&'static str> {
    let set = |k: &str| {
        env(k)
            .map(|v| !v.is_empty() && v != "0" && v != "false")
            .unwrap_or(false)
    };
    if set("TREESHIP_NO_TELEMETRY") {
        return Some("TREESHIP_NO_TELEMETRY is set");
    }
    if set("DO_NOT_TRACK") {
        return Some("DO_NOT_TRACK is set");
    }
    if env("CI").map(|v| !v.is_empty()).unwrap_or(false) {
        return Some("CI is set");
    }
    None
}

fn env_lookup(k: &str) -> Option<String> {
    std::env::var(k).ok()
}

/// The effective answer for this process: the environment switches, plus one
/// rule for builds from source. A debug build only sends when
/// `TREESHIP_TELEMETRY_ENDPOINT` names where to, so `cargo test` and a
/// developer's scratch binary never register as installs on the public hub.
pub fn disabled_reason() -> Option<&'static str> {
    if let Some(why) = disabled_reason_from(&env_lookup) {
        return Some(why);
    }
    if cfg!(debug_assertions) && std::env::var_os("TREESHIP_TELEMETRY_ENDPOINT").is_none() {
        return Some("debug build without TREESHIP_TELEMETRY_ENDPOINT");
    }
    None
}

/// Endpoint the ping is posted to. Overridable so tests and self-hosted hubs
/// can point it elsewhere; only `http(s)://` is accepted.
pub fn endpoint() -> String {
    match std::env::var("TREESHIP_TELEMETRY_ENDPOINT") {
        Ok(v) if v.starts_with("https://") || v.starts_with("http://") => {
            v.trim_end_matches('/').to_string()
        }
        _ => DEFAULT_ENDPOINT.to_string(),
    }
}

pub fn state_path() -> Option<PathBuf> {
    home::home_dir().map(|h| h.join(".treeship").join(STATE_FILE))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn new_install_id() -> String {
    // OsRng, same as every other identifier this crate mints: not because
    // the id is secret (it is not) but so there is one randomness source in
    // the codebase to audit.
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("ins_{}", hex::encode(bytes))
}

pub fn load() -> Option<State> {
    let path = state_path()?;
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn save(state: &State) -> std::io::Result<()> {
    let path = state_path().ok_or_else(|| std::io::Error::other("no home directory"))?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let body = serde_json::to_string_pretty(state).map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    fs::rename(tmp, path)
}

/// Load the state file, creating it on first run. Returns the state and
/// whether it was just created (which is what makes this run an `install`).
fn load_or_create() -> Option<(State, bool)> {
    if let Some(s) = load() {
        return Some((s, false));
    }
    let s = State {
        install_id: new_install_id(),
        created_at: now_secs(),
        last_sent_at: None,
        enabled: None,
    };
    save(&s).ok()?;
    Some((s, true))
}

fn os_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macos",
        "linux" => "linux",
        "windows" => "windows",
        _ => "other",
    }
}

fn arch_name() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        _ => "other",
    }
}

/// Which agent harness is driving the CLI, from the environment variables
/// those harnesses set. A closed vocabulary the hub checks; anything not
/// recognised is `unknown`, never the raw value.
pub fn harness_from(env: &dyn Fn(&str) -> Option<String>) -> &'static str {
    let set = |k: &str| env(k).map(|v| !v.is_empty()).unwrap_or(false);
    if set("CLAUDECODE") || set("CLAUDE_CODE_ENTRYPOINT") {
        "claude-code"
    } else if set("CODEX_THREAD_ID") || set("CODEX_SANDBOX") {
        "codex"
    } else if set("CURSOR_TRACE_ID") {
        "cursor"
    } else {
        "unknown"
    }
}

pub fn payload(install_id: &str, event: &'static str) -> Payload {
    Payload {
        schema: SCHEMA,
        install_id: install_id.to_string(),
        event,
        cli_version: env!("CARGO_PKG_VERSION"),
        os: os_name(),
        arch: arch_name(),
        harness: harness_from(&env_lookup),
    }
}

/// Whether a heartbeat is due: never sent, or sent more than a week ago.
pub fn heartbeat_due(state: &State, now: u64) -> bool {
    match state.last_sent_at {
        None => true,
        Some(t) => now.saturating_sub(t) >= HEARTBEAT_INTERVAL.as_secs(),
    }
}

fn send(p: &Payload, timeout: Duration) -> Result<(), String> {
    let url = format!("{}/v1/telemetry", endpoint());
    let agent = ureq::AgentBuilder::new().timeout(timeout).build();
    agent
        .post(&url)
        .set("Content-Type", "application/json")
        .send_json(p)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Called once per command invocation. Sends `install` on the first run on
/// this machine, `heartbeat` when one is due, nothing otherwise. Every
/// failure is silent: telemetry must never change a command's outcome.
pub fn tick() {
    if disabled_reason().is_some() {
        return;
    }
    let Some((mut state, created)) = load_or_create() else {
        return;
    };
    if state.enabled == Some(false) {
        return;
    }
    let now = now_secs();
    let (event, timeout) = if created {
        ("install", INSTALL_TIMEOUT)
    } else if heartbeat_due(&state, now) {
        ("heartbeat", HEARTBEAT_TIMEOUT)
    } else {
        return;
    };
    // Mark before sending. A failed send waits for the next interval rather
    // than retrying on every command against a hub that is down.
    state.last_sent_at = Some(now);
    let _ = save(&state);
    let _ = send(&payload(&state.install_id, event), timeout);
}

/// The disclosure printed at the end of `treeship init`.
pub fn notice(printer: &Printer) {
    printer.section("telemetry");
    match disabled_reason() {
        Some(why) => {
            printer.dim_info(&format!("  off ({why})"));
        }
        None => match load() {
            Some(s) if s.enabled == Some(false) => {
                printer.dim_info("  off (treeship telemetry disable)");
            }
            _ => {
                printer.info("  Treeship sends one anonymous ping on first use and at most");
                printer
                    .info("  weekly: a random id, CLI version, OS, arch, harness. Nothing else.");
                printer.dim_info("  Turn off: treeship telemetry disable  (or DO_NOT_TRACK=1)");
            }
        },
    }
    printer.hint("treeship telemetry status  shows exactly what is sent");
    printer.blank();
}

pub fn status(printer: &Printer) {
    let state = load();
    let reason = disabled_reason();
    let enabled = reason.is_none()
        && state
            .as_ref()
            .map(|s| s.enabled != Some(false))
            .unwrap_or(true);

    if printer.is_json() {
        let sample = state.as_ref().map(|s| payload(&s.install_id, "heartbeat"));
        printer.json(&serde_json::json!({
            "enabled": enabled,
            "disabled_reason": reason.or(if state.as_ref().map(|s| s.enabled == Some(false)).unwrap_or(false) { Some("treeship telemetry disable") } else { None }),
            "endpoint": endpoint(),
            "state_file": state_path(),
            "install_id": state.as_ref().map(|s| s.install_id.clone()),
            "last_sent_at": state.as_ref().and_then(|s| s.last_sent_at),
            "payload": sample,
        }));
        return;
    }

    printer.blank();
    printer.section("telemetry");
    printer.info(&format!(
        "  enabled:   {}",
        if enabled { "yes" } else { "no" }
    ));
    if let Some(why) = reason {
        printer.dim_info(&format!("  reason:    {why}"));
    } else if let Some(s) = &state {
        if s.enabled == Some(false) {
            printer.dim_info("  reason:    treeship telemetry disable");
        }
    }
    printer.info(&format!("  endpoint:  {}/v1/telemetry", endpoint()));
    if let Some(p) = state_path() {
        printer.info(&format!("  state:     {}", p.display()));
    }
    match &state {
        Some(s) => {
            printer.info(&format!("  install:   {}", s.install_id));
            match s.last_sent_at {
                Some(t) => printer.info(&format!("  last sent: {t} (unix)")),
                None => printer.dim_info("  last sent: never"),
            }
            printer.blank();
            printer.info("  payload (the whole thing):");
            if let Ok(j) = serde_json::to_string(&payload(&s.install_id, "heartbeat")) {
                printer.dim_info(&format!("  {j}"));
            }
        }
        None => printer.dim_info("  install:   none yet (created on first command)"),
    }
    printer.blank();
    printer.hint("treeship telemetry disable | enable");
    printer.blank();
}

fn set_enabled(on: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = match load() {
        Some(s) => s,
        None => State {
            install_id: new_install_id(),
            created_at: now_secs(),
            last_sent_at: None,
            enabled: None,
        },
    };
    state.enabled = if on { None } else { Some(false) };
    save(&state)?;
    Ok(())
}

pub fn enable(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    set_enabled(true)?;
    printer.success("telemetry enabled", &[]);
    if let Some(why) = disabled_reason() {
        printer.warn("still off in this environment", &[("reason", why)]);
    }
    Ok(())
}

pub fn disable(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    set_enabled(false)?;
    printer.success(
        "telemetry disabled",
        &[("persisted", "~/.treeship/telemetry.json")],
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| m.get(k).cloned()
    }

    #[test]
    fn every_off_switch_disables() {
        assert_eq!(disabled_reason_from(&env(&[])), None);
        assert!(disabled_reason_from(&env(&[("TREESHIP_NO_TELEMETRY", "1")])).is_some());
        assert!(disabled_reason_from(&env(&[("DO_NOT_TRACK", "1")])).is_some());
        assert!(disabled_reason_from(&env(&[("CI", "true")])).is_some());
        assert!(disabled_reason_from(&env(&[("CI", "1")])).is_some());
        // "0" and "false" mean not set for the boolean-shaped ones.
        assert_eq!(disabled_reason_from(&env(&[("DO_NOT_TRACK", "0")])), None);
        assert_eq!(
            disabled_reason_from(&env(&[("TREESHIP_NO_TELEMETRY", "false")])),
            None
        );
    }

    #[test]
    fn harness_is_a_closed_vocabulary() {
        assert_eq!(harness_from(&env(&[("CLAUDECODE", "1")])), "claude-code");
        assert_eq!(
            harness_from(&env(&[("CODEX_SANDBOX", "seatbelt")])),
            "codex"
        );
        assert_eq!(harness_from(&env(&[("CURSOR_TRACE_ID", "x")])), "cursor");
        assert_eq!(
            harness_from(&env(&[("TERM_PROGRAM", "iTerm.app")])),
            "unknown"
        );
        assert_eq!(harness_from(&env(&[])), "unknown");
    }

    #[test]
    fn heartbeat_is_weekly() {
        let mut s = State {
            install_id: new_install_id(),
            created_at: 0,
            last_sent_at: None,
            enabled: None,
        };
        assert!(heartbeat_due(&s, 100));
        s.last_sent_at = Some(1_000_000);
        assert!(!heartbeat_due(&s, 1_000_000 + 6 * 86_400));
        assert!(heartbeat_due(&s, 1_000_000 + 7 * 86_400));
        // A clock that went backwards must not panic or spam.
        assert!(!heartbeat_due(&s, 10));
    }

    #[test]
    fn install_id_shape_and_payload_field_set() {
        let id = new_install_id();
        assert_eq!(id.len(), 4 + 32);
        assert!(id.starts_with("ins_"));
        assert!(id[4..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(id, new_install_id());

        let p = payload(&id, "install");
        let v: serde_json::Value = serde_json::to_value(&p).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "arch",
                "cli_version",
                "event",
                "harness",
                "install_id",
                "os",
                "schema"
            ]
        );
        assert!(["macos", "linux", "windows", "other"].contains(&p.os));
        assert!(["x86_64", "aarch64", "other"].contains(&p.arch));
    }
}
