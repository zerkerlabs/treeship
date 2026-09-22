//! Anonymous usage telemetry, end to end against a local one-shot hub: the
//! first command on a machine sends exactly one `install` ping with exactly
//! the documented seven fields, later commands send nothing until a week has
//! passed, every off switch sends nothing and writes nothing, and the state
//! file is private to the user.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use serde_json::Value;
use tempfile::TempDir;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

/// A hub that accepts telemetry pings until dropped: answers 204 and hands
/// each request body back on the channel.
struct Hub {
    url: String,
    rx: mpsc::Receiver<String>,
}

impl Hub {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let body = loop {
                    let n = match stream.read(&mut chunk) {
                        Ok(0) | Err(_) => break None,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..pos]).to_string();
                        let len = head
                            .lines()
                            .find_map(|l| {
                                let (k, v) = l.split_once(':')?;
                                k.eq_ignore_ascii_case("content-length")
                                    .then(|| v.trim().parse::<usize>().ok())?
                            })
                            .unwrap_or(0);
                        while buf.len() < pos + 4 + len {
                            let n = match stream.read(&mut chunk) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => n,
                            };
                            buf.extend_from_slice(&chunk[..n]);
                        }
                        assert!(
                            head.starts_with("POST /v1/telemetry HTTP/1.1"),
                            "unexpected request: {head}"
                        );
                        break Some(String::from_utf8_lossy(&buf[pos + 4..]).to_string());
                    }
                };
                let _ = stream.write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
                if let Some(b) = body {
                    if tx.send(b).is_err() {
                        break;
                    }
                }
            }
        });
        Self {
            url: format!("http://{addr}"),
            rx,
        }
    }

    fn next(&self) -> Option<Value> {
        self.rx
            .recv_timeout(Duration::from_secs(3))
            .ok()
            .map(|b| serde_json::from_str(&b).expect("ping body is json"))
    }
}

struct Ws {
    _tmp: TempDir,
    root: PathBuf,
}

impl Ws {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        Self { _tmp: tmp, root }
    }
    fn config(&self) -> PathBuf {
        self.root.join(".treeship/config.json")
    }
    fn state(&self) -> PathBuf {
        self.root.join(".treeship/telemetry.json")
    }
    fn cmd(&self, hub: &str) -> Command {
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root)
            .env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1")
            .env("TREESHIP_TELEMETRY_ENDPOINT", hub)
            .env_remove("TREESHIP_NO_TELEMETRY")
            .env_remove("DO_NOT_TRACK")
            .env_remove("CI")
            .env_remove("CLAUDECODE")
            .env_remove("CLAUDE_CODE_ENTRYPOINT")
            .env_remove("CODEX_SANDBOX")
            .env_remove("CODEX_THREAD_ID")
            .env_remove("CURSOR_TRACE_ID")
            .current_dir(&self.root);
        c
    }
    fn run(&self, hub: &str, args: &[&str], env: &[(&str, &str)]) -> (bool, String) {
        let mut c = self.cmd(hub);
        for (k, v) in env {
            c.env(k, v);
        }
        let out = c.args(args).output().unwrap();
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }
    fn init(&self, hub: &str, env: &[(&str, &str)]) -> String {
        let (ok, out) = self.run(
            hub,
            &[
                "init",
                "--name",
                "ws",
                "--config",
                self.config().to_str().unwrap(),
            ],
            env,
        );
        assert!(ok, "init failed:\n{out}");
        out
    }
}

fn first_json(out: &str) -> Value {
    let start = out.find('{').expect("json object in output");
    serde_json::from_str(&out[start..]).expect("parse json")
}

#[test]
fn first_run_sends_one_install_ping_with_exactly_the_documented_fields() {
    let hub = Hub::start();
    let ws = Ws::new();

    let out = ws.init(&hub.url, &[]);
    assert!(
        out.contains("anonymous ping") && out.contains("treeship telemetry disable"),
        "init must disclose telemetry and the off switch:\n{out}"
    );

    let ping = hub.next().expect("one install ping");
    let obj = ping.as_object().unwrap();
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
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
        ],
        "the field set is closed: {ping}"
    );
    assert_eq!(obj["schema"], "treeship.telemetry.v1");
    assert_eq!(obj["event"], "install");
    assert_eq!(obj["cli_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(obj["harness"], "unknown");
    let id = obj["install_id"].as_str().unwrap();
    assert!(id.starts_with("ins_") && id.len() == 36, "{id}");
    // Nothing about the machine leaks through the values.
    let raw = ping.to_string();
    for forbidden in [ws.root.to_str().unwrap(), "ws", "config.json"] {
        assert!(
            !raw.contains(&format!("\"{forbidden}\"")),
            "payload carries {forbidden}: {raw}"
        );
    }

    // The state file matches the ping and is private.
    let state: Value = serde_json::from_str(&std::fs::read_to_string(ws.state()).unwrap()).unwrap();
    assert_eq!(state["install_id"], id);
    assert!(state["last_sent_at"].is_u64());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(ws.state()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "state file mode {mode:o}");
    }

    // A second command the same week sends nothing.
    let (ok, _) = ws.run(
        &hub.url,
        &["status", "--config", ws.config().to_str().unwrap()],
        &[],
    );
    assert!(ok);
    assert!(
        hub.next().is_none(),
        "no heartbeat before a week has passed"
    );

    // Age the state by eight days: the next command sends one heartbeat.
    let mut aged = state.clone();
    aged["last_sent_at"] = Value::from(state["last_sent_at"].as_u64().unwrap() - 8 * 86_400);
    std::fs::write(ws.state(), aged.to_string()).unwrap();
    let (ok, _) = ws.run(
        &hub.url,
        &["status", "--config", ws.config().to_str().unwrap()],
        &[],
    );
    assert!(ok);
    let hb = hub.next().expect("one heartbeat");
    assert_eq!(hb["event"], "heartbeat");
    assert_eq!(hb["install_id"], id, "the id is stable across runs");
    assert!(hub.next().is_none());
}

#[test]
fn every_off_switch_sends_nothing_and_writes_nothing() {
    let hub = Hub::start();
    for env in [
        &[("DO_NOT_TRACK", "1")][..],
        &[("TREESHIP_NO_TELEMETRY", "1")][..],
        &[("CI", "true")][..],
    ] {
        let ws = Ws::new();
        let out = ws.init(&hub.url, env);
        assert!(
            out.contains("off ("),
            "init must say telemetry is off under {env:?}:\n{out}"
        );
        assert!(hub.next().is_none(), "ping sent under {env:?}");
        assert!(!ws.state().exists(), "state file written under {env:?}");
    }
}

#[test]
fn disable_persists_and_status_shows_the_whole_payload() {
    let hub = Hub::start();
    let ws = Ws::new();
    ws.init(&hub.url, &[]);
    let install = hub.next().expect("install ping");

    let (ok, out) = ws.run(&hub.url, &["telemetry", "disable"], &[]);
    assert!(ok, "{out}");
    let state: Value = serde_json::from_str(&std::fs::read_to_string(ws.state()).unwrap()).unwrap();
    assert_eq!(state["enabled"], false);

    // Aged and disabled: still nothing.
    let mut aged = state.clone();
    aged["last_sent_at"] = Value::from(1u64);
    std::fs::write(ws.state(), aged.to_string()).unwrap();
    let (ok, _) = ws.run(
        &hub.url,
        &["status", "--config", ws.config().to_str().unwrap()],
        &[],
    );
    assert!(ok);
    assert!(
        hub.next().is_none(),
        "disabled must send nothing even when a heartbeat is due"
    );

    let (ok, out) = ws.run(&hub.url, &["telemetry", "status", "--format", "json"], &[]);
    assert!(ok, "{out}");
    let st = first_json(&out);
    assert_eq!(st["enabled"], false);
    assert_eq!(st["disabled_reason"], "treeship telemetry disable");
    assert_eq!(st["install_id"], install["install_id"]);
    assert_eq!(st["payload"]["schema"], "treeship.telemetry.v1");
    assert_eq!(st["endpoint"], hub.url);

    let (ok, _) = ws.run(&hub.url, &["telemetry", "enable"], &[]);
    assert!(ok);
    let (ok, _) = ws.run(
        &hub.url,
        &["status", "--config", ws.config().to_str().unwrap()],
        &[],
    );
    assert!(ok);
    let hb = hub.next().expect("re-enabled and due: one heartbeat");
    assert_eq!(hb["event"], "heartbeat");
}

#[test]
fn an_unreachable_hub_never_fails_the_command() {
    // Nothing listens here; the connect fails fast and the command succeeds.
    let ws = Ws::new();
    let out = ws.init("http://127.0.0.1:9", &[]);
    assert!(out.contains("Treeship initialized"), "{out}");
    let (ok, _) = ws.run(
        "http://127.0.0.1:9",
        &["status", "--config", ws.config().to_str().unwrap()],
        &[],
    );
    assert!(ok);
}
