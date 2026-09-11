//! QA on the published 0.31.1 (two-ship run, 2026-09-09): two findings in
//! the CLI, pinned here so they cannot come back.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;
use tempfile::TempDir;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

struct Ws {
    _tmp: TempDir,
    root: PathBuf,
}

impl Ws {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let ws = Self { _tmp: tmp, root };
        assert!(ws
            .cmd()
            .args(["init", "--name", "qa", "--config"])
            .arg(ws.config())
            .status()
            .unwrap()
            .success());
        ws
    }
    fn config(&self) -> PathBuf {
        self.root.join(".treeship/config.json")
    }
    fn cmd(&self) -> Command {
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root)
            .env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1")
            .env("TREESHIP_TRUST_ROOTS", self.root.join("trust_roots.json"))
            .current_dir(&self.root);
        c
    }
    fn json(&self, args: &[&str]) -> Value {
        let out = self
            .cmd()
            .args(args)
            .args(["--format", "json", "--config"])
            .arg(self.config())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{args:?}: {stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let last = stdout
            .trim()
            .rsplit("\n{")
            .next()
            .map(|s| {
                if s.starts_with('{') {
                    s.to_string()
                } else {
                    format!("{{{s}")
                }
            })
            .unwrap();
        serde_json::from_str(&last).unwrap_or_else(|e| panic!("{e}: {stdout}"))
    }
    fn text(&self, args: &[&str]) -> (bool, String) {
        let out = self
            .cmd()
            .args(args)
            .args(["--config"])
            .arg(self.config())
            .output()
            .unwrap();
        (
            out.status.success(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }
}

/// `wrap --actor` signed with the ship key regardless of the actor's own
/// registered key, so a key-bound agent's wrapped commands were `asserted`
/// while its `attest action` receipts were `proven (key-bound)`.
#[test]
fn wrap_signs_with_the_key_bound_actors_own_key() {
    let ws = Ws::new();
    let (ok, out) = ws.text(&["agent", "register", "--name", "qa", "--own-key", "--quiet"]);
    assert!(ok, "{out}");
    // Flags go before `--`; anything after it belongs to the wrapped
    // command. A harness that appends `--format json` after the command sees
    // the child's output where it expected a receipt, which is by design.
    let out = ws
        .cmd()
        .args([
            "wrap",
            "--actor",
            "agent://qa",
            "--format",
            "json",
            "--config",
        ])
        .arg(ws.config())
        .args(["--", "echo", "hi"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let wrapped: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)));
    let id = wrapped["artifact_id"].as_str().unwrap().to_string();
    let (ok, out) = ws.text(&["verify", &id]);
    assert!(ok, "{out}");
    assert!(
        out.contains("proven (key-bound)"),
        "wrap must sign with the agent's pinned key:\n{out}"
    );
    let attested = ws.json(&["attest", "action", "--actor", "agent://qa", "--action", "t"]);
    let id2 = attested["id"].as_str().unwrap().to_string();
    let (_, out2) = ws.text(&["verify", &id2]);
    assert!(out2.contains("proven (key-bound)"), "{out2}");
}

/// The MCP bridge tells agents to leave `agent.note` events; the CLI refused
/// them as unsupported.
#[test]
fn session_event_accepts_agent_note() {
    let ws = Ws::new();
    ws.json(&[
        "session",
        "start",
        "--name",
        "notes",
        "--actor",
        "agent://qa",
    ]);
    let ev = ws.json(&[
        "session",
        "event",
        "--type",
        "agent.note",
        "--actor",
        "agent://qa",
        "--agent-name",
        "qa",
        "--meta",
        r#"{"text":"stopped before the second retry: rate limited"}"#,
    ]);
    assert!(
        ev["event_id"].as_str().unwrap_or("").starts_with("evt_"),
        "{ev}"
    );
    let session_id = ws.json(&["session", "status"])["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let log = std::fs::read_to_string(
        ws.root
            .join(".treeship/sessions")
            .join(&session_id)
            .join("events.jsonl"),
    )
    .unwrap();
    assert!(log.contains("\"agent.note\""), "{log}");
    assert!(log.contains("stopped before the second retry"), "{log}");
    // And it survives into the sealed receipt with its text as the summary.
    let closed = ws.json(&["session", "close", "--summary", "notes"]);
    let receipt = std::fs::read_to_string(
        PathBuf::from(closed["package"].as_str().unwrap()).join("receipt.json"),
    )
    .unwrap();
    assert!(receipt.contains("agent.note"), "{receipt}");
    assert!(
        receipt.contains("stopped before the second retry"),
        "{receipt}"
    );
}
