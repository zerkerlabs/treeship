//! `session close` mints a `coverage.v1` receipt chained onto the close
//! artifact: what the attached harnesses declare they could capture and what
//! the event log shows they did. It is sealed in the package and reported by
//! `package verify` as the `coverage` row.

use std::path::PathBuf;
use std::process::Command;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
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
            .args(["init", "--name", "ws", "--config"])
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
    fn run(&self, args: &[&str]) -> (bool, String) {
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

fn first_json(out: &str) -> Value {
    let start = out.find('{').expect("json object in output");
    let mut de = serde_json::Deserializer::from_str(&out[start..]);
    Value::deserialize(&mut de).expect("parse json")
}

/// Decode the statement inside a bare DSSE envelope file from a package.
fn statement_in(pkg: &std::path::Path, artifact_id: &str) -> Value {
    let raw = std::fs::read(pkg.join("artifacts").join(format!("{artifact_id}.json"))).unwrap();
    let env: Value = serde_json::from_slice(&raw).unwrap();
    let bytes = URL_SAFE_NO_PAD
        .decode(env["payload"].as_str().unwrap())
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn start_and_act(ws: &Ws) {
    let (ok, out) = ws.run(&["session", "start", "--name", "s", "--actor", "agent://ci"]);
    assert!(ok, "{out}");
    for tool in ["Read", "Write"] {
        let (ok, out) = ws.run(&[
            "session",
            "event",
            "--type",
            "agent.called_tool",
            "--tool",
            tool,
            "--agent-name",
            "ci",
        ]);
        assert!(ok, "{out}");
    }
}

#[test]
fn close_seals_a_coverage_receipt_and_verify_reports_it() {
    let ws = Ws::new();
    start_and_act(&ws);
    let (ok, out) = ws.run(&["session", "close", "--summary", "done", "--format", "json"]);
    assert!(ok, "{out}");
    let close = first_json(&out);
    let session_id = close["session_id"].as_str().unwrap().to_string();
    let coverage_id = close["coverage_artifact_id"]
        .as_str()
        .expect("coverage_artifact_id in close output")
        .to_string();
    assert_eq!(close["coverage_declared_level"], "none");
    let pkg = PathBuf::from(close["package"].as_str().unwrap());

    // Sealed in the chain: listed in receipt.json and present as an envelope.
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(pkg.join("receipt.json")).unwrap()).unwrap();
    let ids: Vec<&str> = receipt["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["artifact_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&coverage_id.as_str()), "{ids:?}");
    assert_eq!(
        ids.last().copied(),
        Some(coverage_id.as_str()),
        "coverage is the chain head"
    );

    let stmt = statement_in(&pkg, &coverage_id);
    assert_eq!(stmt["kind"], "coverage.v1");
    let p = &stmt["payload"];
    assert_eq!(p["schema"], "coverage.v1");
    assert_eq!(p["session_id"], session_id);
    assert_eq!(p["actor"], "agent://ci");
    assert_eq!(p["declared_level"], "none");
    assert_eq!(p["harnesses"].as_array().unwrap().len(), 0);
    // session.started + 2 tool calls + session.closed
    assert_eq!(p["observed"]["events"], 4, "{p}");
    assert_eq!(p["observed"]["event_types"]["agent.called_tool"], 2);
    assert_eq!(p["observed"]["event_types"]["session.closed"], 1);
    assert_eq!(p["observed"]["event_log_skipped"], 0);
    let gaps: Vec<&str> = p["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g.as_str().unwrap())
        .collect();
    assert!(
        gaps.iter().any(|g| g.contains("no harness state")),
        "{gaps:?}"
    );
    assert!(
        !gaps
            .iter()
            .any(|g| g.contains("only the session boundaries")),
        "tool events were captured: {gaps:?}"
    );

    // package verify reports it and still verifies strictly.
    let (ok, out) = ws.run(&[
        "package",
        "verify",
        pkg.to_str().unwrap(),
        "--strict",
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let verdict = first_json(&out);
    assert_eq!(verdict["verdict"], "verified", "{out}");
    let row = verdict["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "coverage")
        .expect("coverage row");
    assert_eq!(row["status"], "pass", "{row}");
    let detail = row["detail"].as_str().unwrap();
    assert!(detail.contains(&coverage_id), "{detail}");
    assert!(detail.contains("declared none"), "{detail}");
    assert!(detail.contains("4 events observed"), "{detail}");
}

#[test]
fn declared_level_and_modes_come_from_harness_state() {
    let ws = Ws::new();
    let harnesses = ws.root.join(".treeship/harnesses");
    std::fs::create_dir_all(&harnesses).unwrap();
    std::fs::write(
        harnesses.join("claude-code.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "harness_id": "claude-code",
            "status": "instrumented",
            "coverage": "high",
            "active_connection_modes": ["native-hook", "mcp", "git-reconcile"],
            "installed_at": "2026-09-18T00:00:00Z",
            "known_gaps": ["Built-in tools the user invokes outside hooks rely on git-reconcile."]
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        harnesses.join("codex.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "harness_id": "codex",
            "status": "disabled",
            "coverage": "medium",
            "active_connection_modes": ["mcp"]
        }))
        .unwrap(),
    )
    .unwrap();

    let (ok, out) = ws.run(&["session", "start", "--name", "s", "--actor", "agent://ci"]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&["session", "close", "--format", "json"]);
    assert!(ok, "{out}");
    let close = first_json(&out);
    assert_eq!(close["coverage_declared_level"], "high");
    let pkg = PathBuf::from(close["package"].as_str().unwrap());
    let stmt = statement_in(&pkg, close["coverage_artifact_id"].as_str().unwrap());
    let p = &stmt["payload"];
    assert_eq!(p["declared_level"], "high");
    let hs = p["harnesses"].as_array().unwrap();
    assert_eq!(
        hs.len(),
        2,
        "every state is listed, disabled included: {hs:?}"
    );
    let cc = hs
        .iter()
        .find(|h| h["harness_id"] == "claude-code")
        .unwrap();
    assert_eq!(cc["status"], "instrumented");
    assert_eq!(
        cc["connection_modes"],
        serde_json::json!(["native-hook", "mcp", "git-reconcile"])
    );
    let gaps: Vec<&str> = p["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g.as_str().unwrap())
        .collect();
    assert!(gaps.iter().any(|g| g.contains("git-reconcile")), "{gaps:?}");
    // No activity events this time: the gap is stated.
    assert!(
        gaps.iter()
            .any(|g| g.contains("only the session boundaries")),
        "{gaps:?}"
    );

    let (ok, out) = ws.run(&[
        "package",
        "verify",
        pkg.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let verdict = first_json(&out);
    let row = verdict["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "coverage")
        .unwrap();
    let detail = row["detail"].as_str().unwrap();
    assert!(detail.contains("declared high"), "{detail}");
    assert!(
        detail.contains("claude-code via native-hook+mcp+git-reconcile"),
        "{detail}"
    );
}
