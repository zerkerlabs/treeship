//! `attest receipt` inside a session follows the same chain rule as
//! `attest action`: minted by the session's own actor it chains onto the
//! session's head, so the sealed package passes `chain_completeness` under
//! `--strict` on a stranger's machine. Found by the evaluator kit: a grade
//! sealed in the evaluator's own grading session was `unchained`.

use std::path::PathBuf;
use std::process::Command;

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

const PAYLOAD: &str = r#"{"schema":"evaluation.v1","subject_kind":"package","subject_digest":"sha256:aa","suite_id":"s","suite_digest":"sha256:bb","result_digest":"sha256:cc","verdict":"pass","evaluated_at":"2026-09-20T00:00:00Z"}"#;

fn attest(ws: &Ws, system: &str, extra: &[&str]) -> String {
    let mut args = vec![
        "attest",
        "receipt",
        "--system",
        system,
        "--kind",
        "evaluation.v1",
        "--payload",
        PAYLOAD,
        "--format",
        "json",
    ];
    args.extend_from_slice(extra);
    let (ok, out) = ws.run(&args);
    assert!(ok, "{out}");
    first_json(&out)["id"].as_str().unwrap().to_string()
}

fn close(ws: &Ws) -> (Value, Value) {
    let (ok, out) = ws.run(&["session", "close", "--format", "json"]);
    assert!(ok, "{out}");
    let close = first_json(&out);
    let pkg = PathBuf::from(close["package"].as_str().unwrap());
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(pkg.join("receipt.json")).unwrap()).unwrap();
    (close, receipt)
}

fn entry<'a>(receipt: &'a Value, id: &str) -> &'a Value {
    receipt["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["artifact_id"] == id)
        .expect("artifact sealed")
}

#[test]
fn receipt_by_the_sessions_actor_chains_and_verifies_strictly() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "session",
        "start",
        "--name",
        "g",
        "--actor",
        "system://evaluator",
    ]);
    assert!(ok, "{out}");
    let id = attest(&ws, "system://evaluator", &[]);
    let (close, receipt) = close(&ws);
    assert_eq!(
        close["sealed_unchained"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        0,
        "{close}"
    );
    assert_eq!(
        entry(&receipt, &id)["unchained"],
        Value::Null,
        "chained entries carry no unchained flag"
    );

    let pkg = close["package"].as_str().unwrap();
    let (ok, out) = ws.run(&["package", "verify", pkg, "--strict", "--format", "json"]);
    assert!(ok, "{out}");
    let v = first_json(&out);
    assert_eq!(v["verdict"], "verified", "{out}");
    let linkage = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "chain_linkage")
        .unwrap();
    assert_eq!(linkage["status"], "pass", "{linkage}");
}

#[test]
fn receipt_by_another_system_is_sealed_loose_with_a_hint() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "session",
        "start",
        "--name",
        "g",
        "--actor",
        "system://evaluator",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&[
        "attest",
        "receipt",
        "--system",
        "system://someone-else",
        "--kind",
        "evaluation.v1",
        "--payload",
        PAYLOAD,
    ]);
    assert!(ok, "{out}");
    assert!(out.contains("sealed loose"), "{out}");
    let (close, _) = close(&ws);
    assert_eq!(
        close["sealed_unchained"].as_array().unwrap().len(),
        1,
        "{close}"
    );
}

#[test]
fn no_parent_keeps_the_receipt_off_the_chain() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "session",
        "start",
        "--name",
        "g",
        "--actor",
        "system://evaluator",
    ]);
    assert!(ok, "{out}");
    let id = attest(&ws, "system://evaluator", &["--no-parent"]);
    let (_, receipt) = close(&ws);
    assert_eq!(entry(&receipt, &id)["unchained"], true);
}

#[test]
fn explicit_parent_is_honoured_and_signed() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "session",
        "start",
        "--name",
        "g",
        "--actor",
        "system://evaluator",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&["session", "status", "--format", "json"]);
    assert!(ok, "{out}");
    let root = first_json(&out)["root_artifact_id"]
        .as_str()
        .unwrap()
        .to_string();
    let id = attest(&ws, "system://someone-else", &["--parent", &root]);
    let (close, receipt) = close(&ws);
    assert_eq!(
        close["sealed_unchained"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        0,
        "{close}"
    );
    assert_eq!(entry(&receipt, &id)["unchained"], Value::Null);
    let (ok, out) = ws.run(&["verify", &id, "--full"]);
    assert!(ok, "{out}");
    assert!(
        out.contains(&root[..16]),
        "the walk reaches the explicit parent: {out}"
    );
}

#[test]
fn outside_a_session_the_subject_is_the_parent() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "attest",
        "action",
        "--actor",
        "agent://a",
        "--action",
        "t",
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let subject = first_json(&out)["id"].as_str().unwrap().to_string();
    let id = attest(&ws, "system://evaluator", &["--subject", &subject]);
    let (ok, out) = ws.run(&["verify", &id, "--full"]);
    assert!(ok, "{out}");
    assert!(out.contains(&subject[..16]), "{out}");
}
