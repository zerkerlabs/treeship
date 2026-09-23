//! `judgement.v1` end to end: a judge's typed answer is attested by the
//! caller inside its session, chained onto the action it gated, sealed, and
//! reported by `package verify` as the `judgements` row, which flags a
//! judgement acted on below its own bar. Nested vocabulary is refused before
//! signing.

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

fn judgement(noul: f64, threshold: Option<f64>, outcome: &str) -> String {
    let mut p = serde_json::json!({
        "schema": "judgement.v1",
        "judge": {"model": "jev-1.13.0", "provider": "typesafe", "kind": "decision-model", "replayable": false},
        "state_digest": format!("sha256:{}", "ab".repeat(32)),
        "questions_digest": format!("sha256:{}", "cd".repeat(32)),
        "question": {"key": "destructive", "type": "noul", "instructions": "Does this command delete files outside the workspace?"},
        "answer": {"noul": noul},
        "outcome": outcome,
        "effect": if outcome == "refused" { "deny" } else { "allow" },
        "judged_at": "2026-09-22T20:00:00Z"
    });
    if let Some(t) = threshold {
        p["threshold"] = serde_json::json!({"value": t, "applies_to": "noul", "set_by": "card:agent://claude-code"});
    }
    p.to_string()
}

fn attest_judgement(ws: &Ws, payload: &str, subject: &str) -> (bool, String) {
    ws.run(&[
        "attest",
        "receipt",
        "--system",
        "agent://claude-code",
        "--kind",
        "judgement.v1",
        "--subject",
        subject,
        "--payload",
        payload,
        "--format",
        "json",
    ])
}

#[test]
fn judgement_chains_onto_the_gated_action_and_verify_reports_it() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "session",
        "start",
        "--name",
        "s",
        "--actor",
        "agent://claude-code",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&[
        "attest",
        "action",
        "--actor",
        "agent://claude-code",
        "--action",
        "shell.exec",
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let action = first_json(&out)["id"].as_str().unwrap().to_string();

    // Refused at 0.93 against a 0.85 bar: within its bar.
    let (ok, out) = attest_judgement(&ws, &judgement(0.93, Some(0.85), "refused"), &action);
    assert!(ok, "{out}");
    let j1 = first_json(&out)["id"].as_str().unwrap().to_string();
    // Allowed at 0.93 against a 0.85 bar: the answer was yes and the caller
    // proceeded anyway. Outside its bar.
    let (ok, out) = attest_judgement(&ws, &judgement(0.93, Some(0.85), "acted"), &action);
    assert!(ok, "{out}");
    let j2 = first_json(&out)["id"].as_str().unwrap().to_string();
    // Allowed at 0.40 against a 0.85 bar: the answer was no and the caller
    // proceeded. That is what the bar asked for, not a violation.
    let (ok, out) = attest_judgement(&ws, &judgement(0.40, Some(0.85), "acted"), &action);
    assert!(ok, "{out}");
    let j3 = first_json(&out)["id"].as_str().unwrap().to_string();

    let (ok, out) = ws.run(&["verify", &j1, "--full"]);
    assert!(ok, "{out}");
    assert!(
        out.contains(&action[..16]),
        "judgement walks to the action: {out}"
    );

    let (ok, out) = ws.run(&["session", "close", "--format", "json"]);
    assert!(ok, "{out}");
    let pkg = first_json(&out)["package"].as_str().unwrap().to_string();
    let (ok, out) = ws.run(&["package", "verify", &pkg, "--strict", "--format", "json"]);
    assert!(ok, "{out}");
    let v = first_json(&out);
    assert_eq!(v["verdict"], "verified", "{out}");
    let row = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "judgements")
        .expect("judgements row");
    assert_eq!(row["status"], "warn", "{row}");
    let d = row["detail"].as_str().unwrap();
    assert!(d.contains("3 judgement(s) by jev-1.13.0"), "{d}");
    assert!(
        d.contains(&j2)
            && d.contains("at or above its threshold")
            && d.contains("the answer was yes"),
        "{d}"
    );
    assert!(!d.contains(&j1), "the in-bar refusal is not flagged: {d}");
    assert!(
        !d.contains(&j3),
        "proceeding on a no is inside the bar: {d}"
    );
}

#[test]
fn a_package_without_judgements_has_no_row() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&["session", "start", "--name", "s", "--actor", "agent://a"]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&["session", "close", "--format", "json"]);
    assert!(ok, "{out}");
    let pkg = first_json(&out)["package"].as_str().unwrap().to_string();
    let (ok, out) = ws.run(&["package", "verify", &pkg, "--format", "json"]);
    assert!(ok, "{out}");
    let v = first_json(&out);
    assert!(v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .all(|c| c["name"] != "judgements"));
}

#[test]
fn nested_vocabulary_is_refused_before_signing() {
    let ws = Ws::new();
    let bad = judgement(0.9, Some(0.8), "acted").replace("\"type\":\"noul\"", "\"type\":\"essay\"");
    assert!(bad.contains("essay"));
    let (ok, out) = ws.run(&[
        "attest",
        "receipt",
        "--system",
        "agent://claude-code",
        "--kind",
        "judgement.v1",
        "--payload",
        &bad,
    ]);
    assert!(!ok, "{out}");
    assert!(
        out.contains("question.type"),
        "dotted path in the error: {out}"
    );
    let bad = judgement(1.7, Some(0.8), "acted");
    let (ok, out) = ws.run(&[
        "attest",
        "receipt",
        "--system",
        "agent://claude-code",
        "--kind",
        "judgement.v1",
        "--payload",
        &bad,
    ]);
    assert!(!ok, "{out}");
    assert!(out.contains("answer.noul"), "{out}");
}
