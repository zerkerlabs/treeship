//! `evaluation.v1` end to end through the CLI: an evaluator signs a result
//! about a sealed session, the receipt chains onto the session's close
//! artifact, and an out-of-vocabulary verdict is refused before signing.

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

#[test]
fn evaluator_grades_a_sealed_session_and_the_grade_chains_onto_it() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "session",
        "start",
        "--name",
        "graded",
        "--actor",
        "agent://subject",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&[
        "attest",
        "action",
        "--actor",
        "agent://subject",
        "--action",
        "tool.call",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&[
        "session",
        "close",
        "--headline",
        "graded run",
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let closed: Value = serde_json::from_str(out.trim()).unwrap();
    // The close JSON names the package; the receipt inside lists the sealed
    // artifacts in chain order, and the last one is the session's close.
    let package = closed["package"].as_str().unwrap();
    let receipt: Value = serde_json::from_str(
        &std::fs::read_to_string(PathBuf::from(package).join("receipt.json")).unwrap(),
    )
    .unwrap();
    let close_id = receipt["artifacts"]
        .as_array()
        .and_then(|a| a.last())
        .and_then(|a| a["artifact_id"].as_str())
        .unwrap_or_default()
        .to_string();
    assert!(
        close_id.starts_with("art_"),
        "receipt artifacts: {}",
        receipt["artifacts"]
    );

    let payload = format!(
        r#"{{"schema":"evaluation.v1","subject_kind":"session","subject_digest":"{close_id}","subject_actor":"agent://subject","suite_id":"sandbox-escape-v3","suite_digest":"sha256:bb22","environment_digest":"sha256:ee55","result_digest":"sha256:cc33","verdict":"pass","score":0.02,"threshold":0.05,"capability":"sandbox-escape","evaluated_at":"2026-09-17T18:00:00Z"}}"#
    );
    let (ok, out) = ws.run(&[
        "attest",
        "receipt",
        "--system",
        "system://evaluator-metr",
        "--kind",
        "evaluation.v1",
        "--subject",
        &close_id,
        "--payload",
        &payload,
        "--format",
        "json",
    ]);
    assert!(ok, "evaluation receipt: {out}");
    let grade: Value = serde_json::from_str(out.trim()).unwrap();
    let grade_id = grade["id"].as_str().unwrap().to_string();

    let (ok, out) = ws.run(&["verify", &grade_id]);
    assert!(ok, "verify: {out}");
    assert!(out.contains("chain intact"), "{out}");
    let (ok, out) = ws.run(&["verify", &grade_id, "--full"]);
    assert!(ok, "{out}");
    assert!(
        out.contains(&close_id[..16]),
        "the grade should walk to the session it grades: {out}"
    );
}

#[test]
fn out_of_vocabulary_verdict_is_refused_before_signing() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "attest",
        "receipt",
        "--system",
        "system://evaluator-metr",
        "--kind",
        "evaluation.v1",
        "--payload",
        r#"{"schema":"evaluation.v1","subject_kind":"model","subject_digest":"sha256:aa","suite_id":"s","suite_digest":"sha256:bb","result_digest":"sha256:cc","verdict":"mostly","evaluated_at":"2026-09-17T18:00:00Z"}"#,
    ]);
    assert!(!ok, "{out}");
    assert!(out.contains("verdict"), "{out}");
}
