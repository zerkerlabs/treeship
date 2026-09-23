//! Regressions for the 0.31.7 retest: a signed lift outlives a restored
//! marker (T20), a payload's own schema must be the kind (31), `--kind list`
//! and `--help` name every registered predicate (32), `grant --expiry`
//! takes a duration (33), a moved workspace can still sign (N1), the import
//! hint names both pins (N2), and `judge --enforce` puts the decision in
//! the exit code.

use std::path::PathBuf;
use std::process::{Command, Output};

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
        ws.ok(&["init", "--name", "ws"]);
        ws
    }
    fn config(&self) -> String {
        self.root
            .join(".treeship/config.json")
            .display()
            .to_string()
    }
    fn cmd_in(&self, config: &str) -> Command {
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root)
            .env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1")
            .env("TREESHIP_TRUST_ROOTS", self.root.join("trust_roots.json"))
            .env_remove("TREESHIP_KEYSTORE_ORIGIN")
            .current_dir(&self.root)
            .arg("--config")
            .arg(config);
        c
    }
    fn run(&self, args: &[&str]) -> Output {
        self.cmd_in(&self.config()).args(args).output().unwrap()
    }
    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "treeship {args:?} failed:\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    }
    fn fails(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            !out.status.success(),
            "treeship {args:?} unexpectedly succeeded"
        );
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    }
    fn json(&self, args: &[&str]) -> Value {
        let mut full = args.to_vec();
        full.extend(["--format", "json"]);
        let out = self.ok(&full);
        serde_json::Deserializer::from_str(&out)
            .into_iter::<Value>()
            .filter_map(Result::ok)
            .last()
            .unwrap_or_else(|| panic!("no JSON in:\n{out}"))
    }
}

// ── T20 ─────────────────────────────────────────────────────────────────

#[test]
fn a_restored_marker_cannot_re_arm_a_lifted_halt() {
    let ws = Ws::new();
    ws.ok(&["halt", "agent://worker", "--reason", "test"]);
    let marker = ws.root.join(".treeship/halts/agent___worker.json");
    let saved = std::fs::read(&marker).expect("marker written");
    let lift = ws.json(&["halt", "--lift", "agent://worker"]);
    let lift_id = lift["lift"].as_str().unwrap().to_string();
    assert!(!marker.exists(), "lift removes the marker");
    let list = ws.json(&["halt", "list"]);
    assert!(list["halts"].as_array().unwrap().is_empty(), "{list}");

    // Restore the saved marker file: the attack the retest ran.
    std::fs::write(&marker, &saved).unwrap();
    let list = ws.json(&["halt", "list"]);
    let rows = list["halts"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "{list}");
    assert_eq!(rows[0]["honoured"], false, "the signed lift stands: {list}");
    assert_eq!(rows[0]["lifted_by"], lift_id, "{list}");
    assert!(!marker.exists(), "a stale marker is removed on sight");

    // The actor can be halted again afresh; the old marker did not block it.
    ws.ok(&["halt", "agent://worker"]);
    let list = ws.json(&["halt", "list"]);
    assert_eq!(list["halts"][0]["honoured"], true, "{list}");
}

// ── 31 ──────────────────────────────────────────────────────────────────

#[test]
fn a_payload_that_names_a_registered_schema_is_validated_as_that_schema() {
    let ws = Ws::new();
    let payload = r#"{"schema":"evaluation.v1","verdict":"excellent","subject_kind":"session","suite_id":"agent-safety-basic"}"#;
    // Under its own kind: refused, the verdict is outside the vocabulary.
    let out = ws.fails(&[
        "attest",
        "receipt",
        "--system",
        "system://eval",
        "--kind",
        "evaluation.v1",
        "--payload",
        payload,
    ]);
    assert!(out.contains("predicate validation failed"), "{out}");
    // Under an untyped kind: refused too, the payload says what it is.
    let out = ws.fails(&[
        "attest",
        "receipt",
        "--system",
        "system://eval",
        "--kind",
        "confirmation",
        "--payload",
        payload,
    ]);
    assert!(
        out.contains("payload declares schema \"evaluation.v1\" but --kind is \"confirmation\""),
        "{out}"
    );
    // An untyped payload under an untyped kind still signs.
    ws.ok(&[
        "attest",
        "receipt",
        "--system",
        "system://eval",
        "--kind",
        "confirmation",
        "--payload",
        r#"{"status":"ok"}"#,
    ]);
}

// ── 32 ──────────────────────────────────────────────────────────────────

#[test]
fn kind_list_and_help_name_every_registered_predicate() {
    let ws = Ws::new();
    let listed = ws.json(&["attest", "receipt", "--system", "x", "--kind", "list"]);
    let listed: Vec<String> = listed["registered_predicates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    let registry = treeship_core::predicates::registered_suffixes();
    for k in &registry {
        assert!(listed.iter().any(|l| l == k), "--kind list omits {k}");
    }
    let help = String::from_utf8_lossy(
        &Command::new(cli_path())
            .args(["attest", "receipt", "--help"])
            .output()
            .unwrap()
            .stdout,
    )
    .to_string();
    for k in &registry {
        assert!(
            help.contains(k),
            "--help omits registered predicate {k}:\n{help}"
        );
    }
}

// ── 33 ──────────────────────────────────────────────────────────────────

#[test]
fn grant_expiry_takes_a_duration_from_now() {
    let ws = Ws::new();
    let g = ws.json(&[
        "grant",
        "issue",
        "--scope",
        "payments.charge",
        "--audience",
        "acme",
        "--expiry",
        "30d",
    ]);
    let expiry = g["expiry"]
        .as_str()
        .or_else(|| g["grant"]["expiry"].as_str())
        .unwrap_or("");
    assert!(
        expiry.ends_with('Z') && expiry.contains('T'),
        "duration became an RFC 3339 instant: {g}"
    );
    let out = ws.fails(&[
        "grant",
        "issue",
        "--scope",
        "payments.charge",
        "--audience",
        "acme",
        "--expiry",
        "soon",
    ]);
    assert!(
        out.contains("--expiry must be RFC 3339 or a duration from now"),
        "{out}"
    );
}

// ── N1 ──────────────────────────────────────────────────────────────────

#[test]
fn a_workspace_moved_to_another_path_can_still_sign() {
    let ws = Ws::new();
    // Sign once at the original path: the store records where it lives.
    ws.ok(&["attest", "action", "--actor", "agent://a", "--action", "t"]);
    assert!(
        ws.root.join(".treeship/keys/keystore.origin").exists(),
        "origin recorded after a decrypt"
    );

    // Restore the whole workspace somewhere else, as a backup or a fresh
    // container would.
    let moved = tempfile::tempdir().unwrap();
    let dst = moved.path().join("restored");
    copy_dir(&ws.root.join(".treeship"), &dst.join(".treeship"));
    let cfg = dst.join(".treeship/config.json").display().to_string();
    let out = ws
        .cmd_in(&cfg)
        .args(["attest", "action", "--actor", "agent://a", "--action", "t2"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "signing at the new path must work via the recorded origin:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Rewrapped: the second call needs no fallback and the origin moved on.
    let origin = std::fs::read_to_string(dst.join(".treeship/keys/keystore.origin")).unwrap();
    assert!(
        origin.trim().ends_with("restored/.treeship/keys") || origin.contains("restored"),
        "{origin}"
    );

    // A store written before the origin file existed: the variable names
    // the old path once.
    let again = tempfile::tempdir().unwrap();
    let dst2 = again.path().join("again");
    copy_dir(&ws.root.join(".treeship"), &dst2.join(".treeship"));
    std::fs::remove_file(dst2.join(".treeship/keys/keystore.origin")).unwrap();
    let cfg2 = dst2.join(".treeship/config.json").display().to_string();
    let out = ws
        .cmd_in(&cfg2)
        .args(["attest", "action", "--actor", "agent://a", "--action", "t3"])
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "without the origin the move is still fatal"
    );
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        err.contains("TREESHIP_KEYSTORE_ORIGIN"),
        "the error names the recovery: {err}"
    );
    let out = ws
        .cmd_in(&cfg2)
        .env("TREESHIP_KEYSTORE_ORIGIN", ws.root.display().to_string())
        .args(["attest", "action", "--actor", "agent://a", "--action", "t3"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // And it sticks: no variable on the next call.
    let out = ws
        .cmd_in(&cfg2)
        .args(["attest", "action", "--actor", "agent://a", "--action", "t4"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "rewrapped under the new path: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let p = e.path();
        let t = to.join(e.file_name());
        if p.is_dir() {
            copy_dir(&p, &t);
        } else {
            std::fs::copy(&p, &t).unwrap();
        }
    }
}

// ── N2 ──────────────────────────────────────────────────────────────────

#[test]
fn the_import_refusal_shows_both_pins_and_says_which_is_which() {
    let a = Ws::new();
    let b = Ws::new();
    let act = a.json(&["attest", "action", "--actor", "agent://a", "--action", "t"]);
    let id = act["id"].as_str().unwrap().to_string();
    let bundle = a.json(&["bundle", "create", "--artifacts", &id]);
    let bid = bundle["id"]
        .as_str()
        .or_else(|| bundle["artifact_id"].as_str())
        .unwrap()
        .to_string();
    let out = a.root.join("x.treeship");
    a.ok(&["bundle", "export", &bid, "--out", out.to_str().unwrap()]);
    let err = b.fails(&["bundle", "import", out.to_str().unwrap()]);
    assert!(
        err.contains("--kind agent_cert --yes    # if it is an agent's own key"),
        "{err}"
    );
    assert!(
        err.contains("--kind cert_issuer --yes   # if it is the ship key"),
        "{err}"
    );
}

// ── judge --enforce ──────────────────────────────────────────────────────

#[test]
fn judge_enforce_puts_the_decision_in_the_exit_code() {
    let ws = Ws::new();
    let out = ws.run(&[
        "judge",
        "--tool",
        "Bash",
        "--input",
        r#"{"command":"rm -rf /"}"#,
        "--enforce",
    ]);
    assert_eq!(out.status.code(), Some(2), "deny exits 2");
    let out = ws.run(&[
        "judge",
        "--tool",
        "Bash",
        "--input",
        r#"{"command":"ls"}"#,
        "--enforce",
    ]);
    assert_eq!(out.status.code(), Some(0), "allow exits 0");
    let out = ws.run(&[
        "judge",
        "--tool",
        "Bash",
        "--input",
        r#"{"command":"rm -rf /"}"#,
    ]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "without --enforce the decision is in the output only"
    );
}
