//! Regressions for the findings from filming the integrations (2026-09-22).
//! Each test is one numbered finding or one gate-report cause, in the shape
//! the report reproduced it.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use serde_json::Value;
use tempfile::TempDir;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

/// A workspace with its own keystore under `<root>/.treeship/`.
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
            .cmd_in(&ws.root)
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
    fn cmd_in(&self, dir: &Path) -> Command {
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root)
            .env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1")
            .env("TREESHIP_TRUST_ROOTS", self.root.join("trust_roots.json"))
            .current_dir(dir);
        c
    }
    fn run(&self, args: &[&str]) -> (bool, String) {
        let out = self
            .cmd_in(&self.root)
            .args(args)
            .args(["--config"])
            .arg(self.config())
            .output()
            .unwrap();
        (out.status.success(), text(&out))
    }
}

fn text(out: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn first_json(out: &str) -> Value {
    let start = out.find('{').expect("json object in output");
    let mut de = serde_json::Deserializer::from_str(&out[start..]);
    Value::deserialize(&mut de).expect("parse json")
}

fn row<'a>(verdict: &'a Value, name: &str) -> Option<&'a Value> {
    verdict["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
}

// ---------------------------------------------------------------------------
// #1: an action then a receipt about it, both by the session's actor, sealed
// as chained steps with a signed parent. Was FAIL chain_linkage.
// ---------------------------------------------------------------------------
#[test]
fn finding_1_receipt_about_an_action_by_the_session_actor_verifies_strictly() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&["session", "start", "--name", "r", "--actor", "agent://x"]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&[
        "attest",
        "action",
        "--actor",
        "agent://x",
        "--action",
        "t.intent",
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let a = first_json(&out)["id"].as_str().unwrap().to_string();
    let (ok, out) = ws.run(&[
        "attest",
        "receipt",
        "--system",
        "agent://x",
        "--kind",
        "tool.result",
        "--subject",
        &a,
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&["session", "close", "--headline", "r", "--format", "json"]);
    assert!(ok, "{out}");
    let pkg = first_json(&out)["package"].as_str().unwrap().to_string();
    let (ok, out) = ws.run(&["package", "verify", &pkg, "--strict", "--format", "json"]);
    assert!(ok, "{out}");
    let v = first_json(&out);
    assert_eq!(v["verdict"], "verified", "{out}");
    assert_eq!(row(&v, "chain_linkage").unwrap()["status"], "pass");
}

// ---------------------------------------------------------------------------
// #5: a unique prefix resolves; the hint prints the full id.
// ---------------------------------------------------------------------------
#[test]
fn finding_5_verify_resolves_a_unique_prefix_and_prints_full_ids() {
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
    let id = first_json(&out)["id"].as_str().unwrap().to_string();
    let (ok, out) = ws.run(&["verify", &id[..16]]);
    assert!(ok, "prefix must resolve: {out}");
    assert!(out.contains(&id), "hint prints the full id: {out}");
    let (ok, out) = ws.run(&["verify", "art_zz"]);
    assert!(!ok, "{out}");
    assert!(out.contains("not found"), "{out}");
}

// ---------------------------------------------------------------------------
// #8 / gate report: receipt_body_binding says the body is bound when the
// close record binds receipt.json, instead of contradicting receipt_binding.
// ---------------------------------------------------------------------------
#[test]
fn finding_8_body_binding_row_agrees_with_the_close_record() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&["session", "start", "--name", "s", "--actor", "agent://a"]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&["session", "close", "--format", "json"]);
    assert!(ok, "{out}");
    let pkg = first_json(&out)["package"].as_str().unwrap().to_string();
    let (ok, out) = ws.run(&["package", "verify", &pkg, "--format", "json"]);
    assert!(ok, "{out}");
    let v = first_json(&out);
    assert_eq!(row(&v, "receipt_binding").unwrap()["status"], "pass");
    let body = row(&v, "receipt_body_binding").unwrap();
    assert_eq!(body["status"], "pass", "{body}");
    assert!(
        body["detail"].as_str().unwrap().contains("record.json"),
        "{body}"
    );
    // On the producer's machine signer_trust says whose keys these are.
    let st = row(&v, "signer_trust").unwrap();
    assert_eq!(st["status"], "pass");
    assert!(
        st["detail"].as_str().unwrap().contains("this ship's own"),
        "{st}"
    );
}

// ---------------------------------------------------------------------------
// #13: the pin command a stranger is told to paste runs non-interactively.
// ---------------------------------------------------------------------------
#[test]
fn finding_13_pin_hint_carries_yes() {
    let producer = Ws::new();
    let (ok, out) = producer.run(&["session", "start", "--name", "s", "--actor", "agent://a"]);
    assert!(ok, "{out}");
    let (ok, out) = producer.run(&["session", "close", "--format", "json"]);
    assert!(ok, "{out}");
    let pkg = first_json(&out)["package"].as_str().unwrap().to_string();
    let stranger = Ws::new();
    let (_ok, out) = stranger.run(&["package", "verify", &pkg, "--format", "json"]);
    let v = first_json(&out);
    let st = row(&v, "signer_trust").unwrap();
    assert_eq!(st["status"], "warn", "{st}");
    let detail = st["detail"].as_str().unwrap();
    assert!(detail.contains("--kind cert_issuer --yes"), "{detail}");
    // And the pasted command works.
    let cmd: Vec<&str> = detail
        .split("treeship ")
        .last()
        .unwrap()
        .split_whitespace()
        .collect();
    let (ok, out) = stranger.run(&cmd);
    assert!(ok, "pasted pin command must run: {out}");
}

// ---------------------------------------------------------------------------
// #9: Treeship's own files are not the agent's writes.
// ---------------------------------------------------------------------------
#[test]
fn finding_9_first_receipt_does_not_list_treeship_config_as_written() {
    // The documented quickstart: a plain git project, `treeship init` in it,
    // one real edit. HOME is elsewhere so the git root is the project.
    let home = tempfile::tempdir().unwrap();
    let proj = tempfile::tempdir().unwrap();
    let run = |args: &[&str]| {
        let out = Command::new(cli_path())
            .current_dir(proj.path())
            .env("HOME", home.path())
            .env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1")
            .env("TREESHIP_TRUST_ROOTS", home.path().join("trust_roots.json"))
            .args(args)
            .args(["--config", ".treeship/config.json"])
            .output()
            .unwrap();
        (out.status.success(), text(&out))
    };
    let git = |args: &[&str]| {
        let st = Command::new("git")
            .args(args)
            .current_dir(proj.path())
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .status()
            .unwrap();
        assert!(st.success(), "git {args:?}");
    };
    git(&["init", "-q"]);
    std::fs::write(proj.path().join("cart.js"), "1").unwrap();
    git(&["add", "cart.js"]);
    git(&["commit", "-qm", "base"]);
    let (ok, out) = run(&["init", "--name", "qs"]);
    assert!(ok, "{out}");
    let (ok, out) = run(&["session", "start", "--name", "s", "--actor", "agent://a"]);
    assert!(ok, "{out}");
    std::fs::write(proj.path().join("cart.js"), "2").unwrap();
    let (ok, out) = run(&["session", "close", "--format", "json"]);
    assert!(ok, "{out}");
    let pkg = first_json(&out)["package"].as_str().unwrap().to_string();
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(Path::new(&pkg).join("receipt.json")).unwrap())
            .unwrap();
    let written: Vec<String> = receipt["side_effects"]["files_written"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|f| f["file_path"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert!(
        written.iter().any(|p| p.ends_with("cart.js")),
        "{written:?}"
    );
    assert!(
        !written.iter().any(|p| p.contains(".treeship/")),
        "Treeship's own files listed as written: {written:?}"
    );
}

// ---------------------------------------------------------------------------
// #10: a stub whose extends target is gone is named, not chased in circles.
// ---------------------------------------------------------------------------
#[test]
fn finding_10_dangling_stub_is_named_by_init_and_doctor() {
    let home = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    let stub_dir = parent.path().join(".treeship");
    std::fs::create_dir_all(&stub_dir).unwrap();
    let stub = stub_dir.join("config.json");
    std::fs::write(
        &stub,
        serde_json::to_vec_pretty(&serde_json::json!({
            "extends": parent.path().join("gone").join(".treeship").join("config.json"),
            "project": true
        }))
        .unwrap(),
    )
    .unwrap();
    let sub = parent.path().join("work");
    std::fs::create_dir_all(&sub).unwrap();
    let run = |args: &[&str]| {
        let out = Command::new(cli_path())
            .current_dir(&sub)
            .env("HOME", home.path())
            .env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1")
            .args(args)
            .output()
            .unwrap();
        (out.status.success(), text(&out))
    };
    let (ok, out) = run(&["init"]);
    assert!(!ok);
    assert!(!out.contains("already initialized"), "{out}");
    assert!(out.contains("leftover project stub"), "{out}");
    assert!(out.contains(&stub.display().to_string()), "{out}");
    let (_ok, out) = run(&["doctor"]);
    assert!(
        out.contains("leftover project stub"),
        "doctor names the stub: {out}"
    );
}

// ---------------------------------------------------------------------------
// #11: a single-use grant is single-use across every config that shares the
// keystore. A project stub extending the global config shares its journal.
// ---------------------------------------------------------------------------
#[test]
fn finding_11_single_use_holds_across_a_project_stub_and_the_global_workspace() {
    let home = tempfile::tempdir().unwrap();
    let pay = home.path().join("pay");
    std::fs::create_dir_all(&pay).unwrap();
    let run = |dir: &Path, args: &[&str]| {
        let out = Command::new(cli_path())
            .current_dir(dir)
            .env("HOME", home.path())
            .env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1")
            .env("TREESHIP_TRUST_ROOTS", home.path().join("trust_roots.json"))
            .args(args)
            .output()
            .unwrap();
        (out.status.success(), text(&out))
    };
    let (ok, out) = run(home.path(), &["init", "--global"]);
    assert!(ok, "{out}");
    // The stub `treeship init` writes into a project: extends the global.
    let stub_dir = pay.join(".treeship");
    std::fs::create_dir_all(&stub_dir).unwrap();
    std::fs::write(
        stub_dir.join("config.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "extends": home.path().join(".treeship").join("config.json"),
            "project": true
        }))
        .unwrap(),
    )
    .unwrap();

    let (ok, out) = run(
        &pay,
        &[
            "attest",
            "approval",
            "--approver",
            "human://alice",
            "--allowed-actor",
            "agent://payments",
            "--allowed-action",
            "payments.refund",
            "--max-uses",
            "1",
            "--format",
            "json",
        ],
    );
    assert!(ok, "{out}");
    let nonce = first_json(&out)["nonce"].as_str().unwrap().to_string();
    let act = |dir: &Path| {
        run(
            dir,
            &[
                "attest",
                "action",
                "--actor",
                "agent://payments",
                "--action",
                "payments.refund",
                "--approval-nonce",
                &nonce,
                "--format",
                "json",
            ],
        )
    };
    let (ok, out) = act(&pay);
    assert!(ok, "first use: {out}");
    let first_id = first_json(&out)["id"].as_str().unwrap().to_string();
    let (ok, out) = act(&pay);
    assert!(!ok, "second use in the same dir must be refused: {out}");
    let (ok, out) = act(home.path());
    assert!(
        !ok,
        "second use from the global workspace must be refused too: {out}"
    );
    assert!(out.contains("max_uses"), "{out}");
    // The journal lives beside the keystore, not beside the stub.
    assert!(home.path().join(".treeship/journals/approval-use").is_dir());
    assert!(!stub_dir.join("journals").exists());
    // Verifying the one real use from the other directory still passes.
    let (ok, out) = run(home.path(), &["verify", &first_id, "--full"]);
    assert!(ok, "{out}");
    assert!(out.contains("use 1/1"), "{out}");
}

// ---------------------------------------------------------------------------
// Gate report cause 1: re-registering with no rule flags keeps the rules.
// ---------------------------------------------------------------------------
#[test]
fn gate_register_without_rule_flags_keeps_the_cards_rules() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&[
        "agent",
        "register",
        "--name",
        "claude-code",
        "--tools",
        "file.read,file.write",
        "--forbidden",
        "shell.exec,net.fetch",
        "--quiet",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&[
        "agent",
        "register",
        "--own-key",
        "--quiet",
        "--name",
        "claude-code",
    ]);
    assert!(ok, "{out}");
    let card = std::fs::read_dir(ws.root.join(".treeship/agents"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter_map(|p| serde_json::from_slice::<Value>(&std::fs::read(p).ok()?).ok())
        .find(|c| c["agent_name"] == "claude-code")
        .expect("card");
    assert_eq!(
        card["capabilities"]["forbidden"],
        serde_json::json!(["shell.exec", "net.fetch"]),
        "{card}"
    );
    assert_eq!(
        card["capabilities"]["bounded_tools"],
        serde_json::json!(["file.read", "file.write"]),
        "{card}"
    );
    assert!(
        card["key_id"].as_str().is_some(),
        "own key recorded: {card}"
    );
    // Explicit flags still replace.
    let (ok, out) = ws.run(&[
        "agent",
        "register",
        "--name",
        "claude-code",
        "--tools",
        "file.read",
        "--quiet",
    ]);
    assert!(ok, "{out}");
    let card = std::fs::read_dir(ws.root.join(".treeship/agents"))
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter_map(|p| serde_json::from_slice::<Value>(&std::fs::read(p).ok()?).ok())
        .find(|c| c["agent_name"] == "claude-code")
        .expect("card");
    assert_eq!(
        card["capabilities"]["bounded_tools"],
        serde_json::json!(["file.read"])
    );
    assert!(card["capabilities"]["forbidden"].is_null(), "{card}");
}
