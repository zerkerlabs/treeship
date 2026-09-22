//! Retries as a signed chain: `attest action --retry-of <id> --attempt N
//! --retry-cause <c>` puts the reason for a second attempt inside the
//! signature, and `package verify` reports every chain as the `retries` row:
//! a recovery (same action, same key, one effect) passes; two attempts that
//! each report a distinct effect are named.

use std::path::PathBuf;
use std::process::Command;

use base64::Engine;
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

fn act(ws: &Ws, extra: &[&str]) -> String {
    let mut args = vec![
        "attest",
        "action",
        "--actor",
        "agent://ops",
        "--action",
        "tickets.create",
        "--format",
        "json",
    ];
    args.extend_from_slice(extra);
    let (ok, out) = ws.run(&args);
    assert!(ok, "{out}");
    first_json(&out)["id"].as_str().unwrap().to_string()
}

fn close_and_verify(ws: &Ws) -> Value {
    let (ok, out) = ws.run(&["session", "close", "--format", "json"]);
    assert!(ok, "{out}");
    let pkg = first_json(&out)["package"].as_str().unwrap().to_string();
    let (ok, out) = ws.run(&["package", "verify", &pkg, "--strict", "--format", "json"]);
    assert!(ok, "{out}");
    let v = first_json(&out);
    assert_eq!(v["verdict"], "verified", "{out}");
    v
}

fn row<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
}

#[test]
fn a_recovery_passes_and_a_duplicate_is_named() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&["session", "start", "--name", "s", "--actor", "agent://ops"]);
    assert!(ok, "{out}");

    // Chain 1: a timeout, retried with the same key, the same effect once.
    let a1 = act(
        &ws,
        &[
            "--idempotency-key",
            "tkt-42",
            "--output-digest",
            &format!("sha256:{}", "aa".repeat(32)),
        ],
    );
    let a2 = act(
        &ws,
        &[
            "--retry-of",
            &a1,
            "--attempt",
            "2",
            "--retry-cause",
            "timeout",
            "--backoff-ms",
            "800",
            "--idempotency-key",
            "tkt-42",
            "--output-digest",
            &format!("sha256:{}", "aa".repeat(32)),
        ],
    );
    // Chain 2: retried after an error, and the two attempts report different effects.
    let b1 = act(
        &ws,
        &[
            "--idempotency-key",
            "tkt-43",
            "--output-digest",
            &format!("sha256:{}", "bb".repeat(32)),
        ],
    );
    let b2 = act(
        &ws,
        &[
            "--retry-of",
            &b1,
            "--attempt",
            "2",
            "--retry-cause",
            "error",
            "--idempotency-key",
            "tkt-43",
            "--output-digest",
            &format!("sha256:{}", "cc".repeat(32)),
        ],
    );

    // The retry block is inside the signed statement, not only in storage.
    let (ok, out) = ws.run(&["verify", &a2, "--full"]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&["receipt", "export", &a2, "--format", "json"]);
    assert!(ok, "{out}");
    let exported = first_json(&out);
    let msg = base64::engine::general_purpose::STANDARD
        .decode(exported["message_b64"].as_str().unwrap())
        .unwrap();
    let msg = String::from_utf8_lossy(&msg);
    assert!(
        msg.contains("\"retry\":{")
            && msg.contains("\"cause\":\"timeout\"")
            && msg.contains("\"idempotencyKey\":\"tkt-42\""),
        "retry and key are inside the signed bytes: {msg}"
    );

    let v = close_and_verify(&ws);
    let r = row(&v, "retries").expect("retries row");
    assert_eq!(r["status"], "warn", "{r}");
    let d = r["detail"].as_str().unwrap();
    assert!(d.contains("2 retry attempt(s) across 2 chain(s)"), "{d}");
    assert!(
        d.contains(&b2) && d.contains("two mutations, not one recovery"),
        "{d}"
    );
    assert!(!d.contains(&a2), "the clean chain is not named: {d}");
}

#[test]
fn clean_chains_pass_and_keys_are_checked() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&["session", "start", "--name", "s", "--actor", "agent://ops"]);
    assert!(ok, "{out}");
    let a1 = act(&ws, &["--idempotency-key", "k1"]);
    let _a2 = act(
        &ws,
        &[
            "--retry-of",
            &a1,
            "--retry-cause",
            "rate_limited",
            "--idempotency-key",
            "k1",
        ],
    );
    let v = close_and_verify(&ws);
    let r = row(&v, "retries").unwrap();
    assert_eq!(r["status"], "pass", "{r}");
    assert!(
        r["detail"]
            .as_str()
            .unwrap()
            .contains("1 retry attempt(s) across 1 chain(s)"),
        "{r}"
    );

    let ws = Ws::new();
    let (ok, out) = ws.run(&["session", "start", "--name", "s", "--actor", "agent://ops"]);
    assert!(ok, "{out}");
    let c1 = act(&ws, &["--idempotency-key", "k1"]);
    let c2 = act(
        &ws,
        &[
            "--retry-of",
            &c1,
            "--retry-cause",
            "error",
            "--idempotency-key",
            "k2",
        ],
    );
    let v = close_and_verify(&ws);
    let r = row(&v, "retries").unwrap();
    assert_eq!(r["status"], "warn", "{r}");
    assert!(r["detail"].as_str().unwrap().contains(&c2), "{r}");
    assert!(
        r["detail"]
            .as_str()
            .unwrap()
            .contains("different idempotency key"),
        "{r}"
    );
}

#[test]
fn half_specified_and_out_of_vocabulary_retries_are_refused() {
    let ws = Ws::new();
    let a1 = act(&ws, &[]);
    let (ok, out) = ws.run(&[
        "attest",
        "action",
        "--actor",
        "agent://ops",
        "--action",
        "t",
        "--retry-of",
        &a1,
        "--retry-cause",
        "boredom",
    ]);
    assert!(!ok, "{out}");
    assert!(out.contains("--retry-cause must be one of"), "{out}");
    let (ok, out) = ws.run(&[
        "attest",
        "action",
        "--actor",
        "agent://ops",
        "--action",
        "t",
        "--retry-of",
        &a1,
        "--attempt",
        "1",
    ]);
    assert!(!ok, "{out}");
    assert!(out.contains("first attempt is not a retry"), "{out}");
    let (ok, out) = ws.run(&[
        "attest",
        "action",
        "--actor",
        "agent://ops",
        "--action",
        "t",
        "--attempt",
        "2",
    ]);
    assert!(!ok, "clap requires --retry-of: {out}");

    // No retries in a package: no row.
    let (ok, out) = ws.run(&["session", "start", "--name", "s", "--actor", "agent://ops"]);
    assert!(ok, "{out}");
    act(&ws, &[]);
    let v = close_and_verify(&ws);
    assert!(row(&v, "retries").is_none());
}
