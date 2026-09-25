//! `session close --receipt-dir <DIR>` copies the sealed package out of the
//! workspace and prints a `Treeship-Receipt` commit trailer whose digest is
//! the sha256 of the copied `receipt.json`. This is what the verify-receipts
//! GitHub Action recomputes, so the two must agree byte for byte.

use std::path::PathBuf;
use std::process::Command;

use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
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

#[test]
fn close_copies_package_and_prints_matching_trailer() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&["session", "start", "--name", "s", "--actor", "agent://ci"]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&[
        "session",
        "event",
        "--type",
        "agent.called_tool",
        "--tool",
        "Read",
        "--agent-name",
        "ci",
    ]);
    assert!(ok, "{out}");

    let receipt_dir = ws.root.join("out/receipts");
    let (ok, out) = ws.run(&[
        "session",
        "close",
        "--summary",
        "done",
        "--receipt-dir",
        receipt_dir.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let close = first_json(&out);
    let session_id = close["session_id"].as_str().unwrap();
    let digest = close["receipt_digest"].as_str().unwrap();
    let trailer = close["commit_trailer"].as_str().unwrap();
    let copy = PathBuf::from(close["receipt_copy"].as_str().unwrap());

    assert_eq!(trailer, format!("Treeship-Receipt: {session_id} {digest}"));
    assert_eq!(copy, receipt_dir.join(format!("{session_id}.treeship")));

    // The copy carries the whole sealed set, including the close record.
    for f in ["receipt.json", "merkle.json", "record.json", "keys.json"] {
        assert!(copy.join(f).is_file(), "missing {f} in the copied package");
    }
    assert!(copy.join("artifacts").is_dir());

    // The trailer's digest is sha256(receipt.json) of the copy, which is
    // what the PR check recomputes.
    let bytes = std::fs::read(copy.join("receipt.json")).unwrap();
    let recomputed = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    assert_eq!(digest, recomputed);

    // And the copy verifies strictly on its own.
    let (ok, out) = ws.run(&[
        "package",
        "verify",
        copy.to_str().unwrap(),
        "--strict",
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let verdict = first_json(&out);
    assert_eq!(verdict["verdict"], "verified", "{out}");
}

#[test]
fn close_without_receipt_dir_still_prints_trailer_and_copies_nothing() {
    let ws = Ws::new();
    let (ok, out) = ws.run(&["session", "start", "--name", "s", "--actor", "agent://ci"]);
    assert!(ok, "{out}");
    let (ok, out) = ws.run(&["session", "close", "--format", "json"]);
    assert!(ok, "{out}");
    let close = first_json(&out);
    assert!(close["commit_trailer"]
        .as_str()
        .unwrap()
        .starts_with("Treeship-Receipt: ssn_"));
    assert!(close["receipt_copy"].is_null());
}

/// The close record is signed by the actor's own key when the actor has one.
/// That key was minted after `keys.json` was written, so a package closed by
/// a registered agent named every signer except the one on `record.json` and
/// failed `receipt_binding` on any machine but the producer's. Found by the
/// verify-receipts PR check on its own first package.
#[test]
fn package_closed_by_own_key_agent_verifies_on_another_machine() {
    let producer = Ws::new();
    let (ok, out) = producer.run(&[
        "agent",
        "register",
        "--name",
        "coder",
        "--own-key",
        "--quiet",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = producer.run(&[
        "session",
        "start",
        "--name",
        "s",
        "--actor",
        "agent://coder",
    ]);
    assert!(ok, "{out}");
    let (ok, out) = producer.run(&[
        "session",
        "event",
        "--type",
        "agent.called_tool",
        "--tool",
        "Read",
        "--agent-name",
        "coder",
    ]);
    assert!(ok, "{out}");
    let receipt_dir = producer.root.join("out/receipts");
    let (ok, out) = producer.run(&[
        "session",
        "close",
        "--receipt-dir",
        receipt_dir.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(ok, "{out}");
    let close = first_json(&out);
    let copy = PathBuf::from(close["receipt_copy"].as_str().unwrap());

    // record.json's signer must be named in keys.json.
    let record: Value =
        serde_json::from_slice(&std::fs::read(copy.join("record.json")).unwrap()).unwrap();
    let record_key = record["signatures"][0]["keyid"]
        .as_str()
        .unwrap()
        .to_string();
    let keys: Value =
        serde_json::from_slice(&std::fs::read(copy.join("keys.json")).unwrap()).unwrap();
    assert!(
        keys["keys"].get(&record_key).is_some(),
        "keys.json does not carry the record signer {record_key}: {keys}"
    );

    // The agent's key signs the record and none of the sealed artifacts (the
    // ship key signs start and close). A record like that is byte-for-byte
    // what a forged record under a key added to keys.json looks like, so a
    // stranger who pinned only the ship key must not get `verified`: the
    // agent key has to be pinned too.
    let (ok, out) = producer.run(&["keys", "export", "--format", "json"]);
    assert!(ok, "{out}");
    let export = first_json(&out);
    let ship_root = serde_json::json!({
        "key_id": export["key_id"],
        "public_key": export["public_key"],
        "kind": "session_host",
        "label": "producer",
        "added_at": "2026-09-18T00:00:00Z"
    });
    let agent_pub = keys["keys"][&record_key].as_str().unwrap().to_string();
    let verify_with = |roots: Vec<Value>| {
        let stranger = Ws::new();
        std::fs::write(
            stranger.root.join("trust_roots.json"),
            serde_json::to_vec_pretty(&serde_json::json!({"version": 1, "roots": roots})).unwrap(),
        )
        .unwrap();
        stranger.run(&[
            "package",
            "verify",
            copy.to_str().unwrap(),
            "--strict",
            "--format",
            "json",
        ])
    };

    // Only the ship key pinned: fails, and says which key to pin.
    let (ok, out) = verify_with(vec![ship_root.clone()]);
    assert!(!ok, "{out}");
    let verdict = first_json(&out);
    assert_eq!(verdict["verdict"], "failed", "{out}");
    let binding = verdict["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "receipt_binding")
        .unwrap();
    assert_eq!(binding["status"], "fail", "{out}");
    let detail = binding["detail"].as_str().unwrap();
    assert!(
        detail.contains(&format!("treeship trust add {record_key} {agent_pub}")),
        "{detail}"
    );

    // Ship key and agent key pinned: verified.
    let agent_root = serde_json::json!({
        "key_id": record_key,
        "public_key": agent_pub,
        "kind": "cert_issuer",
        "label": "producer agent",
        "added_at": "2026-09-18T00:00:00Z"
    });
    let (ok, out) = verify_with(vec![ship_root, agent_root]);
    assert!(ok, "{out}");
    assert_eq!(first_json(&out)["verdict"], "verified", "{out}");
}
