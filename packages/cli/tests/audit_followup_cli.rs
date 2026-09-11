//! Audit follow-up of 2026-09-11 (AUD-34, AUD-35, P3, FR-4, FR-7), end to
//! end through the CLI.

use std::path::{Path, PathBuf};
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
    fn json_any(&self, args: &[&str]) -> (bool, Value) {
        let out = self
            .cmd()
            .args(args)
            .args(["--format", "json", "--config"])
            .arg(self.config())
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let v = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| panic!("{e}: {stdout}"));
        (out.status.success(), v)
    }
    fn attest(&self, action: &str, extra: &[&str]) -> String {
        let mut args = vec![
            "attest",
            "action",
            "--actor",
            "agent://buyer",
            "--action",
            action,
        ];
        args.extend(extra);
        self.json(&args)["id"].as_str().unwrap().to_string()
    }
    fn close(&self, name: &str) -> PathBuf {
        let v = self.json(&["session", "close", "--summary", name]);
        PathBuf::from(v["package"].as_str().unwrap())
    }
    fn receipt(&self, pkg: &Path) -> Value {
        serde_json::from_slice(&std::fs::read(pkg.join("receipt.json")).unwrap()).unwrap()
    }
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            std::fs::copy(e.path(), dest).unwrap();
        }
    }
}

/// Rewrite a package's sealed set and recompute the tree and proofs, the way
/// the auditor's script does. Every structural row stays green.
fn reseal(pkg: &Path, mut receipt: Value) {
    let ids: Vec<String> = receipt["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["artifact_id"].as_str().unwrap().to_string())
        .collect();
    let mut tree = treeship_core::merkle::MerkleTree::new();
    for id in &ids {
        tree.append(id);
    }
    let proofs: Vec<Value> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            serde_json::json!({"artifact_id": id, "leaf_index": i, "proof": tree.inclusion_proof(i).unwrap()})
        })
        .collect();
    receipt["merkle"]["root"] =
        Value::String(format!("mroot_{}", hex::encode(tree.root().unwrap())));
    receipt["merkle"]["leaf_count"] = Value::from(ids.len());
    receipt["merkle"]["inclusion_proofs"] = Value::Array(proofs.clone());
    std::fs::write(
        pkg.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    std::fs::write(
        pkg.join("merkle.json"),
        serde_json::to_vec_pretty(&receipt["merkle"]).unwrap(),
    )
    .unwrap();
    for f in std::fs::read_dir(pkg.join("proofs")).unwrap() {
        let _ = std::fs::remove_file(f.unwrap().path());
    }
    for (i, p) in proofs.iter().enumerate() {
        std::fs::write(
            pkg.join("proofs").join(format!("{}.proof.json", ids[i])),
            serde_json::to_vec_pretty(p).unwrap(),
        )
        .unwrap();
    }
}

/// AUD-34: an artifact from another session, same key, spliced into a sealed
/// package as an `unchained` entry, tree recomputed. The close record binds
/// the receipt digest, so the splice fails `receipt_binding`.
#[test]
fn a_spliced_artifact_from_another_session_fails_receipt_binding() {
    let ws = Ws::new();
    ws.json(&[
        "session",
        "start",
        "--name",
        "A",
        "--actor",
        "agent://buyer",
    ]);
    ws.attest("cart.add", &[]);
    ws.attest("checkout", &[]);
    let pkg_a = ws.close("A");
    assert!(
        pkg_a.join("record.json").exists(),
        "close seals its record beside the package"
    );

    ws.json(&[
        "session",
        "start",
        "--name",
        "B",
        "--actor",
        "agent://buyer",
    ]);
    let refund = ws.attest("refund.DENIED", &[]);
    let pkg_b = ws.close("B");

    // The genuine package: every row green on the producer's own ship.
    let (ok, out) = ws.run(&["package", "verify", pkg_a.to_str().unwrap()]);
    assert!(ok, "{out}");
    assert!(out.contains("PASS receipt_binding"), "{out}");
    assert!(out.contains("PASS session_window"), "{out}");
    assert!(out.contains("package verified"), "{out}");

    // The splice.
    let spliced = ws.root.join("spliced.treeship");
    copy_dir(&pkg_a, &spliced);
    std::fs::copy(
        pkg_b.join("artifacts").join(format!("{refund}.json")),
        spliced.join("artifacts").join(format!("{refund}.json")),
    )
    .unwrap();
    let mut receipt = ws.receipt(&spliced);
    let mut entry = ws.receipt(&pkg_b)["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["artifact_id"] == refund)
        .unwrap()
        .clone();
    entry["unchained"] = Value::Bool(true);
    receipt["artifacts"].as_array_mut().unwrap().push(entry);
    reseal(&spliced, receipt);

    let (ok, out) = ws.run(&["package", "verify", spliced.to_str().unwrap()]);
    assert!(!ok, "a spliced package must not verify:\n{out}");
    assert!(out.contains("FAIL receipt_binding"), "{out}");
    let (ok_strict, _) = ws.run(&["package", "verify", spliced.to_str().unwrap(), "--strict"]);
    assert!(!ok_strict);
    let (ok_json, v) = ws.json_any(&["package", "verify", spliced.to_str().unwrap()]);
    assert!(!ok_json);
    assert_eq!(v["verdict"], "failed", "{v}");
    assert!(v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "receipt_binding" && c["status"] == "fail"));
}

/// AUD-35: an unknown signer's package says `signatures-pass`, not
/// `verified`, and the JSON carries the rows.
#[test]
fn an_unpinned_signer_gets_signatures_pass_not_verified() {
    let producer = Ws::new();
    producer.json(&[
        "session",
        "start",
        "--name",
        "legit",
        "--actor",
        "agent://buyer",
    ]);
    producer.attest("wire.transfer", &[]);
    let pkg = producer.close("legit");

    let stranger = Ws::new();
    let (ok, out) = stranger.run(&["package", "verify", pkg.to_str().unwrap()]);
    assert!(ok, "{out}");
    assert!(out.contains("signatures-pass"), "{out}");
    assert!(!out.contains("package verified"), "{out}");
    let (_, v) = stranger.json_any(&["package", "verify", pkg.to_str().unwrap()]);
    assert_eq!(v["verdict"], "signatures-pass", "{v}");
    assert_eq!(v["status"], "warning");
    assert_eq!(v["signer_pinned"], false);
    assert!(v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c["name"] == "signer_trust"));
    let (ok_strict, _) = stranger.run(&["package", "verify", pkg.to_str().unwrap(), "--strict"]);
    assert!(!ok_strict, "strict fails on an unpinned signer");

    // Pin the key and the word becomes `verified`.
    let keys: Value =
        serde_json::from_slice(&std::fs::read(pkg.join("keys.json")).unwrap()).unwrap();
    let (kid, pk) = keys["keys"].as_object().unwrap().iter().next().unwrap();
    let (ok, out) = stranger.run(&[
        "trust",
        "add",
        kid,
        pk.as_str().unwrap(),
        "--kind",
        "cert_issuer",
        "--yes",
    ]);
    assert!(ok, "{out}");
    let (_, v) = stranger.json_any(&["package", "verify", pkg.to_str().unwrap()]);
    assert_eq!(v["verdict"], "verified", "{v}");
}

/// P3: the session's own actions chain by default, another agent's receipt
/// in the same workspace does not become the session's chained step, and the
/// root is never `unchained`.
#[test]
fn own_actions_chain_by_default_and_foreign_receipts_stay_loose() {
    let ws = Ws::new();
    ws.json(&[
        "session",
        "start",
        "--name",
        "mine",
        "--actor",
        "agent://mine",
    ]);
    let root = ws.json(&["session", "status"])["root_artifact_id"]
        .as_str()
        .unwrap()
        .to_string();
    let inside = ws.attest("inside", &[]);
    let foreign = ws.json(&[
        "attest",
        "action",
        "--actor",
        "agent://someone-else",
        "--action",
        "foreign",
        "--no-parent",
    ])["id"]
        .as_str()
        .unwrap()
        .to_string();
    let loose = ws.attest("loose", &["--no-parent"]);
    let pkg = ws.close("mine");
    let receipt = ws.receipt(&pkg);
    let entries: Vec<(String, bool)> = receipt["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["artifact_id"].as_str().unwrap().to_string(),
                a["unchained"] == true,
            )
        })
        .collect();
    let flag = |id: &str| entries.iter().find(|(i, _)| i == id).map(|(_, u)| *u);
    assert_eq!(
        flag(&root),
        Some(false),
        "root is on the chain: {entries:?}"
    );
    assert_eq!(
        flag(&inside),
        Some(false),
        "an action without --parent chains: {entries:?}"
    );
    assert_eq!(
        flag(&foreign),
        Some(true),
        "foreign receipt is loose: {entries:?}"
    );
    assert_eq!(
        flag(&loose),
        Some(true),
        "--no-parent is loose: {entries:?}"
    );
    let (ok, out) = ws.run(&["package", "verify", pkg.to_str().unwrap()]);
    assert!(ok, "{out}");
    assert!(out.contains("PASS chain_linkage"), "{out}");
}

/// FR-4: an action whose subject is an external reference verifies; the
/// subject is not a chain parent.
#[test]
fn verify_last_with_an_external_subject() {
    let ws = Ws::new();
    let id = ws.attest("order.place", &["--subject", "ord_12345"]);
    let (ok, out) = ws.run(&["verify", "last"]);
    assert!(ok, "{out}");
    assert!(!out.contains("not found in local storage"), "{out}");
    let (ok, _) = ws.run(&["verify", &id]);
    assert!(ok);
}

/// FR-7: a report whose local verify failed exits nonzero.
#[test]
fn session_report_exits_nonzero_when_local_verify_fails() {
    let ws = Ws::new();
    ws.json(&[
        "session",
        "start",
        "--name",
        "r",
        "--actor",
        "agent://buyer",
    ]);
    ws.attest("a", &[]);
    let pkg = ws.close("r");
    let (ok, v) = ws.json_any(&["session", "report", "--no-upload"]);
    assert!(ok, "{v}");
    assert_eq!(v["verification_status"], "pass", "{v}");
    // Break the sealed set: drop an artifact's envelope.
    let art = std::fs::read_dir(pkg.join("artifacts"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    std::fs::remove_file(art).unwrap();
    let (ok, v) = ws.json_any(&["session", "report", "--no-upload"]);
    assert!(!ok, "a failed local verify must exit nonzero: {v}");
    assert_eq!(v["verification_status"], "fail", "{v}");
}
