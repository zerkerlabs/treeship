//! Audit 2026-09 (AUD-31, AUD-32) and QA TS-002/TS-002b, end to end through
//! the CLI: every artifact signed during a session is sealed, chained or not;
//! the package carries its envelopes and keys; `package verify` checks the
//! signatures and fails a fabricated sealed set.

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
            .args(["init", "--name", "seal-test", "--config"])
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
            .current_dir(&self.root);
        c
    }
    fn run(&self, args: &[&str]) -> (bool, String, String) {
        let out = self
            .cmd()
            .args(args)
            .args(["--config"])
            .arg(self.config())
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
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
    fn attest(&self, action: &str, parent: Option<&str>) -> String {
        let mut args = vec![
            "attest",
            "action",
            "--actor",
            "agent://t",
            "--action",
            action,
        ];
        if let Some(p) = parent {
            args.extend(["--parent", p]);
        }
        let v = self.json(&args);
        v["id"]
            .as_str()
            .or_else(|| v["artifact_id"].as_str())
            .unwrap()
            .to_string()
    }
    fn sealed_ids(&self, pkg: &str) -> Vec<String> {
        let r: Value = serde_json::from_slice(
            &std::fs::read(PathBuf::from(pkg).join("receipt.json")).unwrap(),
        )
        .unwrap();
        r["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["artifact_id"].as_str().unwrap().to_string())
            .collect()
    }
    fn unchained_ids(&self, pkg: &str) -> Vec<String> {
        let r: Value = serde_json::from_slice(
            &std::fs::read(PathBuf::from(pkg).join("receipt.json")).unwrap(),
        )
        .unwrap();
        r["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|a| a["unchained"] == true)
            .map(|a| a["artifact_id"].as_str().unwrap().to_string())
            .collect()
    }
}

#[test]
fn unchained_and_forked_artifacts_are_sealed_and_marked() {
    let ws = Ws::new();
    ws.json(&[
        "session",
        "start",
        "--name",
        "loose",
        "--actor",
        "agent://t",
    ]);
    let root = ws.json(&["session", "status"])["root_artifact_id"]
        .as_str()
        .unwrap()
        .to_string();
    // AUD-32: three actions, no --parent.
    let a = ws.attest("act.A", None);
    let b = ws.attest("act.B", None);
    let c = ws.attest("act.C", None);
    // A fork: signed onto A after B and C exist.
    let fork = ws.attest("act.fork", Some(&a));
    let (_, _, err) = ws.run(&[
        "attest",
        "action",
        "--actor",
        "agent://t",
        "--action",
        "act.hinted",
    ]);
    let _ = err;
    let closed = ws.json(&["session", "close", "--summary", "loose"]);
    let pkg = closed["package"].as_str().unwrap().to_string();
    let sealed = ws.sealed_ids(&pkg);
    for id in [&root, &a, &b, &c, &fork] {
        assert!(
            sealed.contains(id),
            "{id} must be sealed; sealed = {sealed:?}"
        );
    }
    let unchained = ws.unchained_ids(&pkg);
    assert!(
        unchained.contains(&a) && unchained.contains(&b) && unchained.contains(&fork),
        "{unchained:?}"
    );
    let listed: Vec<&str> = closed["sealed_unchained"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(
        listed.contains(&a.as_str()) && listed.contains(&fork.as_str()),
        "{closed}"
    );
    assert!(PathBuf::from(&pkg).join("keys.json").exists());
    for id in &sealed {
        assert!(
            PathBuf::from(&pkg)
                .join("artifacts")
                .join(format!("{id}.json"))
                .exists(),
            "envelope for {id}"
        );
    }

    // The package verifies its own signatures. The signer is this ship's key,
    // and this ship trusts its own keys: PASS here, a warning on a stranger's machine.
    let v = ws.json(&["package", "verify", &pkg]);
    assert_eq!(v["status"], "ok", "{v}");
    let (ok, stdout, _) = ws.run(&["package", "verify", &pkg]);
    assert!(ok);
    assert!(stdout.contains("PASS chain_linkage"), "{stdout}");
    assert!(stdout.contains("WARN chain_completeness"), "{stdout}");
    // The signer is this ship's own key: trusted here, a warning only on a
    // stranger's machine. The release smoke on 0.31.2 caught the inverse.
    assert!(stdout.contains("PASS signer_trust"), "{stdout}");
    let report = ws.json(&["session", "report", "--no-upload"]);
    assert_eq!(report["verification_status"], "warn", "{report}");
    let kinds: Vec<&str> = report["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|w| w["kind"].as_str().unwrap())
        .collect();
    assert!(!kinds.contains(&"signer_trust"), "{kinds:?}");
    assert!(kinds.contains(&"chain_completeness"), "{kinds:?}");
    assert_eq!(
        stdout.matches("PASS signature:").count(),
        sealed.len(),
        "{stdout}"
    );
}

#[test]
fn a_fabricated_artifact_fails_package_verify_with_a_nonzero_exit() {
    // The auditor's reproduction, verbatim in spirit: substitute an invented
    // id into the sealed set and recompute the tree so structure is intact.
    let ws = Ws::new();
    ws.json(&[
        "session",
        "start",
        "--name",
        "forge",
        "--actor",
        "agent://t",
    ]);
    let root = ws.json(&["session", "status"])["root_artifact_id"]
        .as_str()
        .unwrap()
        .to_string();
    let a = ws.attest("act.A", Some(&root));
    let _b = ws.attest("act.B", Some(&a));
    let closed = ws.json(&["session", "close", "--summary", "forge"]);
    let pkg = PathBuf::from(closed["package"].as_str().unwrap());
    let tampered = ws.root.join("tampered.treeship");
    copy_dir(&pkg, &tampered);

    let evil = "art_ev11wire1000000usd0000000000000";
    let mut receipt: Value =
        serde_json::from_slice(&std::fs::read(tampered.join("receipt.json")).unwrap()).unwrap();
    receipt["artifacts"][1]["artifact_id"] = Value::String(evil.into());
    receipt["artifacts"][1]["digest"] = Value::String(format!("sha256:{}", "ab".repeat(32)));
    let ids: Vec<String> = receipt["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["artifact_id"].as_str().unwrap().to_string())
        .collect();
    let mut tree = treeship_core::merkle::MerkleTree::new();
    for id in &ids {
        tree.append(id);
    }
    receipt["merkle"]["root"] =
        Value::String(format!("mroot_{}", hex::encode(tree.root().unwrap())));
    let proofs: Vec<Value> = ids.iter().enumerate().map(|(i, id)| serde_json::json!({"artifact_id": id, "leaf_index": i, "proof": tree.inclusion_proof(i).unwrap()})).collect();
    receipt["merkle"]["inclusion_proofs"] = Value::Array(proofs.clone());
    std::fs::write(
        tampered.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    std::fs::write(
        tampered.join("merkle.json"),
        serde_json::to_vec_pretty(&receipt["merkle"]).unwrap(),
    )
    .unwrap();
    for f in std::fs::read_dir(tampered.join("proofs")).unwrap() {
        let _ = std::fs::remove_file(f.unwrap().path());
    }
    for (i, p) in proofs.iter().enumerate() {
        std::fs::write(
            tampered
                .join("proofs")
                .join(format!("{}.proof.json", ids[i])),
            serde_json::to_vec_pretty(p).unwrap(),
        )
        .unwrap();
    }

    let out = ws
        .cmd()
        .args(["package", "verify"])
        .arg(&tampered)
        .args(["--config"])
        .arg(ws.config())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success(),
        "a fabricated artifact must not verify:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!("FAIL signature:{evil}")),
        "{stdout}"
    );
    let jout = ws
        .cmd()
        .args(["package", "verify"])
        .arg(&tampered)
        .args(["--format", "json", "--config"])
        .arg(ws.config())
        .output()
        .unwrap();
    assert!(!jout.status.success());
    let js = String::from_utf8_lossy(&jout.stdout);
    assert!(!js.contains("\"status\":\"ok\""), "{js}");

    // The genuine package still verifies, with the same command.
    let (ok, _, _) = ws.run(&["package", "verify", pkg.to_str().unwrap()]);
    assert!(ok);
}

fn copy_dir(from: &PathBuf, to: &PathBuf) {
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

#[test]
fn a_fully_chained_session_reports_pass_on_its_own_ship() {
    let ws = Ws::new();
    ws.json(&[
        "session",
        "start",
        "--name",
        "clean",
        "--actor",
        "agent://t",
    ]);
    let root = ws.json(&["session", "status"])["root_artifact_id"]
        .as_str()
        .unwrap()
        .to_string();
    let a = ws.attest("act.A", Some(&root));
    let _b = ws.attest("act.B", Some(&a));
    ws.json(&["session", "close", "--summary", "clean"]);
    let report = ws.json(&["session", "report", "--no-upload"]);
    assert_eq!(report["verification_status"], "pass", "{report}");
}
