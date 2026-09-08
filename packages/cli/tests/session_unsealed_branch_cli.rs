//! A receipt signed onto a stale parent forks the chain. The package seals
//! one path from the head, so the fork is signed but unsealed. `session
//! close` must say so instead of reporting a clean package (QA TS-002).

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
            .args(["init", "--name", "fork-test", "--config"])
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
    fn attest(&self, action: &str, parent: &str) -> String {
        let v = self.json(&[
            "attest",
            "action",
            "--actor",
            "agent://t",
            "--action",
            action,
            "--parent",
            parent,
        ]);
        v["id"]
            .as_str()
            .or_else(|| v["artifact_id"].as_str())
            .unwrap()
            .to_string()
    }
}

#[test]
fn close_names_artifacts_that_branch_off_the_sealed_chain() {
    let ws = Ws::new();
    ws.json(&["session", "start", "--name", "fork", "--actor", "agent://t"]);
    let root = ws.json(&["session", "status"])["root_artifact_id"]
        .as_str()
        .unwrap()
        .to_string();
    let a = ws.attest("step.one", &root);
    let b = ws.attest("step.two", &a);
    // A receipt signed onto `a` after `b` exists: `.last` is now this fork,
    // so re-point it at `b` the way a host that kept the real head would.
    let fork = ws.attest("step.fork", &a);
    std::fs::write(ws.root.join(".treeship/artifacts/.last"), &b).unwrap();

    let closed = ws.json(&["session", "close", "--summary", "forked"]);
    let unsealed: Vec<&str> = closed["unsealed_branches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(unsealed, vec![fork.as_str()], "{closed}");
    assert_eq!(
        closed["receipts"], 2,
        "root + a + b are the chain; the fork is not counted"
    );

    // A clean chain reports none.
    let ws2 = Ws::new();
    ws2.json(&[
        "session",
        "start",
        "--name",
        "clean",
        "--actor",
        "agent://t",
    ]);
    let root2 = ws2.json(&["session", "status"])["root_artifact_id"]
        .as_str()
        .unwrap()
        .to_string();
    let a2 = ws2.attest("step.one", &root2);
    ws2.attest("step.two", &a2);
    let closed2 = ws2.json(&["session", "close", "--summary", "clean"]);
    assert_eq!(closed2["unsealed_branches"].as_array().unwrap().len(), 0);
}
