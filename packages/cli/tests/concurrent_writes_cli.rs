//! Concurrent CLI processes in one workspace: parallel tool calls from an
//! agent produce several `attest action` processes at once, and parallel
//! agents can each run `session start`.
//!
//! - Every concurrently signed action is indexed, chained without forking,
//!   and sealed, and `package verify --strict` passes. Before the store's
//!   index update was locked and re-read, and the chain head was read under
//!   a workspace lock, most of them were dropped from the index, the chain
//!   forked, and close sealed only what the index still listed.
//! - Exactly one of several concurrent `session start`s succeeds; the
//!   others are refused with the active session's id and actor. Before, all
//!   of them reported success and only one session.json survived.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Arc, Barrier};

use serde::Deserialize;
use serde_json::Value;
use tempfile::TempDir;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

const ACTOR: &str = "agent://parallel";

struct Ws {
    _tmp: TempDir,
    root: PathBuf,
}

impl Ws {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let ws = Self { _tmp: tmp, root };
        let out = ws.output(&["init", "--name", "conc"]);
        assert!(out.status.success(), "{}", text(&out));
        ws
    }
    fn config(&self) -> PathBuf {
        self.root.join(".treeship/config.json")
    }
    /// Fully isolated: HOME and TREESHIP_CONFIG both point into the temp
    /// directory, so nothing reads or writes the real ~/.treeship.
    fn cmd(&self) -> Command {
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root)
            .env("TREESHIP_CONFIG", self.config())
            .env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1")
            .env("TREESHIP_TRUST_ROOTS", self.root.join("trust_roots.json"))
            .env_remove("TREESHIP_PARENT")
            .current_dir(&self.root);
        c.args(["--config"]).arg(self.config());
        c
    }
    fn output(&self, args: &[&str]) -> Output {
        self.cmd().args(args).output().unwrap()
    }
}

fn text(out: &Output) -> String {
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

/// Run `n` copies of a command at once (released together by a barrier) and
/// return their outputs.
fn concurrently(ws: &Ws, n: usize, args: impl Fn(usize) -> Vec<String>) -> Vec<Output> {
    let barrier = Arc::new(Barrier::new(n));
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..n)
            .map(|i| {
                let barrier = barrier.clone();
                let mut cmd = ws.cmd();
                cmd.args(args(i));
                s.spawn(move || {
                    barrier.wait();
                    cmd.output().unwrap()
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

#[test]
fn concurrent_attests_in_one_session_are_all_sealed_and_verify_strictly() {
    const N: usize = 8;
    let ws = Ws::new();
    let out = ws.output(&["session", "start", "--name", "par", "--actor", ACTOR]);
    assert!(out.status.success(), "{}", text(&out));

    let outs = concurrently(&ws, N, |i| {
        [
            "attest",
            "action",
            "--actor",
            ACTOR,
            "--action",
            &format!("tool.call.{i}"),
            "--format",
            "json",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    });
    let mut ids = Vec::new();
    for o in &outs {
        let t = text(o);
        assert!(o.status.success(), "{t}");
        let v = first_json(&String::from_utf8_lossy(&o.stdout));
        let id = v["id"]
            .as_str()
            .or_else(|| v["artifact_id"].as_str())
            .unwrap_or_else(|| panic!("no id: {v}"));
        ids.push(id.to_string());
    }
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), N, "every attest signed a distinct artifact");

    // All N are in the index, not only on disk.
    let index: Value = serde_json::from_slice(
        &std::fs::read(ws.root.join(".treeship/artifacts/index.json")).unwrap(),
    )
    .unwrap();
    let indexed: Vec<&str> = index["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["id"].as_str())
        .collect();
    for id in &ids {
        assert!(indexed.contains(&id.as_str()), "{id} missing from index");
    }

    let out = ws.output(&["session", "close", "--format", "json"]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    let close = first_json(&String::from_utf8_lossy(&out.stdout));
    // No fork: every action is on the walked chain, none sealed loose.
    assert_eq!(
        close["sealed_unchained"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0),
        0,
        "{close}"
    );
    let pkg = PathBuf::from(close["package"].as_str().unwrap());
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(pkg.join("receipt.json")).unwrap()).unwrap();
    let sealed: Vec<&str> = receipt["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["artifact_id"].as_str())
        .collect();
    for id in &ids {
        assert!(sealed.contains(&id.as_str()), "{id} not sealed: {sealed:?}");
    }

    let out = ws.output(&[
        "package",
        "verify",
        pkg.to_str().unwrap(),
        "--strict",
        "--format",
        "json",
    ]);
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert_eq!(first_json(&t)["verdict"], "verified", "{t}");
}

#[test]
fn concurrent_session_starts_give_exactly_one_session() {
    const N: usize = 4;
    let ws = Ws::new();
    let outs = concurrently(&ws, N, |i| {
        [
            "session",
            "start",
            "--name",
            &format!("s{i}"),
            "--actor",
            ACTOR,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    });
    let ok: Vec<&Output> = outs.iter().filter(|o| o.status.success()).collect();
    assert_eq!(
        ok.len(),
        1,
        "exactly one start succeeds: {:?}",
        outs.iter().map(text).collect::<Vec<_>>()
    );

    let manifest: Value =
        serde_json::from_slice(&std::fs::read(ws.root.join(".treeship/session.json")).unwrap())
            .unwrap();
    let active = manifest["session_id"].as_str().unwrap();
    for o in outs.iter().filter(|o| !o.status.success()) {
        let t = text(o);
        assert!(
            t.contains(&format!("session already active ({active}, {ACTOR}")),
            "loser names the active session and actor: {t}"
        );
    }

    // Only the winner's session exists.
    let sessions: Vec<_> = std::fs::read_dir(ws.root.join(".treeship/sessions"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("ssn_"))
        .collect();
    assert_eq!(sessions.len(), 1, "one session directory");
}
