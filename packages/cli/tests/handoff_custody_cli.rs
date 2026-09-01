//! `treeship attest handoff` custody grading and close-loop evidence
//! (slices 3 and 4 of docs/specs/agent-to-agent-verification.md).
//!
//! Two isolated ships, real keys, real presentations. G is the sender and
//! onboards `agent://grok` with its own key; C is the receiver, mints the
//! nonce, pins G's issuer, and records the handoff. Every case here is one a
//! mocked verifier would pass for the wrong reason.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

/// One isolated ship. HOME is pinned inside the tempdir so trust roots and
/// Merkle checkpoints (which live under `~/.treeship` regardless of
/// `--config`) never touch the developer's real store or the other ship's.
struct Ship {
    _tmp: TempDir,
    root: PathBuf,
}

impl Ship {
    fn new(name: &str) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let ship = Self { _tmp: tmp, root };
        ship.ok(&["init", "--name", name]);
        ship
    }

    fn config(&self) -> String {
        self.root
            .join(".treeship/config.json")
            .display()
            .to_string()
    }

    fn run(&self, args: &[&str]) -> Output {
        let config = self.config();
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root)
            .env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1")
            .current_dir(&self.root)
            .arg("--config")
            .arg(&config)
            .args(args);
        c.output().expect("run treeship")
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "treeship {:?} failed:\nstdout: {}\nstderr: {}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    /// Run with `--format json` and return the last JSON document on stdout.
    /// `attest` may print a warning object before its result, so the result
    /// is the LAST object, never the first.
    fn json(&self, args: &[&str]) -> serde_json::Value {
        let mut full: Vec<&str> = args.to_vec();
        full.extend(["--format", "json"]);
        last_json(&self.ok(&full))
    }

    fn file_count(&self) -> usize {
        fn walk(p: &Path) -> usize {
            if p.is_file() {
                return 1;
            }
            std::fs::read_dir(p)
                .map(|d| d.flatten().map(|e| walk(&e.path())).sum())
                .unwrap_or(0)
        }
        walk(&self.root.join(".treeship"))
    }
}

/// The CLI pretty-prints, and `attest` may emit a warning object before its
/// result, so stdout is a stream of JSON documents; the result is the last.
fn last_json(stdout: &str) -> serde_json::Value {
    serde_json::Deserializer::from_str(stdout)
        .into_iter::<serde_json::Value>()
        .filter_map(Result::ok)
        .last()
        .unwrap_or_else(|| panic!("no JSON object in stdout:\n{stdout}"))
}

fn id_of(v: &serde_json::Value) -> String {
    v.get("id")
        .or_else(|| v.get("artifact_id"))
        .and_then(|x| x.as_str())
        .unwrap_or_else(|| panic!("no id in {v}"))
        .to_string()
}

fn sha256_file(p: &Path) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(std::fs::read(p).unwrap()))
    )
}

/// The handshake up to a live-verified presentation: G onboarded and
/// checkpointed, C holding the nonce G answered and G's issuer pinned.
struct Handshake {
    g: Ship,
    c: Ship,
    presentation: PathBuf,
    nonce: String,
    /// An artifact in C's store to hand off, so the parent walk resolves.
    intent: String,
}

fn live_handshake() -> Handshake {
    let g = Ship::new("G");
    let c = Ship::new("C");
    g.ok(&["onboard", "grok", "--tools", "a2a.*"]);
    g.ok(&["checkpoint"]);

    let nonce = c.json(&["session", "mint-challenge"])["nonce"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(nonce.len() >= 32, "nonce too short: {nonce}");

    g.json(&["present", "agent://grok", "--challenge", &nonce]);
    let presentation = std::fs::read_dir(&g.root)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.to_string_lossy().ends_with(".presentation.json"))
        .expect("G wrote a presentation file");

    // Pin G's issuer on C. Parse by pattern: `keys export` indents.
    let export = g.ok(&["keys", "export"]);
    let line = export
        .lines()
        .find(|l| l.contains("trust add") && l.contains("--kind cert_issuer"))
        .expect("keys export prints a cert_issuer pin line");
    let key_id = line
        .split_whitespace()
        .find(|w| w.starts_with("key_"))
        .unwrap()
        .to_string();
    let pubkey = line
        .split_whitespace()
        .find(|w| w.starts_with("ed25519:"))
        .unwrap()
        .to_string();
    c.ok(&[
        "trust",
        "add",
        &key_id,
        &pubkey,
        "--kind",
        "cert_issuer",
        "--yes",
    ]);
    c.ok(&[
        "trust",
        "add",
        &key_id,
        &pubkey,
        "--kind",
        "hub_checkpoint",
        "--yes",
    ]);

    let intent = id_of(&c.json(&[
        "attest",
        "action",
        "--actor",
        "agent://claude",
        "--action",
        "a2a.task.intent",
    ]));

    Handshake {
        g,
        c,
        presentation,
        nonce,
        intent,
    }
}

fn custody_of(verify: &serde_json::Value, id: &str) -> serde_json::Value {
    verify["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("no check for {id} in {verify}"))
        .clone()
}

#[test]
fn verified_handoff_records_live_custody_bound_to_presentation_and_nonce() {
    let h = live_handshake();
    let pres = h.presentation.display().to_string();

    let out = h.c.json(&[
        "attest",
        "handoff",
        "--from",
        "agent://grok",
        "--to",
        "agent://claude",
        "--artifacts",
        &h.intent,
        "--verified",
        &pres,
        "--challenge",
        &h.nonce,
    ]);
    let id = id_of(&out);

    let verify = h.c.json(&["verify", &id]);
    assert_eq!(verify["outcome"], "pass", "{verify}");
    let check = custody_of(&verify, &id);
    let custody = &check["custody"];
    assert_eq!(custody["live"], true, "{custody}");
    assert_eq!(custody["grade"], "live");
    assert_eq!(custody["presentation_digest"], sha256_file(&h.presentation));
    assert_eq!(custody["challenge"], h.nonce);
    assert_eq!(custody["verifier"], "agent://claude");
    assert!(custody["card_id"].as_str().unwrap().starts_with("art_"));
    assert_eq!(check["close_loop"], serde_json::Value::Null);
    let _ = &h.g;
}

#[test]
fn verified_handoff_refuses_a_replayed_presentation_and_writes_nothing() {
    let h = live_handshake();
    let pres = h.presentation.display().to_string();
    let other = h.c.json(&["session", "mint-challenge"])["nonce"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(other, h.nonce);

    let before = h.c.file_count();
    let out = h.c.run(&[
        "attest",
        "handoff",
        "--from",
        "agent://grok",
        "--to",
        "agent://claude",
        "--artifacts",
        &h.intent,
        "--verified",
        &pres,
        "--challenge",
        &other,
        "--format",
        "json",
    ]);
    assert!(
        !out.status.success(),
        "a replayed presentation was recorded as live custody"
    );
    let err =
        String::from_utf8_lossy(&out.stderr).to_string() + &String::from_utf8_lossy(&out.stdout);
    assert!(
        err.contains("custody: live was NOT recorded"),
        "refusal must say live custody was not recorded: {err}"
    );
    assert_eq!(
        h.c.file_count(),
        before,
        "a refused handoff must leave no artifact behind"
    );
}

#[test]
fn verified_handoff_refuses_when_from_is_not_the_presenter() {
    let h = live_handshake();
    let pres = h.presentation.display().to_string();
    let out = h.c.run(&[
        "attest",
        "handoff",
        "--from",
        "agent://codex",
        "--to",
        "agent://claude",
        "--artifacts",
        &h.intent,
        "--verified",
        &pres,
        "--challenge",
        &h.nonce,
    ]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("proves live control for agent://grok") && err.contains("agent://codex"),
        "{err}"
    );
}

#[test]
fn verified_handoff_requires_the_challenge_it_answered() {
    // A static presentation proves the record, not the bearer. The flag
    // pairing is enforced at the parser so it cannot be forgotten.
    let h = live_handshake();
    let pres = h.presentation.display().to_string();
    let out = h.c.run(&[
        "attest",
        "handoff",
        "--from",
        "agent://grok",
        "--to",
        "agent://claude",
        "--artifacts",
        &h.intent,
        "--verified",
        &pres,
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--challenge"));
}

#[test]
fn handoff_with_custody_reason_is_graded_asserted_with_that_reason() {
    let h = live_handshake();
    let out = h.c.json(&[
        "attest",
        "handoff",
        "--from",
        "agent://grok",
        "--to",
        "agent://claude",
        "--artifacts",
        &h.intent,
        "--custody-reason",
        "same_computer",
    ]);
    let id = id_of(&out);
    let custody = custody_of(&h.c.json(&["verify", &id]), &id)["custody"].clone();
    assert_eq!(custody["live"], false);
    assert_eq!(custody["grade"], "asserted");
    assert_eq!(custody["reason"], "same_computer");
    assert_eq!(custody["detail"], "asserted (same_computer)");
}

#[test]
fn close_loop_binds_the_sealed_session_receipt_digest_and_refuses_unknown_ids() {
    let h = live_handshake();

    // Unknown session: refuse, never cite evidence that does not exist.
    let out = h.c.run(&[
        "attest",
        "handoff",
        "--from",
        "agent://grok",
        "--to",
        "agent://claude",
        "--artifacts",
        &h.intent,
        "--close-loop",
        "ssn_doesnotexist",
    ]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("no sealed session package"));

    // Seal a real session on C, then bind it.
    h.c.ok(&["session", "start", "--name", "evidence"]);
    h.c.ok(&["wrap", "--", "printf", "ok"]);
    let close = h.c.json(&["session", "close", "--summary", "done"]);
    let session_id = close["session_id"].as_str().unwrap().to_string();
    let receipt =
        h.c.root
            .join(".treeship/sessions")
            .join(format!("{session_id}.treeship"))
            .join("receipt.json");
    assert!(
        receipt.exists(),
        "sealed package missing at {}",
        receipt.display()
    );

    let out = h.c.json(&[
        "attest",
        "handoff",
        "--from",
        "agent://grok",
        "--to",
        "agent://claude",
        "--artifacts",
        &h.intent,
        "--close-loop",
        &session_id,
    ]);
    let id = id_of(&out);
    let check = custody_of(&h.c.json(&["verify", &id]), &id);
    assert_eq!(check["close_loop"]["kind"], "session");
    assert_eq!(check["close_loop"]["session_id"], session_id);
    assert_eq!(check["close_loop"]["receipt_digest"], sha256_file(&receipt));
    // Evidence does not upgrade custody.
    assert_eq!(check["custody"]["live"], false);
}
