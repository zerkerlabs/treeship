//! End-to-end tests for the irreversibility gate on `treeship attest approval`
//! (docs/specs/memory-provenance-binding.md §2.4-2.5).
//!
//! The gate's contract: a consequential-or-worse grant is refused without a
//! clean, schema-valid, key-bound memory.quarantine-check.v1 receipt; a
//! terminal grant additionally requires a human approver; a dirty verdict or
//! an unpinned provider signer refuses fail-closed. Each refusal path is
//! exercised against a real binary in an isolated workspace.

use std::path::PathBuf;
use std::process::Command;

use tempfile::TempDir;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

struct Workspace {
    _tmp: TempDir,
    root: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        Self { _tmp: tmp, root }
    }

    fn config(&self) -> String {
        self.root
            .join(".treeship/config.json")
            .display()
            .to_string()
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root);
        c.env(
            "TREESHIP_TRUST_ROOTS",
            self.root
                .join(".treeship/trust_roots.json")
                .display()
                .to_string(),
        );
        c.env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1");
        c.current_dir(&self.root);
        c
    }

    fn init(&self) {
        let out = self
            .cmd()
            .args(["init", "--config"])
            .arg(self.config())
            .args(["--name", "gate-test"])
            .output()
            .expect("treeship init");
        assert!(
            out.status.success(),
            "init failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    /// Default ship key id + base64url pubkey, read from the keystore.
    fn default_key(&self) -> (String, String) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let keys_dir = self.root.join(".treeship/keys");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(keys_dir.join("manifest.json")).unwrap())
                .unwrap();
        let default_id = manifest["default_key_id"].as_str().unwrap().to_string();
        let entry: serde_json::Value = serde_json::from_slice(
            &std::fs::read(keys_dir.join(format!("{default_id}.json"))).unwrap(),
        )
        .unwrap();
        let pk: Vec<u8> = entry["public_key"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap() as u8)
            .collect();
        (default_id, URL_SAFE_NO_PAD.encode(pk))
    }

    /// Pin the default (ship) key under agent_cert so receipts it signs
    /// count as key-bound provider attestations for the gate.
    fn pin_default_key_as_provider(&self) {
        let (key_id, pk) = self.default_key();
        let out = self
            .cmd()
            .args(["trust", "add", &key_id, &format!("ed25519:{pk}")])
            .args(["--kind", "agent_cert", "--yes", "--config"])
            .arg(self.config())
            .output()
            .expect("trust add");
        assert!(
            out.status.success(),
            "trust add failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }

    /// Mint a memory.quarantine-check.v1 receipt and return its artifact id.
    fn mint_check(&self, clean: bool) -> String {
        let payload = format!(
            r#"{{"action_id":"aac_test01","provider":"system://zmem","chain_root":"u3v9xJ2kQm4Zr8pW","decision_seq":7,"clean":{clean},"quarantined_triggers":{}}}"#,
            if clean { "[]" } else { r#"["mem_poisoned1"]"# }
        );
        let out = self
            .cmd()
            .args(["attest", "receipt", "--system", "system://zmem"])
            .args(["--kind", "memory.quarantine-check.v1"])
            .args(["--payload", &payload])
            .args(["--format", "json", "--config"])
            .arg(self.config())
            .output()
            .expect("attest receipt");
        assert!(
            out.status.success(),
            "attest receipt failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        // JSON mode may emit more than one object (warnings); take the one
        // carrying the artifact id.
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if let Some(id) = v.get("id").or_else(|| v.get("artifact_id")) {
                    if let Some(s) = id.as_str() {
                        return s.to_string();
                    }
                }
            }
        }
        panic!(
            "no artifact id in attest receipt output: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    /// Attempt a consequential approval, returning (success, combined output).
    fn approve_consequential(&self, receipt: Option<&str>, approver: &str, class: &str) -> (bool, String) {
        let mut c = self.cmd();
        c.args(["attest", "approval", "--approver", approver])
            .args(["--description", "irreversible thing"])
            .args(["--allowed-action", "deploy.production"])
            .args(["--max-uses", "1"])
            .args(["--irreversibility", class]);
        if let Some(r) = receipt {
            c.args(["--quarantine-receipt", r]);
        }
        c.args(["--config"]).arg(self.config());
        let out = c.output().expect("attest approval");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), combined)
    }
}

#[test]
fn consequential_without_receipt_is_refused() {
    let ws = Workspace::new();
    ws.init();
    let (ok, output) = ws.approve_consequential(None, "human://alice", "one_way_consequential");
    assert!(!ok, "grant must be refused without quarantine evidence");
    assert!(
        output.contains("requires memory quarantine evidence"),
        "refusal must say why: {output}"
    );
}

#[test]
fn terminal_requires_human_approver() {
    let ws = Workspace::new();
    ws.init();
    // Fails on the approver check even before evidence is considered.
    let (ok, output) = ws.approve_consequential(None, "agent://deployer", "one_way_terminal");
    assert!(!ok, "terminal grant must require a human approver");
    assert!(
        output.contains("human approver"),
        "refusal must name the fix: {output}"
    );
}

#[test]
fn recoverable_class_needs_no_evidence() {
    let ws = Workspace::new();
    ws.init();
    let (ok, output) = ws.approve_consequential(None, "human://alice", "one_way_recoverable");
    assert!(ok, "recoverable grant must mint without evidence: {output}");
}

#[test]
fn unpinned_provider_signer_is_refused() {
    let ws = Workspace::new();
    ws.init();
    // Receipt exists and is clean, but its signer is not pinned under
    // agent_cert -- a self-asserted verdict must not pass as a check.
    let receipt = ws.mint_check(true);
    let (ok, output) =
        ws.approve_consequential(Some(&receipt), "human://alice", "one_way_consequential");
    assert!(!ok, "unpinned provider signer must refuse the grant");
    assert!(
        output.contains("key-bound memory provider"),
        "refusal must name the trust gap: {output}"
    );
}

#[test]
fn dirty_verdict_is_refused() {
    let ws = Workspace::new();
    ws.init();
    ws.pin_default_key_as_provider();
    let receipt = ws.mint_check(false);
    let (ok, output) =
        ws.approve_consequential(Some(&receipt), "human://alice", "one_way_consequential");
    assert!(!ok, "dirty quarantine verdict must refuse the grant");
    assert!(output.contains("DIRTY"), "refusal must be explicit: {output}");
    assert!(
        output.contains("mem_poisoned1"),
        "refusal must surface the quarantined triggers: {output}"
    );
}

#[test]
fn clean_keybound_check_mints_grant_with_evidence_signed_in() {
    let ws = Workspace::new();
    ws.init();
    ws.pin_default_key_as_provider();
    let receipt = ws.mint_check(true);
    let (ok, output) =
        ws.approve_consequential(Some(&receipt), "human://alice", "one_way_consequential");
    assert!(ok, "clean key-bound check must mint the grant: {output}");
    assert!(
        output.contains(&receipt),
        "the evidence link must be visible on the grant: {output}"
    );
}
