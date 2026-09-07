//! Failure-first end-to-end tests for the atomic Reason verify-then-sign adapter.
//!
//! The load-bearing ordering invariant is observable on disk: every malformed,
//! denied, verifier-rejected, timed-out, or forged verifier result leaves the artifact
//! store empty. The success case also proves that the verifier received the
//! exact bytes whose SHA-256 digest is committed into the signed receipt.

#![cfg(unix)]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

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
        let workspace = Self { _tmp: tmp, root };
        let output = workspace
            .cmd()
            .args(["init", "--config"])
            .arg(workspace.config())
            .args(["--name", "reason-adapter-test"])
            .output()
            .expect("treeship init");
        assert_success(&output, "init");
        workspace
    }

    fn config(&self) -> String {
        self.root
            .join(".treeship/config.json")
            .display()
            .to_string()
    }

    fn cmd(&self) -> Command {
        let mut command = Command::new(cli_path());
        command
            .env("HOME", &self.root)
            .env("TREESHIP_ALLOW_INSECURE_KEY_PERMS", "1")
            .current_dir(&self.root);
        command
    }

    fn bundle_path(&self, bytes: &[u8]) -> PathBuf {
        let path = self.root.join("authorization-bundle.json");
        fs::write(&path, bytes).unwrap();
        path
    }

    fn verifier(&self, name: &str, body: &str) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    fn attest(&self, bundle: &Path, verifier: &Path, timeout_ms: u64) -> std::process::Output {
        self.cmd()
            .args(["attest", "reason-authorization", "--bundle-file"])
            .arg(bundle)
            .args(["--reason-bin"])
            .arg(verifier)
            .args([
                "--timeout-ms",
                &timeout_ms.to_string(),
                "--format",
                "json",
                "--config",
            ])
            .arg(self.config())
            .output()
            .expect("attest reason-authorization")
    }

    fn artifact_count(&self) -> usize {
        let index = self.root.join(".treeship/artifacts/index.json");
        if !index.exists() {
            return 0;
        }
        let value: Value = serde_json::from_slice(&fs::read(index).unwrap()).unwrap();
        value["entries"].as_array().unwrap().len()
    }

    fn record(&self, artifact_id: &str) -> Value {
        serde_json::from_slice(
            &fs::read(
                self.root
                    .join(".treeship/artifacts")
                    .join(format!("{artifact_id}.json")),
            )
            .unwrap(),
        )
        .unwrap()
    }
}

fn authorized_bundle() -> Vec<u8> {
    // This is an adapter transport fixture, not a Reason proof vector. The
    // verifier subprocess is the test double under explicit control below.
    // Fields are hand-authored from the public v1 transport schemas.
    serde_json::to_vec(&json!({
        "schema": "zerker.reason.authorization-bundle.v1",
        "request": {
            "schema": "zerker.reason.action.v1",
            "mission": {},
            "action": {},
            "policy": {}
        },
        "certificate": {
            "schema": "zerker.reason.authorization.v1",
            "status": "authorized",
            "request_digest": DIGEST_A,
            "mission": {},
            "action": {},
            "reasoning": {},
            "issues": []
        }
    }))
    .unwrap()
}

fn verification_json(status: &str) -> String {
    json!({
        "schema": "zerker.reason.authorization-verification.v1",
        "status": "verified",
        "authorization_status": status,
        "request_digest": DIGEST_A,
        "reasoning_result_digest": DIGEST_B
    })
    .to_string()
}

fn assert_success(output: &std::process::Output, operation: &str) {
    assert!(
        output.status.success(),
        "{operation} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failed_without_artifact(
    workspace: &Workspace,
    output: &std::process::Output,
    case: &str,
) {
    assert!(
        !output.status.success(),
        "{case} unexpectedly succeeded: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        workspace.artifact_count(),
        0,
        "{case} signed or stored an artifact before all gates passed"
    );
}

#[test]
fn exact_verified_bundle_bytes_are_committed_before_receipt_signing() {
    let workspace = Workspace::new();
    let bytes = authorized_bundle();
    let bundle = workspace.bundle_path(&bytes);
    let captured = workspace.root.join("captured-bundle");
    let verifier = workspace.verifier(
        "reason-ok",
        &format!(
            "/bin/cat > '{}'\nprintf '%s\\n' '{}'",
            captured.display(),
            verification_json("authorized")
        ),
    );

    let output = workspace.attest(&bundle, &verifier, 2_000);
    assert_success(&output, "atomic attestation");
    assert_eq!(
        fs::read(captured).unwrap(),
        bytes,
        "Reason saw different bytes"
    );
    assert_eq!(workspace.artifact_count(), 1);

    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    let artifact_id = response["id"].as_str().expect("success id");
    let record = workspace.record(artifact_id);
    let payload = URL_SAFE_NO_PAD
        .decode(record["envelope"]["payload"].as_str().unwrap())
        .unwrap();
    let statement: Value = serde_json::from_slice(&payload).unwrap();
    let expected_digest = format!("sha256:{:x}", Sha256::digest(&bytes));
    assert_eq!(statement["kind"], "reason.authorization.v1");
    assert_eq!(statement["payload"]["status"], "authorized");
    assert_eq!(statement["payloadDigest"], expected_digest);
    assert_eq!(
        statement["meta"]["authorization_bundle"]["digest"],
        expected_digest
    );
    assert_eq!(
        statement["meta"]["reason_verification"]["status"],
        "verified"
    );

    let verify = workspace
        .cmd()
        .args(["verify", artifact_id, "--no-chain", "--config"])
        .arg(workspace.config())
        .output()
        .expect("treeship verify");
    assert_success(&verify, "verify signed receipt");
}

#[test]
fn verifier_descendant_cannot_hold_success_pipes_open() {
    let workspace = Workspace::new();
    let bundle = workspace.bundle_path(&authorized_bundle());
    let verifier = workspace.verifier(
        "reason-orphan",
        &format!(
            "/bin/cat >/dev/null\n/bin/sleep 5 &\nprintf '%s\\n' '{}'",
            verification_json("authorized")
        ),
    );

    let started = Instant::now();
    let output = workspace.attest(&bundle, &verifier, 2_000);
    assert_success(&output, "verifier with inherited descendant pipes");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "adapter waited for an outliving verifier descendant: {:?}",
        started.elapsed()
    );
}

#[test]
fn verifier_and_bundle_failures_leave_no_signed_side_effect() {
    let mut extra: Value = serde_json::from_str(&verification_json("authorized")).unwrap();
    extra["extra"] = json!(true);
    let cases = [
        (
            "verifier-rejection",
            "/bin/cat >/dev/null\nexit 1".to_string(),
            2_000,
        ),
        (
            "verified-denial",
            format!(
                "/bin/cat >/dev/null\nprintf '%s\\n' '{}'",
                verification_json("denied")
            ),
            2_000,
        ),
        (
            "malformed-output",
            "/bin/cat >/dev/null\nprintf 'not-json'".to_string(),
            2_000,
        ),
        (
            "unknown-output-field",
            format!("/bin/cat >/dev/null\nprintf '%s\\n' '{}'", extra),
            2_000,
        ),
        (
            "timeout",
            "/bin/cat >/dev/null\n/bin/sleep 5".to_string(),
            30,
        ),
    ];

    for (name, body, timeout) in cases {
        let workspace = Workspace::new();
        let bundle = workspace.bundle_path(&authorized_bundle());
        let verifier = workspace.verifier(&format!("reason-{name}"), &body);
        let output = workspace.attest(&bundle, &verifier, timeout);
        assert_failed_without_artifact(&workspace, &output, name);
    }
}

#[test]
fn oversized_input_is_rejected_before_the_verifier_starts() {
    let workspace = Workspace::new();
    let bundle = workspace.bundle_path(&vec![b'x'; (1 << 20) + 1]);
    let marker = workspace.root.join("verifier-started");
    let verifier = workspace.verifier(
        "reason-marker",
        &format!("/usr/bin/touch '{}'", marker.display()),
    );

    let output = workspace.attest(&bundle, &verifier, 2_000);
    assert_failed_without_artifact(&workspace, &output, "oversized input");
    assert!(!marker.exists(), "verifier started for oversized input");
}

#[test]
fn oversized_verifier_output_fails_closed_before_signing() {
    let workspace = Workspace::new();
    let bundle = workspace.bundle_path(&authorized_bundle());
    let output = "x".repeat((64 << 10) + 1);
    let verifier = workspace.verifier(
        "reason-loud",
        &format!("/bin/cat >/dev/null\nprintf '%s' '{}'", output),
    );

    let result = workspace.attest(&bundle, &verifier, 2_000);
    assert_failed_without_artifact(&workspace, &result, "oversized output");
}

#[test]
fn generic_receipt_cannot_bypass_reason_verification() {
    let workspace = Workspace::new();
    let certificate = json!({
        "schema": "zerker.reason.authorization.v1",
        "status": "authorized",
        "request_digest": DIGEST_A,
        "mission": {},
        "action": {},
        "reasoning": {},
        "issues": []
    })
    .to_string();
    let output = workspace
        .cmd()
        .args([
            "attest",
            "receipt",
            "--system",
            "system://zerker-reason",
            "--kind",
            "reason.authorization.v1",
            "--payload",
            &certificate,
            "--config",
        ])
        .arg(workspace.config())
        .output()
        .expect("generic receipt bypass attempt");

    assert_failed_without_artifact(&workspace, &output, "generic receipt bypass");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("reason-authorization"),
        "error must direct the caller to the verified adapter: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
