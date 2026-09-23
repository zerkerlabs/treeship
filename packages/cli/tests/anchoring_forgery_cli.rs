//! TS-2026-003 regression vectors, through the real binary.
//!
//! The bug: `verify --max-unwitnessed` took an anchor's time from
//! `Record.anchors[].observed_at`, a value the pushing machine writes into a
//! file it controls. An operator could add a "rekor" anchor in the middle of
//! an eight-hour chain and pass a 1h policy. Separately, the gate only ran in
//! the default text output: `--format json` (what CI consumes) and `--full`
//! ignored it and exited 0.
//!
//! Each test builds a real two-artifact chain eight hours long, signed by the
//! workspace's own key, then plants anchors in the local store the way an
//! editing operator would.

use std::path::PathBuf;
use std::process::{Command, Output};

use tempfile::TempDir;
use treeship_core::{
    attestation::sign,
    keys::Store as KeyStore,
    statements::{payload_type, ActionStatement},
    storage::{Record, RecordAnchor, Store as ArtifactStore},
};

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
        let ws = Self { _tmp: tmp, root };
        let out = ws.cmd().args(["init"]).output().unwrap();
        assert!(
            out.status.success(),
            "init failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        ws
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(cli_path());
        c.env("HOME", &self.root);
        c.current_dir(&self.root);
        c
    }

    /// Sign an action at `timestamp` (optionally chained to `parent`) and
    /// store it with the given anchors. Returns the artifact id.
    fn plant(&self, timestamp: &str, parent: Option<&str>, anchors: Vec<RecordAnchor>) -> String {
        self.plant_with_record_time(timestamp, timestamp, parent, anchors)
    }

    /// As `plant`, but with the unsigned `Record.signed_at` set independently
    /// of the signed statement timestamp -- what an editing operator can do.
    fn plant_with_record_time(
        &self,
        timestamp: &str,
        record_time: &str,
        parent: Option<&str>,
        anchors: Vec<RecordAnchor>,
    ) -> String {
        let keys = KeyStore::open(self.root.join(".treeship/keys")).unwrap();
        let signer = keys.default_signer().unwrap();
        let mut stmt = ActionStatement::new("agent://forger", "tool.call");
        stmt.timestamp = timestamp.into();
        stmt.parent_id = parent.map(str::to_string);
        let signed = sign(&payload_type("action"), &stmt, signer.as_ref()).unwrap();
        let store = ArtifactStore::open(self.root.join(".treeship/artifacts")).unwrap();
        store
            .write(&Record {
                artifact_id: signed.artifact_id.clone(),
                digest: signed.digest.clone(),
                payload_type: payload_type("action"),
                key_id: signer.key_id().to_string(),
                signed_at: record_time.into(),
                parent_id: parent.map(str::to_string),
                envelope: signed.envelope,
                hub_url: None,
                anchors,
            })
            .unwrap();
        signed.artifact_id.to_string()
    }

    /// An eight-hour chain whose tip carries `anchors`.
    fn eight_hour_chain(&self, anchors: Vec<RecordAnchor>) -> String {
        let root = self.plant("2026-09-01T10:00:00Z", None, vec![]);
        self.plant("2026-09-01T18:00:00Z", Some(&root), anchors)
    }

    fn verify(&self, id: &str, extra: &[&str]) -> Output {
        let mut args = vec!["verify", id, "--max-unwitnessed", "1h"];
        args.extend_from_slice(extra);
        self.cmd().args(&args).output().unwrap()
    }
}

/// What an editing operator plants: anchors every 30 minutes with times of
/// their choosing, as both a bare "rekor" claim and a "hub" claim.
fn forged_anchors() -> Vec<RecordAnchor> {
    (0..16)
        .map(|i| RecordAnchor {
            mechanism: if i % 2 == 0 { "rekor" } else { "hub" }.into(),
            observed_at: format!("2026-09-01T{:02}:{:02}:00Z", 10 + i / 2, (i % 2) * 30),
            reference: Some(format!("{}", 1000 + i)),
            status: None,
            reason: None,
            proof: None,
        })
        .collect()
}

#[test]
fn forged_local_anchor_times_fail_the_gate_in_text_mode() {
    let ws = Workspace::new();
    let tip = ws.eight_hour_chain(forged_anchors());
    let out = ws.verify(&tip, &[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !out.status.success(),
        "forged anchors passed the gate:\n{stdout}"
    );
    assert!(
        stdout.contains("claimed but unverified"),
        "no explanation printed:\n{stdout}"
    );
}

#[test]
fn forged_local_anchor_times_fail_the_gate_in_json_mode() {
    let ws = Workspace::new();
    let tip = ws.eight_hour_chain(forged_anchors());
    let out = ws.verify(&tip, &["--format", "json"]);
    assert!(!out.status.success(), "JSON mode ignored --max-unwitnessed");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["anchoring"]["tally"]["verified"], 0);
    assert_eq!(v["anchoring"]["tally"]["claimed_unverified"], 16);
    assert_eq!(
        v["anchoring"]["coverage"]["unwitnessed_span_seconds"],
        8 * 3600
    );
    assert_eq!(
        v["anchoring"]["gate"]["passed"], false,
        "gate verdict missing: {v}"
    );
    assert_eq!(v["anchoring"]["gate"]["max_unwitnessed_seconds"], 3600);
}

#[test]
fn forged_local_anchor_times_fail_the_gate_in_full_mode() {
    let ws = Workspace::new();
    let tip = ws.eight_hour_chain(forged_anchors());
    let out = ws.verify(&tip, &["--full"]);
    assert!(
        !out.status.success(),
        "--full ignored --max-unwitnessed:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// A genuine Rekor proof lifted from another artifact and stapled here is
/// rejected by name, and does not count.
#[test]
fn stapled_proof_for_another_artifact_is_rejected() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../core/tests/fixtures/rekor/public-good-dsse.json"
    ))
    .unwrap();
    let ws = Workspace::new();
    let tip = ws.eight_hour_chain(vec![RecordAnchor {
        mechanism: "rekor".into(),
        observed_at: "2026-09-01T14:00:00Z".into(),
        reference: None,
        status: Some("anchored".into()),
        reason: None,
        proof: Some(fixture["entry"].clone()),
    }]);
    let out = ws.verify(&tip, &["--format", "json"]);
    assert!(!out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let rejected = v["anchoring"]["tally"]["rejected"].as_array().unwrap();
    assert_eq!(rejected.len(), 1, "{v}");
    assert!(
        rejected[0]
            .as_str()
            .unwrap()
            .contains("not for this artifact"),
        "{v}"
    );
}

/// Without --max-unwitnessed nothing is gated: unanchored work is normal and
/// the signatures are valid. The verdict still says what it saw.
#[test]
fn without_a_policy_forged_anchors_are_reported_not_gated() {
    let ws = Workspace::new();
    let tip = ws.eight_hour_chain(forged_anchors());
    let out = ws
        .cmd()
        .args(["verify", &tip, "--format", "json"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["anchoring"]["gate"].is_null());
    assert_eq!(v["anchoring"]["tally"]["claimed_unverified"], 16);
}

/// Third variant of the same gate bug: the claimed span came from the
/// unsigned `Record.signed_at`. Editing both records to the same minute made
/// an eight-hour signed chain look instantaneous, and "no timeline" passed
/// any policy with zero anchors.
#[test]
fn edited_record_times_do_not_shrink_the_signed_span() {
    let ws = Workspace::new();
    let root =
        ws.plant_with_record_time("2026-09-01T10:00:00Z", "2026-09-01T18:00:00Z", None, vec![]);
    let tip = ws.plant("2026-09-01T18:00:00Z", Some(&root), vec![]);
    let out = ws.verify(&tip, &["--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        v["anchoring"]["coverage"]["claimed_span_seconds"],
        8 * 3600,
        "{v}"
    );
    assert!(
        !out.status.success(),
        "compressed record times passed the gate: {v}"
    );
}

/// A policy that passes must say so, not look like "no policy".
#[test]
fn a_passing_policy_is_distinguishable_from_no_policy() {
    let ws = Workspace::new();
    let tip = ws.plant("2026-09-01T10:00:00Z", None, vec![]);
    let out = ws.verify(&tip, &["--format", "json"]);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["anchoring"]["gate"]["passed"], true, "{v}");
}
