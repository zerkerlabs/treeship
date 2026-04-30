//! Integration tests for v0.9.9 PR 6: Hub-signed checkpoint verification
//! against an embedded `.treeship` package's approval evidence.
//!
//! These tests exercise the full path:
//!   - build a fixture `.treeship` package with one ApprovalUse
//!   - sign a `JournalCheckpoint { kind: HubOrg, ... }` with a real
//!     Ed25519 key
//!   - drop the signed checkpoint into the package's approvals/checkpoints/
//!   - re-read the package via `read_approvals_bundle`
//!   - run `verify_package` and inspect the synthesized
//!     `replay-hub-org` row
//!
//! The release rule "PASS only when signature verifies AND covers
//! every use" is what every test pins.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;

use treeship_core::session::{
    build_package_with_approvals, read_approvals_bundle, verify_package,
    ApprovalsBundle, VerifyStatus,
};
use treeship_core::statements::{
    CheckpointKind, JournalCheckpoint, ApprovalUse, ReplayCheckLevel,
    TYPE_APPROVAL_USE, TYPE_JOURNAL_CHECKPOINT,
    approval_use_record_digest, journal_checkpoint_record_digest,
};

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

fn make_use(use_id: &str, grant_id: &str, max_uses: u32) -> ApprovalUse {
    let mut u = ApprovalUse {
        type_:                  TYPE_APPROVAL_USE.into(),
        use_id:                 use_id.into(),
        grant_id:               grant_id.into(),
        grant_digest:           "sha256:00".into(),
        nonce_digest:           "sha256:nn".into(),
        actor:                  "agent://deployer".into(),
        action:                 "deploy.production".into(),
        subject:                "env://production".into(),
        session_id:             None,
        action_artifact_id:     None,
        receipt_digest:         None,
        use_number:             1,
        max_uses:               Some(max_uses),
        idempotency_key:        None,
        created_at:             "2026-04-30T08:00:00Z".into(),
        expires_at:             None,
        previous_record_digest: String::new(),
        record_digest:          String::new(),
        signature:              None,
        signature_alg:          None,
        signing_key_id:         None,
    };
    u.record_digest = approval_use_record_digest(&u);
    u
}

fn sign_hub_checkpoint(
    sk: &SigningKey,
    use_ids: Vec<String>,
) -> JournalCheckpoint {
    let pk = sk.verifying_key();
    let mut cp = JournalCheckpoint {
        type_:                  TYPE_JOURNAL_CHECKPOINT.into(),
        checkpoint_id:          "cp_hub_test".into(),
        checkpoint_kind:        CheckpointKind::HubOrg,
        from_record_index:      1,
        to_record_index:        use_ids.len() as u64,
        merkle_root:            "sha256:demo".into(),
        leaf_count:             use_ids.len() as u64,
        journal_id:             "test-journal".into(),
        created_at:             "2026-04-30T08:00:00Z".into(),
        hub_id:                 "hub://zerker-test".into(),
        hub_public_key:         URL_SAFE_NO_PAD.encode(pk.to_bytes()),
        hub_signature:          String::new(),
        signed_at:              "2026-04-30T08:00:00Z".into(),
        covered_use_ids:        use_ids,
        covered_grant_ids:      Vec::new(),
        previous_record_digest: String::new(),
        record_digest:          String::new(),
        signature:              None,
        signature_alg:          None,
        signing_key_id:         None,
    };
    let payload = cp.canonical_hub_signing_bytes();
    let sig = sk.sign(&payload);
    cp.hub_signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    cp.record_digest = journal_checkpoint_record_digest(&cp);
    cp
}

fn make_minimal_receipt() -> treeship_core::session::SessionReceipt {
    use treeship_core::session::{
        manifest::SessionManifest,
        receipt::{ArtifactEntry, ReceiptComposer},
        event::{EventType, SessionEvent},
    };
    let manifest = SessionManifest::new(
        "ssn_hub_test".into(),
        "agent://test".into(),
        "2026-04-30T08:00:00Z".into(),
        1745035200000,
    );
    let mk = |seq: u64, et: EventType| -> SessionEvent {
        SessionEvent {
            session_id: "ssn_hub_test".into(),
            event_id: format!("evt_{:016x}", seq),
            timestamp: format!("2026-04-30T08:00:{:02}Z", seq),
            sequence_no: seq,
            trace_id: "tr".into(),
            span_id: format!("sp_{seq}"),
            parent_span_id: None,
            agent_id: "agent://test".into(),
            agent_instance_id: "test".into(),
            agent_name: "test".into(),
            agent_role: None,
            host_id: "host_1".into(),
            tool_runtime_id: None,
            event_type: et,
            artifact_ref: None,
            meta: None,
        }
    };
    let events = vec![
        mk(0, EventType::SessionStarted),
        mk(1, EventType::AgentStarted { parent_agent_instance_id: None }),
        mk(2, EventType::AgentCompleted { termination_reason: None }),
        mk(3, EventType::SessionClosed { summary: None, duration_ms: None }),
    ];
    let artifacts = vec![
        ArtifactEntry { artifact_id: "art_use_1".into(), payload_type: "action".into(), digest: None, signed_at: None },
    ];
    ReceiptComposer::compose(&manifest, &events, artifacts)
}

fn build_package_with_bundle(
    bundle: ApprovalsBundle,
) -> std::path::PathBuf {
    let receipt = make_minimal_receipt();
    let tmp = std::env::temp_dir().join(format!("treeship-hub-test-{}", rand::random::<u32>()));
    let out = build_package_with_approvals(&receipt, &tmp, Some(&bundle)).unwrap();
    out.path
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Acceptance: no Hub checkpoint embedded -> no replay-hub-org row.
/// The Approval Authority panel renders "- not checked" instead.
#[test]
fn no_hub_checkpoint_no_row() {
    let mut bundle = ApprovalsBundle::default();
    bundle.uses.push(make_use("use_a", "art_g", 1));
    let pkg = build_package_with_bundle(bundle);

    let checks = verify_package(&pkg).unwrap();
    let hub_rows: Vec<_> = checks.iter().filter(|c| c.name == "replay-hub-org").collect();
    assert!(hub_rows.is_empty(), "no hub-org row should be emitted: {:?}", hub_rows);
}

/// Acceptance: valid signed Hub checkpoint covering every use -> PASS.
#[test]
fn valid_hub_checkpoint_passes() {
    let sk = SigningKey::from_bytes(&[7u8; 32]);

    let mut bundle = ApprovalsBundle::default();
    let u = make_use("use_a", "art_g", 1);
    let cp = sign_hub_checkpoint(&sk, vec!["use_a".into()]);
    bundle.uses.push(u);
    bundle.checkpoints.push(cp);

    let pkg = build_package_with_bundle(bundle);
    let checks = verify_package(&pkg).unwrap();
    let hub = checks.iter().find(|c| c.name == "replay-hub-org")
        .expect("replay-hub-org row expected");
    assert_eq!(hub.status, VerifyStatus::Pass, "expected PASS, got: {hub:?}");
    assert!(hub.detail.contains("verifies"), "detail should mention verification: {}", hub.detail);
}

/// Acceptance: tampered signature -> default WARN (CLI --strict promotes
/// to FAIL; tested in the CLI integration tests).
#[test]
fn tampered_hub_signature_warns_default() {
    let sk = SigningKey::from_bytes(&[8u8; 32]);

    let u = make_use("use_a", "art_g", 1);
    let mut cp = sign_hub_checkpoint(&sk, vec!["use_a".into()]);
    // Tamper: flip a coverage entry. canonical_hub_signing_bytes
    // changes -> stored signature no longer applies.
    cp.covered_use_ids.push("use_smuggled".into());

    let mut bundle = ApprovalsBundle::default();
    bundle.uses.push(u);
    bundle.checkpoints.push(cp);

    let pkg = build_package_with_bundle(bundle);
    let checks = verify_package(&pkg).unwrap();
    let hub = checks.iter().find(|c| c.name == "replay-hub-org")
        .expect("replay-hub-org row expected");
    assert_eq!(hub.status, VerifyStatus::Warn, "expected WARN on tamper, got: {hub:?}");
    assert!(
        hub.detail.contains("hub signature failed") || hub.detail.contains("tampered"),
        "detail should mention signature failure: {}",
        hub.detail,
    );
}

/// Acceptance: signed checkpoint that DOESN'T cover the package's
/// uses -> WARN. The signature verifies but coverage is incomplete.
#[test]
fn hub_checkpoint_missing_use_coverage_warns() {
    let sk = SigningKey::from_bytes(&[9u8; 32]);

    let u_a = make_use("use_a", "art_g", 1);
    let u_b = make_use("use_b", "art_g", 1);
    // Checkpoint only covers use_a; use_b is uncovered.
    let cp = sign_hub_checkpoint(&sk, vec!["use_a".into()]);

    let mut bundle = ApprovalsBundle::default();
    bundle.uses.push(u_a);
    bundle.uses.push(u_b);
    bundle.checkpoints.push(cp);

    let pkg = build_package_with_bundle(bundle);
    let checks = verify_package(&pkg).unwrap();
    let hub = checks.iter().find(|c| c.name == "replay-hub-org")
        .expect("replay-hub-org row expected");
    assert_eq!(hub.status, VerifyStatus::Warn, "expected WARN on missing coverage, got: {hub:?}");
    assert!(hub.detail.contains("does not cover") || hub.detail.contains("not cover"),
        "detail should mention coverage gap: {}", hub.detail);
}

/// Acceptance: missing required Hub field -> WARN with which field
/// is missing.
#[test]
fn hub_checkpoint_missing_field_warns() {
    let sk = SigningKey::from_bytes(&[10u8; 32]);

    let u = make_use("use_a", "art_g", 1);
    let mut cp = sign_hub_checkpoint(&sk, vec!["use_a".into()]);
    cp.hub_id = String::new(); // explicitly clear required field

    let mut bundle = ApprovalsBundle::default();
    bundle.uses.push(u);
    bundle.checkpoints.push(cp);

    let pkg = build_package_with_bundle(bundle);
    let checks = verify_package(&pkg).unwrap();
    let hub = checks.iter().find(|c| c.name == "replay-hub-org")
        .expect("replay-hub-org row expected");
    assert_eq!(hub.status, VerifyStatus::Warn);
    assert!(hub.detail.contains("hub_id"), "detail should name missing field: {}", hub.detail);
}

/// Acceptance: a LocalJournal-kind checkpoint must NOT promote
/// replay-hub-org. The discriminator is what makes this safe -- a
/// well-formed local checkpoint without Hub fields shouldn't be
/// confusable for a Hub checkpoint just because it shares the JSON shape.
#[test]
fn local_journal_kind_does_not_promote_hub_org() {
    let mut cp = JournalCheckpoint {
        type_:                  TYPE_JOURNAL_CHECKPOINT.into(),
        checkpoint_id:          "cp_local_only".into(),
        checkpoint_kind:        CheckpointKind::LocalJournal,
        from_record_index:      1,
        to_record_index:        1,
        merkle_root:            "sha256:00".into(),
        leaf_count:             1,
        journal_id:             "journal".into(),
        created_at:             "2026-04-30T08:00:00Z".into(),
        hub_id:                 String::new(),
        hub_public_key:         String::new(),
        hub_signature:          String::new(),
        signed_at:              String::new(),
        covered_use_ids:        Vec::new(),
        covered_grant_ids:      Vec::new(),
        previous_record_digest: String::new(),
        record_digest:          String::new(),
        signature:              None,
        signature_alg:          None,
        signing_key_id:         None,
    };
    cp.record_digest = journal_checkpoint_record_digest(&cp);

    let mut bundle = ApprovalsBundle::default();
    bundle.uses.push(make_use("use_a", "art_g", 1));
    bundle.checkpoints.push(cp);

    let pkg = build_package_with_bundle(bundle);
    let checks = verify_package(&pkg).unwrap();
    let hub = checks.iter().find(|c| c.name == "replay-hub-org");
    assert!(hub.is_none(), "local-journal-kind checkpoint must not emit replay-hub-org row");

    // included-checkpoint should still pass for the local-kind one.
    let inc = checks.iter().find(|c| c.name == "replay-included-checkpoint");
    assert!(inc.is_some(), "included-checkpoint row should still appear for local kind");
}

/// Smoke: bundle round-trips through write/read; the kind discriminator
/// survives serialization. Pre-PR-6 packages (no checkpoint_kind field)
/// deserialize as LocalJournal.
#[test]
fn checkpoint_kind_round_trip() {
    let sk = SigningKey::from_bytes(&[11u8; 32]);
    let u  = make_use("use_a", "art_g", 1);
    let cp = sign_hub_checkpoint(&sk, vec!["use_a".into()]);

    let mut bundle = ApprovalsBundle::default();
    bundle.uses.push(u);
    bundle.checkpoints.push(cp.clone());

    let pkg = build_package_with_bundle(bundle);
    let read = read_approvals_bundle(&pkg).unwrap();
    assert_eq!(read.checkpoints.len(), 1);
    assert_eq!(read.checkpoints[0].checkpoint_kind, CheckpointKind::HubOrg);
    assert_eq!(read.checkpoints[0].hub_id, "hub://zerker-test");

    // Hand-craft a JSON that omits checkpoint_kind (pre-PR-6 shape).
    let json: Value = serde_json::from_value(serde_json::json!({
        "type": TYPE_JOURNAL_CHECKPOINT,
        "checkpoint_id": "cp_legacy",
        "from_record_index": 1,
        "to_record_index": 1,
        "merkle_root": "sha256:0",
        "leaf_count": 1,
        "journal_id": "j",
        "created_at": "2026-04-30T08:00:00Z",
    })).unwrap();
    let cp_legacy: JournalCheckpoint = serde_json::from_value(json).unwrap();
    assert_eq!(cp_legacy.checkpoint_kind, CheckpointKind::LocalJournal);

    // Tag the unused-import warning silenced.
    let _ = ReplayCheckLevel::HubOrg;
}
