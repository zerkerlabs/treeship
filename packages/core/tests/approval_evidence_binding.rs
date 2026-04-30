//! Integration tests for v0.9.10 PR A: closing the four trust-bypass
//! paths Codex's adversarial review of v0.9.9 found.
//!
//! Each test builds a fixture `.treeship` package with deliberately
//! tampered approval evidence and asserts that `verify_package` flags
//! the right row. The tests are the regression pins for:
//!
//!   1. action↔use binding (via meta.approval_use_id)        → approval-use-action-binding
//!   2. nonce binding (use.nonce_digest vs grant.nonce)      → approval-use-nonce-binding
//!   3. record-digest integrity (renamed from -integrity)    → approval-use-record-digest
//!   4. embedded chain continuity                            → approval-use-chain-continuity
//!
//! The TOCTOU race fix (Blocker 1) is unit-tested in the journal
//! module itself; this file exercises only the package-level checks.

use serde_json::{json, Value};

use treeship_core::session::{
    build_package_with_approvals, read_approvals_bundle, verify_package,
    ApprovalsBundle, VerifyStatus,
};
use treeship_core::statements::{
    ApprovalUse, TYPE_APPROVAL_USE, approval_use_record_digest, nonce_digest,
};

// ---------------------------------------------------------------------------
// Fixture builders
// ---------------------------------------------------------------------------

fn make_use_with_nonce(use_id: &str, grant_id: &str, raw_nonce: &str) -> ApprovalUse {
    let mut u = ApprovalUse {
        type_:                  TYPE_APPROVAL_USE.into(),
        use_id:                 use_id.into(),
        grant_id:               grant_id.into(),
        grant_digest:           "sha256:00".into(),
        nonce_digest:           nonce_digest(raw_nonce),
        actor:                  "agent://deployer".into(),
        action:                 "deploy.production".into(),
        subject:                "env://production".into(),
        session_id:             None,
        action_artifact_id:     None,
        receipt_digest:         None,
        use_number:             1,
        max_uses:               Some(1),
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

/// Build a fake-but-canonical signed ApprovalStatement envelope JSON
/// carrying the given raw nonce. The signatures aren't real Ed25519
/// here; we only need `Envelope::from_json` + `unmarshal_statement`
/// to succeed, and the verifier to read the grant's `nonce` field.
fn fake_grant_envelope(_grant_id: &str, raw_nonce: &str) -> Vec<u8> {
    use base64::Engine;
    // Field names match ApprovalStatement's serde renames
    // (timestamp / approver / nonce / delegatable required).
    let payload = json!({
        "type": "treeship/approval/v1",
        "timestamp": "2026-04-30T07:00:00Z",
        "approver": "human://alice",
        "subject": { "uri": "env://production" },
        "delegatable": false,
        "nonce": raw_nonce,
    });
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).unwrap());
    let env = json!({
        "payload": payload_b64,
        "payloadType": "application/vnd.treeship.approval.v1+json",
        "signatures": [{ "keyid": "key_test", "sig": "AA" }],
    });
    serde_json::to_vec(&env).unwrap()
}

/// Build a fake-but-canonical signed ActionStatement envelope JSON
/// carrying the given approval_nonce and meta.approval_use_id. Useful
/// for testing what verify sees when the action envelope ships in
/// `artifacts/`.
fn fake_action_envelope(
    artifact_id: &str,
    raw_nonce: &str,
    approval_use_id: Option<&str>,
) -> (String, Vec<u8>) {
    use base64::Engine;
    let meta: Value = match approval_use_id {
        Some(id) => json!({ "approval_use_id": id }),
        None     => json!({}),
    };
    // Field names match ActionStatement's serde renames
    // (approvalNonce / parentId / policyRef / type / timestamp).
    let payload = json!({
        "type": "treeship/action/v1",
        "timestamp": "2026-04-30T08:00:00Z",
        "actor": "agent://deployer",
        "action": "deploy.production",
        "subject": { "uri": "env://production" },
        "approvalNonce": raw_nonce,
        "meta": meta,
    });
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).unwrap());
    let env = json!({
        "payload": payload_b64,
        "payloadType": "application/vnd.treeship.action.v1+json",
        "signatures": [{ "keyid": "key_test", "sig": "AA" }],
    });
    (artifact_id.to_string(), serde_json::to_vec(&env).unwrap())
}

fn make_minimal_receipt(action_artifact_ids: &[&str]) -> treeship_core::session::SessionReceipt {
    use treeship_core::session::{
        manifest::SessionManifest,
        receipt::{ArtifactEntry, ReceiptComposer},
        event::{EventType, SessionEvent},
    };
    let manifest = SessionManifest::new(
        "ssn_v0_9_10_test".into(),
        "agent://test".into(),
        "2026-04-30T08:00:00Z".into(),
        1745035200000,
    );
    let mk = |seq: u64, et: EventType| -> SessionEvent {
        SessionEvent {
            session_id: "ssn_v0_9_10_test".into(),
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
    let artifacts: Vec<ArtifactEntry> = action_artifact_ids
        .iter()
        .map(|id| ArtifactEntry {
            artifact_id: id.to_string(),
            payload_type: "application/vnd.treeship.action.v1+json".into(),
            digest: None,
            signed_at: None,
        })
        .collect();
    ReceiptComposer::compose(&manifest, &events, artifacts)
}

fn build(bundle: ApprovalsBundle, action_ids: &[&str]) -> std::path::PathBuf {
    let receipt = make_minimal_receipt(action_ids);
    let tmp = std::env::temp_dir().join(format!("treeship-bind-{}", rand::random::<u32>()));
    let out = build_package_with_approvals(&receipt, &tmp, Some(&bundle)).unwrap();
    out.path
}

fn find_check<'a>(
    checks: &'a [treeship_core::session::VerifyCheck],
    name: &str,
) -> Option<&'a treeship_core::session::VerifyCheck> {
    checks.iter().find(|c| c.name == name)
}

// ---------------------------------------------------------------------------
// Fix 2 — action↔use binding
// ---------------------------------------------------------------------------

#[test]
fn action_envelope_with_correct_use_id_binds_cleanly() {
    let nonce = "raw_nonce_alpha";
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push(("g1".into(), fake_grant_envelope("g1", nonce)));
    bundle.uses.push(make_use_with_nonce("use_real", "g1", nonce));
    let (art_id, env) = fake_action_envelope("art_a", nonce, Some("use_real"));
    bundle.action_envelopes.push((art_id, env));

    let pkg = build(bundle, &["art_a"]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-action-binding")
        .expect("approval-use-action-binding row required");
    assert_eq!(row.status, VerifyStatus::Pass, "expected PASS, got: {row:?}");
    assert!(row.detail.contains("bind cleanly"), "detail: {}", row.detail);
}

#[test]
fn action_envelope_with_nonexistent_use_id_fails_binding() {
    // The exact v0.9.9 attack: action.meta.approval_use_id points at a
    // use_id that has no record. v0.9.9 verify ignored this; v0.9.10
    // catches it.
    let nonce = "raw_nonce_beta";
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push(("g1".into(), fake_grant_envelope("g1", nonce)));
    bundle.uses.push(make_use_with_nonce("use_real", "g1", nonce));
    let (art_id, env) = fake_action_envelope("art_a", nonce, Some("use_does_not_exist"));
    bundle.action_envelopes.push((art_id, env));

    let pkg = build(bundle, &["art_a"]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-action-binding")
        .expect("approval-use-action-binding row required");
    assert_eq!(row.status, VerifyStatus::Fail, "expected FAIL on missing use_id, got: {row:?}");
    assert!(row.detail.contains("use_does_not_exist"), "detail: {}", row.detail);
}

#[test]
fn action_envelope_missing_use_id_pointer_fails_binding() {
    // Action carries approval_nonce but its meta has no
    // approval_use_id. v0.9.9 didn't care; v0.9.10 fails.
    let nonce = "raw_nonce_gamma";
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push(("g1".into(), fake_grant_envelope("g1", nonce)));
    bundle.uses.push(make_use_with_nonce("use_real", "g1", nonce));
    let (art_id, env) = fake_action_envelope("art_a", nonce, None); // no approval_use_id
    bundle.action_envelopes.push((art_id, env));

    let pkg = build(bundle, &["art_a"]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-action-binding")
        .expect("approval-use-action-binding row required");
    assert_eq!(row.status, VerifyStatus::Fail);
    assert!(row.detail.contains("no approval_use_id"), "detail: {}", row.detail);
}

#[test]
fn package_without_action_envelopes_warns_binding_unasserted() {
    // Pre-v0.9.10 packages: artifacts/ dir empty, no action envelopes
    // shipped. Verify must NOT silently pass; it must report the row
    // as `not asserted by package`.
    let nonce = "raw_nonce_delta";
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push(("g1".into(), fake_grant_envelope("g1", nonce)));
    bundle.uses.push(make_use_with_nonce("use_real", "g1", nonce));
    // No action_envelopes deliberately.

    let pkg = build(bundle, &["art_a"]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-action-binding")
        .expect("approval-use-action-binding row required");
    assert_eq!(row.status, VerifyStatus::Warn);
    assert!(row.detail.contains("not asserted by package"), "detail: {}", row.detail);
}

// ---------------------------------------------------------------------------
// Fix 3 — nonce binding (use.nonce_digest vs grant.nonce)
// ---------------------------------------------------------------------------

#[test]
fn use_nonce_digest_matches_grant_signed_nonce_passes() {
    let nonce = "raw_nonce_epsilon";
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push(("g1".into(), fake_grant_envelope("g1", nonce)));
    bundle.uses.push(make_use_with_nonce("use_real", "g1", nonce));

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-nonce-binding")
        .expect("approval-use-nonce-binding row required");
    assert_eq!(row.status, VerifyStatus::Pass, "expected PASS, got: {row:?}");
}

#[test]
fn tampered_use_nonce_digest_fails_binding() {
    // The exact v0.9.9 attack: edit the use's nonce_digest to claim a
    // different consumption, then recompute record_digest. v0.9.9
    // accepted; v0.9.10 cross-checks against the grant's signed nonce.
    let real_nonce = "raw_nonce_zeta";
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push(("g1".into(), fake_grant_envelope("g1", real_nonce)));

    let mut tampered_use = make_use_with_nonce("use_real", "g1", real_nonce);
    // Mutate nonce_digest to claim consumption of a different grant's
    // nonce. Recompute record_digest so the per-record digest still
    // matches (this is the v0.9.9 forgery primitive).
    tampered_use.nonce_digest = nonce_digest("a_different_nonce");
    tampered_use.record_digest = approval_use_record_digest(&tampered_use);
    bundle.uses.push(tampered_use);

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-nonce-binding")
        .expect("approval-use-nonce-binding row required");
    assert_eq!(row.status, VerifyStatus::Fail, "expected FAIL on nonce mismatch, got: {row:?}");
    assert!(
        row.detail.contains("hashes to") || row.detail.contains("nonce_digest"),
        "detail: {}",
        row.detail,
    );
}

#[test]
fn use_referencing_unknown_grant_fails_binding() {
    let mut bundle = ApprovalsBundle::default();
    // Use without its grant in the bundle.
    bundle.uses.push(make_use_with_nonce("use_orphan", "g_missing", "n"));

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-nonce-binding")
        .expect("approval-use-nonce-binding row required");
    assert_eq!(row.status, VerifyStatus::Fail);
    assert!(row.detail.contains("not in the package"), "detail: {}", row.detail);
}

// ---------------------------------------------------------------------------
// Fix 4 — embedded chain continuity
// ---------------------------------------------------------------------------

#[test]
fn embedded_chain_anchored_to_genesis_passes() {
    let nonce = "raw_nonce_eta";
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push(("g1".into(), fake_grant_envelope("g1", nonce)));
    let u = make_use_with_nonce("use_real", "g1", nonce);
    // Default previous_record_digest is empty string = genesis.
    bundle.uses.push(u);

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();
    let row = find_check(&checks, "approval-use-chain-continuity")
        .expect("approval-use-chain-continuity row required");
    assert_eq!(row.status, VerifyStatus::Pass);
}

#[test]
fn dangling_previous_record_digest_fails_chain_continuity() {
    // Attacker rewrites a use record's previous_record_digest to point
    // at an arbitrary value not anchored in this package.
    let nonce = "raw_nonce_theta";
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push(("g1".into(), fake_grant_envelope("g1", nonce)));
    let mut u = make_use_with_nonce("use_real", "g1", nonce);
    u.previous_record_digest = "sha256:dangling_anchor_no_record_here".into();
    u.record_digest = approval_use_record_digest(&u); // re-sync digest after edit
    bundle.uses.push(u);

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-chain-continuity")
        .expect("approval-use-chain-continuity row required");
    assert_eq!(row.status, VerifyStatus::Fail, "expected FAIL on dangling chain, got: {row:?}");
    assert!(row.detail.contains("not anchored"), "detail: {}", row.detail);
}

#[test]
fn two_use_chain_with_correct_links_passes() {
    let nonce_a = "raw_nonce_iota_a";
    let nonce_b = "raw_nonce_iota_b";
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push(("g1".into(), fake_grant_envelope("g1", nonce_a)));
    bundle.grants.push(("g2".into(), fake_grant_envelope("g2", nonce_b)));

    let u1 = make_use_with_nonce("use_1", "g1", nonce_a);
    let u1_digest = u1.record_digest.clone();
    let mut u2 = make_use_with_nonce("use_2", "g2", nonce_b);
    u2.previous_record_digest = u1_digest;
    u2.record_digest = approval_use_record_digest(&u2);
    bundle.uses.push(u1);
    bundle.uses.push(u2);

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-chain-continuity")
        .expect("approval-use-chain-continuity row required");
    assert_eq!(row.status, VerifyStatus::Pass);
}

// ---------------------------------------------------------------------------
// Fix 5 — record-digest rename + label hygiene
// ---------------------------------------------------------------------------

#[test]
fn renamed_record_digest_row_emits_for_present_uses() {
    let nonce = "raw_nonce_kappa";
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push(("g1".into(), fake_grant_envelope("g1", nonce)));
    bundle.uses.push(make_use_with_nonce("use_real", "g1", nonce));

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();

    assert!(
        find_check(&checks, "approval-use-record-digest").is_some(),
        "v0.9.10 must emit approval-use-record-digest",
    );
    assert!(
        find_check(&checks, "approval-use-integrity").is_none(),
        "v0.9.10 must NOT emit the old approval-use-integrity label",
    );
}

#[test]
fn read_back_round_trips_action_envelopes() {
    // The v0.9.10 package format ships action envelopes in
    // `artifacts/`; round-trip via build + read_approvals_bundle.
    let nonce = "raw_nonce_lambda";
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push(("g1".into(), fake_grant_envelope("g1", nonce)));
    bundle.uses.push(make_use_with_nonce("use_real", "g1", nonce));
    let (art_id, env) = fake_action_envelope("art_a", nonce, Some("use_real"));
    bundle.action_envelopes.push((art_id.clone(), env.clone()));

    let pkg = build(bundle, &["art_a"]);

    let read_back = read_approvals_bundle(&pkg).unwrap();
    assert_eq!(read_back.action_envelopes.len(), 1);
    assert_eq!(read_back.action_envelopes[0].0, art_id);
    assert_eq!(read_back.action_envelopes[0].1, env);
}
