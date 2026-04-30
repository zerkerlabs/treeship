//! Integration tests for v0.9.10 PR A: closing the four trust-bypass
//! paths Codex's adversarial review of v0.9.9 found, plus the
//! adjacent hardenings the v0.9.10 PR A round-2 re-check flagged
//! (content-addressed envelope verification, tightened chain
//! continuity).
//!
//! Each test builds a fixture `.treeship` package with deliberately
//! tampered approval evidence and asserts that `verify_package` flags
//! the right row.
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

/// Build a fake-but-canonical signed ApprovalStatement envelope JSON.
/// Returns `(derived_grant_id, envelope_bytes)` where the grant_id is
/// derived from the envelope's PAE bytes via `artifact_id_from_pae` --
/// matching production sign behavior. v0.9.10 PR A round 2 verifies
/// content addressing, so test fixtures must produce envelopes whose
/// derived id matches the grant_id we ship them under.
fn fake_grant_envelope(raw_nonce: &str) -> (String, Vec<u8>) {
    use base64::Engine;
    use treeship_core::attestation::{pae, artifact_id_from_pae};
    let payload = json!({
        "type": "treeship/approval/v1",
        "timestamp": "2026-04-30T07:00:00Z",
        "approver": "human://alice",
        "subject": { "uri": "env://production" },
        "delegatable": false,
        "nonce": raw_nonce,
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let payload_type = "application/vnd.treeship.approval.v1+json";
    let pae_bytes = pae(payload_type, &payload_bytes);
    let derived_id = artifact_id_from_pae(&pae_bytes);
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_bytes);
    let env = json!({
        "payload": payload_b64,
        "payloadType": payload_type,
        "signatures": [{ "keyid": "key_test", "sig": "AA" }],
    });
    (derived_id, serde_json::to_vec(&env).unwrap())
}

/// Build a fake-but-canonical signed ActionStatement envelope JSON.
/// Returns `(derived_artifact_id, envelope_bytes)`.
fn fake_action_envelope(
    raw_nonce: &str,
    approval_use_id: Option<&str>,
) -> (String, Vec<u8>) {
    use base64::Engine;
    use treeship_core::attestation::{pae, artifact_id_from_pae};
    let meta: Value = match approval_use_id {
        Some(id) => json!({ "approval_use_id": id }),
        None     => json!({}),
    };
    let payload = json!({
        "type": "treeship/action/v1",
        "timestamp": "2026-04-30T08:00:00Z",
        "actor": "agent://deployer",
        "action": "deploy.production",
        "subject": { "uri": "env://production" },
        "approvalNonce": raw_nonce,
        "meta": meta,
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();
    let payload_type = "application/vnd.treeship.action.v1+json";
    let pae_bytes = pae(payload_type, &payload_bytes);
    let derived_id = artifact_id_from_pae(&pae_bytes);
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload_bytes);
    let env = json!({
        "payload": payload_b64,
        "payloadType": payload_type,
        "signatures": [{ "keyid": "key_test", "sig": "AA" }],
    });
    (derived_id, serde_json::to_vec(&env).unwrap())
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
// Fix 2 — action↔use binding (content-addressed)
// ---------------------------------------------------------------------------

#[test]
fn action_envelope_with_correct_use_id_binds_cleanly() {
    let nonce = "raw_nonce_alpha";
    let (g_id, g_env) = fake_grant_envelope(nonce);
    let (art_id, env) = fake_action_envelope(nonce, Some("use_real"));
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g_id.clone(), g_env));
    bundle.uses.push(make_use_with_nonce("use_real", &g_id, nonce));
    bundle.action_envelopes.push((art_id.clone(), env));

    let pkg = build(bundle, &[art_id.as_str()]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-action-binding")
        .expect("approval-use-action-binding row required");
    assert_eq!(row.status, VerifyStatus::Pass, "expected PASS, got: {row:?}");
    assert!(row.detail.contains("bind cleanly"), "detail: {}", row.detail);
}

#[test]
fn action_envelope_with_nonexistent_use_id_fails_binding() {
    let nonce = "raw_nonce_beta";
    let (g_id, g_env) = fake_grant_envelope(nonce);
    let (art_id, env) = fake_action_envelope(nonce, Some("use_does_not_exist"));
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g_id.clone(), g_env));
    bundle.uses.push(make_use_with_nonce("use_real", &g_id, nonce));
    bundle.action_envelopes.push((art_id.clone(), env));

    let pkg = build(bundle, &[art_id.as_str()]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-action-binding")
        .expect("approval-use-action-binding row required");
    assert_eq!(row.status, VerifyStatus::Fail, "expected FAIL on missing use_id, got: {row:?}");
    assert!(row.detail.contains("use_does_not_exist"), "detail: {}", row.detail);
}

#[test]
fn action_envelope_missing_use_id_pointer_fails_binding() {
    let nonce = "raw_nonce_gamma";
    let (g_id, g_env) = fake_grant_envelope(nonce);
    let (art_id, env) = fake_action_envelope(nonce, None);
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g_id.clone(), g_env));
    bundle.uses.push(make_use_with_nonce("use_real", &g_id, nonce));
    bundle.action_envelopes.push((art_id.clone(), env));

    let pkg = build(bundle, &[art_id.as_str()]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-action-binding")
        .expect("approval-use-action-binding row required");
    assert_eq!(row.status, VerifyStatus::Fail);
    assert!(row.detail.contains("no approval_use_id"), "detail: {}", row.detail);
}

#[test]
fn package_without_action_envelopes_warns_binding_unasserted() {
    let nonce = "raw_nonce_delta";
    let (g_id, g_env) = fake_grant_envelope(nonce);
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g_id.clone(), g_env));
    bundle.uses.push(make_use_with_nonce("use_real", &g_id, nonce));

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-action-binding")
        .expect("approval-use-action-binding row required");
    assert_eq!(row.status, VerifyStatus::Warn);
    assert!(row.detail.contains("not asserted by package"), "detail: {}", row.detail);
}

/// Round-2 hardening regression: an attacker writes a forged action
/// envelope at `artifacts/<some_id>.json` whose content does NOT
/// derive to that id. v0.9.10 PR A round 1 trusted the file name and
/// parsed `meta.approval_use_id` from arbitrary bytes; round 2 rejects
/// because content-derived artifact_id mismatches the filename stem.
#[test]
fn forged_action_envelope_under_wrong_id_fails_content_addressing() {
    use treeship_core::session::ApprovalsBundle;
    let nonce = "raw_nonce_forge_action";
    let (g_id, g_env) = fake_grant_envelope(nonce);
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g_id.clone(), g_env));
    bundle.uses.push(make_use_with_nonce("use_real", &g_id, nonce));

    // Real action envelope -> derives to art_a.
    let (real_art_id, real_env) = fake_action_envelope(nonce, Some("use_real"));
    // Different action envelope (different nonce, different
    // approval_use_id) -> derives to a different art_b.
    let (fake_art_id, fake_env) = fake_action_envelope("a_different_nonce", Some("use_real"));
    assert_ne!(real_art_id, fake_art_id, "fixture sanity: forge must derive to a distinct id");

    // The attack: ship the FORGED envelope under the REAL id. The
    // file content does not derive to its filename.
    bundle.action_envelopes.push((real_art_id.clone(), fake_env));

    let pkg = build(bundle, &[real_art_id.as_str()]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-action-binding")
        .expect("approval-use-action-binding row required");
    assert_eq!(row.status, VerifyStatus::Fail, "expected FAIL on substituted envelope, got: {row:?}");
    assert!(
        row.detail.contains("substituted or tampered") || row.detail.contains("content derives"),
        "detail: {}",
        row.detail,
    );
}

// ---------------------------------------------------------------------------
// Fix 3 — nonce binding (content-addressed grant envelope)
// ---------------------------------------------------------------------------

#[test]
fn use_nonce_digest_matches_grant_signed_nonce_passes() {
    let nonce = "raw_nonce_epsilon";
    let (g_id, g_env) = fake_grant_envelope(nonce);
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g_id.clone(), g_env));
    bundle.uses.push(make_use_with_nonce("use_real", &g_id, nonce));

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-nonce-binding")
        .expect("approval-use-nonce-binding row required");
    assert_eq!(row.status, VerifyStatus::Pass, "expected PASS, got: {row:?}");
}

#[test]
fn tampered_use_nonce_digest_fails_binding() {
    let real_nonce = "raw_nonce_zeta";
    let (g_id, g_env) = fake_grant_envelope(real_nonce);
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g_id.clone(), g_env));
    let mut tampered_use = make_use_with_nonce("use_real", &g_id, real_nonce);
    tampered_use.nonce_digest = nonce_digest("a_different_nonce");
    tampered_use.record_digest = approval_use_record_digest(&tampered_use);
    bundle.uses.push(tampered_use);

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-nonce-binding")
        .expect("approval-use-nonce-binding row required");
    assert_eq!(row.status, VerifyStatus::Fail, "expected FAIL on nonce mismatch, got: {row:?}");
    assert!(
        row.detail.contains("hashes to") || row.detail.contains("nonce_digest") || row.detail.contains("substituted"),
        "detail: {}",
        row.detail,
    );
}

#[test]
fn use_referencing_unknown_grant_fails_binding() {
    let mut bundle = ApprovalsBundle::default();
    bundle.uses.push(make_use_with_nonce("use_orphan", "g_missing", "n"));

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-nonce-binding")
        .expect("approval-use-nonce-binding row required");
    assert_eq!(row.status, VerifyStatus::Fail);
    assert!(row.detail.contains("no usable grant envelope"), "detail: {}", row.detail);
}

/// Round-2 hardening regression: an attacker substitutes a forged
/// grant envelope (different nonce) under the original grant_id
/// filename. The use record's nonce_digest claims to match the real
/// grant's nonce, but the envelope on disk no longer carries that
/// nonce. v0.9.10 PR A round 1 trusted the parsed envelope; round 2
/// rejects because the envelope's content-derived id no longer
/// matches its filename.
#[test]
fn forged_grant_envelope_under_real_id_fails_content_addressing() {
    let real_nonce = "raw_nonce_grant_real";
    let (real_g_id, _real_env) = fake_grant_envelope(real_nonce);
    let (_, forged_env) = fake_grant_envelope("a_completely_different_nonce");
    // Sanity: the forged envelope content does NOT derive to real_g_id.

    let mut bundle = ApprovalsBundle::default();
    // Ship the forged envelope under the real grant_id filename.
    bundle.grants.push((real_g_id.clone(), forged_env));
    bundle.uses.push(make_use_with_nonce("use_real", &real_g_id, real_nonce));

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-nonce-binding")
        .expect("approval-use-nonce-binding row required");
    assert_eq!(row.status, VerifyStatus::Fail, "expected FAIL on substituted grant envelope, got: {row:?}");
    assert!(
        row.detail.contains("substituted or tampered") || row.detail.contains("content derives"),
        "detail: {}",
        row.detail,
    );
}

// ---------------------------------------------------------------------------
// Fix 4 — embedded chain continuity (single connected linked list)
// ---------------------------------------------------------------------------

#[test]
fn embedded_chain_anchored_to_genesis_passes() {
    let nonce = "raw_nonce_eta";
    let (g_id, g_env) = fake_grant_envelope(nonce);
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g_id.clone(), g_env));
    bundle.uses.push(make_use_with_nonce("use_real", &g_id, nonce));

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();
    let row = find_check(&checks, "approval-use-chain-continuity")
        .expect("approval-use-chain-continuity row required");
    assert_eq!(row.status, VerifyStatus::Pass);
}

#[test]
fn dangling_previous_record_digest_fails_chain_continuity() {
    let nonce = "raw_nonce_theta";
    let (g_id, g_env) = fake_grant_envelope(nonce);
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g_id.clone(), g_env));
    let mut u = make_use_with_nonce("use_real", &g_id, nonce);
    u.previous_record_digest = "sha256:dangling_anchor_no_record_here".into();
    u.record_digest = approval_use_record_digest(&u);
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
    let (g1_id, g1_env) = fake_grant_envelope(nonce_a);
    let (g2_id, g2_env) = fake_grant_envelope(nonce_b);
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g1_id.clone(), g1_env));
    bundle.grants.push((g2_id.clone(), g2_env));

    let u1 = make_use_with_nonce("use_1", &g1_id, nonce_a);
    let u1_digest = u1.record_digest.clone();
    let mut u2 = make_use_with_nonce("use_2", &g2_id, nonce_b);
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

/// Round-2 hardening regression: two records both claim
/// `previous_record_digest == ""` (genesis). A real journal has
/// exactly one genesis record (the chronologically first); seeing
/// two means an attacker fabricated a second "first record" mid-chain
/// to launder a forged record into the linked list.
#[test]
fn multiple_genesis_records_fail_chain_continuity() {
    let nonce_a = "raw_nonce_genesis_a";
    let nonce_b = "raw_nonce_genesis_b";
    let (g1_id, g1_env) = fake_grant_envelope(nonce_a);
    let (g2_id, g2_env) = fake_grant_envelope(nonce_b);
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g1_id.clone(), g1_env));
    bundle.grants.push((g2_id.clone(), g2_env));

    // Both records have prev = "" -> two genesis claims.
    let mut u1 = make_use_with_nonce("use_1", &g1_id, nonce_a);
    u1.previous_record_digest = String::new();
    u1.record_digest = approval_use_record_digest(&u1);
    let mut u2 = make_use_with_nonce("use_2", &g2_id, nonce_b);
    u2.previous_record_digest = String::new();
    u2.record_digest = approval_use_record_digest(&u2);
    bundle.uses.push(u1);
    bundle.uses.push(u2);

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-chain-continuity")
        .expect("approval-use-chain-continuity row required");
    assert_eq!(row.status, VerifyStatus::Fail, "expected FAIL on multiple genesis, got: {row:?}");
    assert!(row.detail.contains("genesis"), "detail: {}", row.detail);
}

/// Round-2 hardening regression: two records share the same non-empty
/// `previous_record_digest`. That's a fork; an honest journal has
/// exactly one record per prev pointer.
#[test]
fn forked_chain_two_records_share_prev_fails_chain_continuity() {
    let nonce_a = "raw_nonce_fork_a";
    let nonce_b = "raw_nonce_fork_b";
    let nonce_c = "raw_nonce_fork_c";
    let (g_a, env_a) = fake_grant_envelope(nonce_a);
    let (g_b, env_b) = fake_grant_envelope(nonce_b);
    let (g_c, env_c) = fake_grant_envelope(nonce_c);
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g_a.clone(), env_a));
    bundle.grants.push((g_b.clone(), env_b));
    bundle.grants.push((g_c.clone(), env_c));

    // u1 is genesis; both u2 and u3 link back to u1 -> fork.
    let u1 = make_use_with_nonce("use_1", &g_a, nonce_a);
    let u1_digest = u1.record_digest.clone();
    let mut u2 = make_use_with_nonce("use_2", &g_b, nonce_b);
    u2.previous_record_digest = u1_digest.clone();
    u2.record_digest = approval_use_record_digest(&u2);
    let mut u3 = make_use_with_nonce("use_3", &g_c, nonce_c);
    u3.previous_record_digest = u1_digest;
    u3.record_digest = approval_use_record_digest(&u3);
    bundle.uses.push(u1);
    bundle.uses.push(u2);
    bundle.uses.push(u3);

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-chain-continuity")
        .expect("approval-use-chain-continuity row required");
    assert_eq!(row.status, VerifyStatus::Fail, "expected FAIL on fork, got: {row:?}");
    assert!(row.detail.contains("fork") || row.detail.contains("share previous_record_digest"),
        "detail: {}", row.detail);
}

/// Round-2 hardening regression: a disconnected subchain. Two
/// records form a linked list but neither links to genesis (both
/// have prev pointing at each other's record_digest -- a cycle). An
/// honest chain walks from genesis to tail with no cycles.
#[test]
fn disconnected_subchain_fails_chain_continuity() {
    let nonce_a = "raw_nonce_disconn_a";
    let nonce_b = "raw_nonce_disconn_b";
    let (g_a, env_a) = fake_grant_envelope(nonce_a);
    let (g_b, env_b) = fake_grant_envelope(nonce_b);
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g_a.clone(), env_a));
    bundle.grants.push((g_b.clone(), env_b));

    // u1's prev is u2's digest; u2's prev is u1's digest -> 2-cycle,
    // no genesis reachable.
    let mut u1 = make_use_with_nonce("use_1", &g_a, nonce_a);
    let mut u2 = make_use_with_nonce("use_2", &g_b, nonce_b);
    // First compute provisional digests, then point at each other.
    let u1_digest_v0 = u1.record_digest.clone();
    let u2_digest_v0 = u2.record_digest.clone();
    u1.previous_record_digest = u2_digest_v0;
    u1.record_digest = approval_use_record_digest(&u1);
    u2.previous_record_digest = u1_digest_v0;
    u2.record_digest = approval_use_record_digest(&u2);
    bundle.uses.push(u1);
    bundle.uses.push(u2);

    let pkg = build(bundle, &[]);
    let checks = verify_package(&pkg).unwrap();

    let row = find_check(&checks, "approval-use-chain-continuity")
        .expect("approval-use-chain-continuity row required");
    assert_eq!(row.status, VerifyStatus::Fail, "expected FAIL on disconnected/cyclic chain, got: {row:?}");
    // Expect any of "dangling", "disconnected", "cycle" depending on
    // which gate fires first; the chain is structurally broken
    // either way.
    assert!(
        row.detail.contains("not anchored")
            || row.detail.contains("disconnected")
            || row.detail.contains("cycle"),
        "detail: {}", row.detail,
    );
}

// ---------------------------------------------------------------------------
// Fix 5 — record-digest rename + label hygiene
// ---------------------------------------------------------------------------

#[test]
fn renamed_record_digest_row_emits_for_present_uses() {
    let nonce = "raw_nonce_kappa";
    let (g_id, g_env) = fake_grant_envelope(nonce);
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g_id.clone(), g_env));
    bundle.uses.push(make_use_with_nonce("use_real", &g_id, nonce));

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
    let nonce = "raw_nonce_lambda";
    let (g_id, g_env) = fake_grant_envelope(nonce);
    let (art_id, env) = fake_action_envelope(nonce, Some("use_real"));
    let mut bundle = ApprovalsBundle::default();
    bundle.grants.push((g_id.clone(), g_env));
    bundle.uses.push(make_use_with_nonce("use_real", &g_id, nonce));
    bundle.action_envelopes.push((art_id.clone(), env.clone()));

    let pkg = build(bundle, &[art_id.as_str()]);

    let read_back = read_approvals_bundle(&pkg).unwrap();
    assert_eq!(read_back.action_envelopes.len(), 1);
    assert_eq!(read_back.action_envelopes[0].0, art_id);
    assert_eq!(read_back.action_envelopes[0].1, env);
}
