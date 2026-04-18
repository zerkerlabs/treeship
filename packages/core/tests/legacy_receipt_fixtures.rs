//! Backwards compatibility regression suite (v0.9.0 item 9).
//!
//! Two flavors of pre-v0.9.0 receipt fixtures must continue to verify cleanly
//! under the current code:
//!
//! - **synthesized**: composed at test time, then mutated to drop the
//!   v0.9.0-only fields (`schema_version`, `session.ship_id`). Catches
//!   "the current code can't handle a missing optional field" regressions.
//! - **committed**: hand-curated JSON files in tests/fixtures/. Catches
//!   "we accidentally renamed a field via #[serde(rename)]" regressions
//!   that the synthesized variant would silently round-trip past.
//!
//! Both flavors are exercised for v0.7.2 and v0.8.0 schema eras. If a fixture
//! ever fails to verify, the breaking change must be documented in CHANGELOG.

use std::path::Path;

use treeship_core::session::{
    build_package, read_package, verify_package, ArtifactEntry, EventType,
    LifecycleMode, ReceiptComposer, SessionEvent, SessionManifest, SessionStatus,
    VerifyStatus,
};

// ============================================================================
// Synthesized legacy fixtures
// ============================================================================

fn make_legacy_events() -> Vec<SessionEvent> {
    let mk = |seq: u64, inst: &str, et: EventType| -> SessionEvent {
        SessionEvent {
            event_id: format!("ev_{seq}"),
            timestamp: format!("2026-04-15T08:00:{:02}Z", seq),
            sequence_no: seq,
            session_id: "ssn_legacy".into(),
            trace_id: "trace_legacy".into(),
            span_id: format!("span_{seq}"),
            parent_span_id: None,
            agent_id: format!("agent://{inst}"),
            agent_instance_id: inst.into(),
            agent_name: inst.into(),
            agent_role: None,
            host_id: "host_1".into(),
            tool_runtime_id: None,
            event_type: et,
            artifact_ref: None,
            meta: None,
        }
    };
    vec![
        mk(0, "root", EventType::SessionStarted),
        mk(1, "root", EventType::AgentStarted { parent_agent_instance_id: None }),
        mk(2, "root", EventType::AgentCalledTool {
            tool_name: "Bash".into(),
            tool_input_digest: None,
            tool_output_digest: None,
            duration_ms: Some(8),
        }),
        mk(3, "root", EventType::AgentCompleted { termination_reason: None }),
        mk(4, "root", EventType::SessionClosed { summary: Some("Done".into()), duration_ms: Some(120_000) }),
    ]
}

fn make_legacy_manifest() -> SessionManifest {
    // `agent://test` (not `ship://...`) so parse_ship_id_from_actor returns
    // None, mimicking the absent ship_id of pre-v0.9.0 receipts even when
    // the composer runs current code.
    let mut m = SessionManifest::new(
        "ssn_legacy".into(),
        "agent://test".into(),
        "2026-04-15T08:00:00Z".into(),
        1_744_704_000_000,
    );
    m.mode = LifecycleMode::Manual;
    m.status = SessionStatus::Completed;
    m
}

/// Compose a receipt the way pre-v0.9.0 code would have, then strip the
/// v0.9.0-only fields and write it to disk as a `.treeship` package.
fn build_synthesized_legacy_package(tmp: &Path) -> std::path::PathBuf {
    let manifest = make_legacy_manifest();
    let events = make_legacy_events();
    let artifacts = vec![
        ArtifactEntry { artifact_id: "art_001".into(), payload_type: "action".into(), digest: None, signed_at: None },
        ArtifactEntry { artifact_id: "art_002".into(), payload_type: "action".into(), digest: None, signed_at: None },
    ];
    let mut receipt = ReceiptComposer::compose(&manifest, &events, artifacts);
    // Mimic pre-v0.9.0: strip the new optional fields.
    receipt.schema_version = None;
    receipt.session.ship_id = None;

    let output = build_package(&receipt, tmp).expect("build legacy package");
    output.path
}

/// One-shot helper to regenerate the committed fixtures. Invoke with:
///   cargo test -p treeship-core --test legacy_receipt_fixtures -- --ignored print_legacy_receipt_json
/// then copy the output into tests/fixtures/v0_8_0_receipt.json.
#[test]
#[ignore]
fn print_legacy_receipt_json() {
    let manifest = make_legacy_manifest();
    let events = make_legacy_events();
    let artifacts = vec![
        ArtifactEntry { artifact_id: "art_001".into(), payload_type: "action".into(), digest: None, signed_at: None },
        ArtifactEntry { artifact_id: "art_002".into(), payload_type: "action".into(), digest: None, signed_at: None },
    ];
    let mut receipt = ReceiptComposer::compose(&manifest, &events, artifacts);
    receipt.schema_version = None;
    receipt.session.ship_id = None;
    println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
}

#[test]
fn synthesized_legacy_receipt_verifies_under_current_code() {
    let tmp = std::env::temp_dir().join(format!(
        "treeship-legacy-syn-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);

    let pkg = build_synthesized_legacy_package(&tmp);

    // Sanity: the on-disk receipt.json must NOT contain the v0.9.0 fields.
    let receipt_bytes = std::fs::read(pkg.join("receipt.json")).unwrap();
    let receipt_str = std::str::from_utf8(&receipt_bytes).unwrap();
    assert!(!receipt_str.contains("schema_version"),
        "synthesized legacy fixture must omit schema_version");
    assert!(!receipt_str.contains(r#""ship_id""#),
        "synthesized legacy fixture must omit ship_id");

    // Re-parse and confirm both fields are None.
    let parsed = read_package(&pkg).expect("read legacy package");
    assert!(parsed.schema_version.is_none(), "legacy receipts parse with schema_version=None");
    assert!(parsed.session.ship_id.is_none(), "legacy receipts parse with ship_id=None");

    // Run the full verifier.
    let checks = verify_package(&pkg).expect("verify legacy package");
    let fails: Vec<_> = checks.iter().filter(|c| c.status == VerifyStatus::Fail).collect();
    assert!(
        fails.is_empty(),
        "legacy receipt must verify under current code, but these checks failed: {:#?}",
        fails
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

// ============================================================================
// Committed JSON fixtures
// ============================================================================

const V0_7_2_FIXTURE: &str = include_str!("fixtures/v0_7_2_receipt.json");
const V0_8_0_FIXTURE: &str = include_str!("fixtures/v0_8_0_receipt.json");

fn copy_fixture_to_package(receipt_json: &str, tmp: &Path) -> std::path::PathBuf {
    let pkg = tmp.join("legacy.treeship");
    std::fs::create_dir_all(&pkg).unwrap();
    std::fs::write(pkg.join("receipt.json"), receipt_json).unwrap();
    pkg
}

#[test]
fn committed_v0_7_2_fixture_parses_and_omits_v0_9_fields() {
    let receipt: treeship_core::session::SessionReceipt =
        serde_json::from_str(V0_7_2_FIXTURE).expect("v0.7.2 fixture must parse");
    assert!(receipt.schema_version.is_none(), "v0.7.2 fixture must lack schema_version");
    assert!(receipt.session.ship_id.is_none(), "v0.7.2 fixture must lack ship_id");
    // Sanity: committed JSON does not literally contain those keys.
    assert!(!V0_7_2_FIXTURE.contains("schema_version"));
    assert!(!V0_7_2_FIXTURE.contains(r#""ship_id""#));
}

#[test]
fn committed_v0_8_0_fixture_parses_and_omits_v0_9_fields() {
    let receipt: treeship_core::session::SessionReceipt =
        serde_json::from_str(V0_8_0_FIXTURE).expect("v0.8.0 fixture must parse");
    assert!(receipt.schema_version.is_none());
    assert!(receipt.session.ship_id.is_none());
    assert!(!V0_8_0_FIXTURE.contains("schema_version"));
    assert!(!V0_8_0_FIXTURE.contains(r#""ship_id""#));
}

#[test]
fn committed_v0_7_2_fixture_passes_package_verification() {
    let tmp = std::env::temp_dir().join(format!("treeship-legacy-072-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let pkg = copy_fixture_to_package(V0_7_2_FIXTURE, &tmp);
    let checks = verify_package(&pkg).expect("verify v0.7.2 fixture");
    let fails: Vec<_> = checks.iter().filter(|c| c.status == VerifyStatus::Fail).collect();
    assert!(fails.is_empty(), "v0.7.2 fixture must verify cleanly: {:#?}", fails);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn committed_v0_8_0_fixture_passes_package_verification() {
    let tmp = std::env::temp_dir().join(format!("treeship-legacy-080-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let pkg = copy_fixture_to_package(V0_8_0_FIXTURE, &tmp);
    let checks = verify_package(&pkg).expect("verify v0.8.0 fixture");
    let fails: Vec<_> = checks.iter().filter(|c| c.status == VerifyStatus::Fail).collect();
    assert!(fails.is_empty(), "v0.8.0 fixture must verify cleanly: {:#?}", fails);
    let _ = std::fs::remove_dir_all(&tmp);
}
