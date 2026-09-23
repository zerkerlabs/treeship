//! TS-2026-003: a session package carries its Rekor proofs under
//! `anchors/`, and `package verify` checks them offline.
//!
//! The artifact here is the Treeship-format envelope that the fixed hub
//! anchored in Sigstore's staging Rekor (`tests/fixtures/rekor/`, provenance
//! in the file), so the proof being checked is Rekor's own output, not
//! something this crate produced.

use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use treeship_core::attestation::{artifact_id_from_pae, digest_from_pae, pae, Envelope};
use treeship_core::session::{
    build_package_with_approvals,
    manifest::SessionManifest,
    receipt::{ArtifactEntry, ReceiptComposer},
    verify_package_with_options, ApprovalsBundle, VerifyCheck, VerifyStatus,
};
use treeship_core::storage::RecordAnchor;
use treeship_core::trust::{TrustRoot, TrustRootKind, TrustRootStore};

/// Staging Rekor's key, from https://rekor.sigstage.dev/api/v1/log/publicKey.
const STAGING_KEY_B64: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDODRU688UYGuy54mNUlaEBiQdTE9nYLr0lg6RXowI/QV/RE1azBn4Eg5/2uTOMbhB1/gfcHzijzFi9Tk+g1Prg==";

fn staging() -> (Envelope, serde_json::Value) {
    let f: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/rekor/staging-dsse.json")).unwrap();
    (serde_json::from_value(f["envelope"].clone()).unwrap(), f["entry"].clone())
}

fn public_good_entry() -> serde_json::Value {
    let f: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/rekor/public-good-dsse.json")).unwrap();
    f["entry"].clone()
}

fn trust_staging() -> TrustRootStore {
    use base64::engine::general_purpose::STANDARD;
    let der = STANDARD.decode(STAGING_KEY_B64).unwrap();
    TrustRootStore::with_roots(vec![TrustRoot {
        key_id: "rekor-staging".into(),
        public_key: format!("ecdsa-p256:{}", URL_SAFE_NO_PAD.encode(der)),
        kind: TrustRootKind::TransparencyLog,
        label: String::new(),
        added_at: String::new(),
    }])
}

fn anchor(proof: serde_json::Value) -> RecordAnchor {
    RecordAnchor {
        mechanism: "rekor".into(),
        observed_at: "2026-09-24T00:08:48Z".into(),
        reference: None,
        status: Some("anchored".into()),
        reason: None,
        proof: Some(proof),
    }
}

/// A one-artifact package around the staging envelope, with `anchors`.
fn build(dir: &Path, anchors: Vec<RecordAnchor>) -> (PathBuf, String) {
    let (env, _) = staging();
    let payload = env.payload_bytes().unwrap();
    let signed = pae(&env.payload_type, &payload);
    let id = artifact_id_from_pae(&signed);
    let entry = ArtifactEntry {
        artifact_id: id.clone(),
        payload_type: env.payload_type.clone(),
        digest: Some(digest_from_pae(&signed)),
        signed_at: Some("2026-09-24T00:00:00Z".into()),
        unchained: false,
    };
    let manifest = SessionManifest::new(
        "ssn_anchortest".into(),
        "agent://t".into(),
        "2026-09-24T00:00:00Z".into(),
        1790208000000,
    );
    let receipt = ReceiptComposer::compose(&manifest, &[], vec![entry]);
    let bundle = ApprovalsBundle {
        sealed_envelopes: vec![(id.clone(), env.to_json().unwrap())],
        sealed_anchors: if anchors.is_empty() {
            vec![]
        } else {
            vec![(id.clone(), anchors)]
        },
        ..ApprovalsBundle::default()
    };
    let out = build_package_with_approvals(&receipt, dir, Some(&bundle)).unwrap();
    (out.path, id)
}

fn row(checks: &[VerifyCheck]) -> Option<&VerifyCheck> {
    checks.iter().find(|c| c.name == "anchoring")
}

#[test]
fn verified_proof_passes_with_rekor_time() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, entry) = staging();
    let (pkg, _) = build(tmp.path(), vec![anchor(entry)]);
    assert!(pkg.join("anchors").is_dir());
    let checks = verify_package_with_options(&pkg, &trust_staging(), false).unwrap();
    let r = row(&checks).expect("anchoring row");
    assert_eq!(r.status, VerifyStatus::Pass, "{}", r.detail);
    assert!(r.detail.contains("1 of 1"), "{}", r.detail);
}

/// Without the staging log pinned, the built-in public-good key does not
/// know it: a warning that names the log, never a pass.
#[test]
fn proof_from_an_unpinned_log_warns() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, entry) = staging();
    let (pkg, _) = build(tmp.path(), vec![anchor(entry)]);
    let checks = verify_package_with_options(&pkg, &TrustRootStore::empty(), false).unwrap();
    let r = row(&checks).expect("anchoring row");
    assert_eq!(r.status, VerifyStatus::Warn, "{}", r.detail);
    assert!(r.detail.contains("does not trust"), "{}", r.detail);
}

/// A genuine production Rekor entry stapled onto this artifact. The log is
/// trusted (built in), the entry is real, and it is for other bytes.
#[test]
fn real_proof_for_other_bytes_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let (pkg, _) = build(tmp.path(), vec![anchor(public_good_entry())]);
    let checks = verify_package_with_options(&pkg, &TrustRootStore::empty(), false).unwrap();
    let r = row(&checks).expect("anchoring row");
    assert_eq!(r.status, VerifyStatus::Fail, "{}", r.detail);
    assert!(r.detail.contains("not for this artifact"), "{}", r.detail);
}

/// An edited integrated time inside the stapled entry breaks Rekor's
/// signature over it.
#[test]
fn edited_proof_time_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, mut entry) = staging();
    let t = entry["integratedTime"].as_i64().unwrap();
    entry["integratedTime"] = serde_json::json!(t - 86_400);
    let (pkg, _) = build(tmp.path(), vec![anchor(entry)]);
    let checks = verify_package_with_options(&pkg, &trust_staging(), false).unwrap();
    assert_eq!(row(&checks).expect("anchoring row").status, VerifyStatus::Fail);
}

/// A package with no proofs gets no row: every existing verdict, including
/// under --strict, is unchanged.
#[test]
fn no_anchors_means_no_row() {
    let tmp = tempfile::tempdir().unwrap();
    let (pkg, _) = build(tmp.path(), vec![]);
    assert!(!pkg.join("anchors").exists());
    let checks = verify_package_with_options(&pkg, &trust_staging(), false).unwrap();
    assert!(row(&checks).is_none());
}

/// A bare local claim is never written into a package.
#[test]
fn claims_without_proof_are_not_packaged() {
    let tmp = tempfile::tempdir().unwrap();
    let mut claim = anchor(serde_json::Value::Null);
    claim.proof = None;
    let (pkg, _) = build(tmp.path(), vec![claim]);
    assert!(!pkg.join("anchors").exists());
}
