//! The content layer: the bytes behind a digest, and what `package verify`
//! says about them.
//!
//! The claim under test is narrow and load-bearing. A blob is part of a trace
//! because a signed statement names its digest and because the file is named
//! by the hash of its own contents -- nothing else. So content can be attached
//! after sealing and dropped before sharing without moving the verdict, while
//! substituted bytes and bytes the trace never mentioned both fail.

use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use treeship_core::attestation::{sign, Ed25519Signer, Signer};
use treeship_core::session::content;
use treeship_core::session::{
    build_package_with_approvals, event::SessionEvent, manifest::SessionManifest,
    package::signed_digests, read_package, receipt::ArtifactEntry, receipt::ReceiptComposer,
    verify_package_with_options, ApprovalsBundle, PackageVerdict, VerifyCheck, VerifyStatus,
};
use treeship_core::statements::{payload_type, ActionStatement};
use treeship_core::trust::{TrustRoot, TrustRootKind, TrustRootStore};

/// The response body the trace commits to by digest. The point of the layer
/// is that a reader can open exactly these bytes and nothing else.
const BODY: &[u8] = br#"{"temperature_2m":14.3,"weather_code":0}"#;

struct Signed {
    id: String,
    digest: String,
    envelope: Vec<u8>,
    signed_at: String,
}

fn finish(stmt: &ActionStatement, signer: &Ed25519Signer) -> Signed {
    let r = sign(&payload_type("action"), stmt, signer).unwrap();
    Signed {
        id: r.artifact_id.clone(),
        digest: r.digest.clone(),
        envelope: r.envelope.to_json().unwrap(),
        signed_at: stmt.timestamp.clone(),
    }
}

fn sign_start(signer: &Ed25519Signer) -> Signed {
    let mut stmt = ActionStatement::new("agent://t", "session.start");
    stmt.meta = Some(serde_json::json!({"session_start": true, "session_id": "ssn_content"}));
    finish(&stmt, signer)
}

/// The step that fetched something: its output is in the signed statement as
/// a digest, which is the only reason bytes may later be filed under it.
fn sign_fetch(signer: &Ed25519Signer, parent: &str, body: &[u8]) -> Signed {
    let mut stmt = ActionStatement::new("agent://t", "http.get");
    stmt.parent_id = Some(parent.to_string());
    stmt.meta = Some(serde_json::json!({
        "url": "https://api.open-meteo.com/v1/forecast",
        "output_digest": content::digest_bytes(body),
    }));
    finish(&stmt, signer)
}

fn sign_close(signer: &Ed25519Signer, parent: &str) -> Signed {
    let mut stmt = ActionStatement::new("agent://t", "session.close");
    stmt.parent_id = Some(parent.to_string());
    stmt.meta = Some(serde_json::json!({"session_close": true, "session_id": "ssn_content"}));
    finish(&stmt, signer)
}

fn entry(s: &Signed) -> ArtifactEntry {
    ArtifactEntry {
        artifact_id: s.id.clone(),
        payload_type: payload_type("action"),
        digest: Some(s.digest.clone()),
        signed_at: Some(s.signed_at.clone()),
        unchained: false,
    }
}

fn seal_record(pkg: &Path, signer: &Ed25519Signer) {
    use treeship_core::statements::ReceiptStatement;
    let receipt = std::fs::read(pkg.join("receipt.json")).unwrap();
    let close: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pkg.join("receipt.json")).unwrap()).unwrap();
    let close_id = close["artifacts"].as_array().unwrap().last().unwrap()["artifact_id"]
        .as_str()
        .unwrap()
        .to_string();
    let mut stmt = ReceiptStatement::new("system://treeship-session", "session.v1");
    stmt.subject = Some(treeship_core::statements::SubjectRef {
        artifact_id: Some(close_id),
        ..Default::default()
    });
    stmt.payload = Some(serde_json::json!({
        "receipt_digest": format!("sha256:{}", hex::encode(Sha256::digest(&receipt))),
        "session_id": "ssn_content",
    }));
    let r = sign(&payload_type("receipt"), &stmt, signer).unwrap();
    std::fs::write(pkg.join("record.json"), r.envelope.to_json().unwrap()).unwrap();
}

/// A sealed, record-signed package whose `http.get` step commits to `BODY`.
/// No content is attached: that is the state every package shipped in before
/// this layer existed.
fn build(dir: &Path, signer: &Ed25519Signer) -> PathBuf {
    let root = sign_start(signer);
    let fetch = sign_fetch(signer, &root.id, BODY);
    let close = sign_close(signer, &fetch.id);
    let arts = [root, fetch, close];
    let entries: Vec<ArtifactEntry> = arts.iter().map(entry).collect();
    let events: Vec<SessionEvent> = vec![];
    let manifest = SessionManifest::new(
        "ssn_content".into(),
        "agent://t".into(),
        "2026-10-26T00:00:00Z".into(),
        1793404800000,
    );
    let receipt = ReceiptComposer::compose(&manifest, &events, entries);
    let bundle = ApprovalsBundle {
        sealed_envelopes: arts
            .iter()
            .map(|s| (s.id.clone(), s.envelope.clone()))
            .collect(),
        signer_keys: vec![(
            signer.key_id().to_string(),
            format!(
                "ed25519:{}",
                URL_SAFE_NO_PAD.encode(signer.public_key_bytes())
            ),
        )],
        ..ApprovalsBundle::default()
    };
    let out = build_package_with_approvals(&receipt, dir, Some(&bundle)).unwrap();
    seal_record(&out.path, signer);
    out.path
}

/// Trust the signer, so the verdict can reach `verified` and a content
/// failure is visibly the thing that moved it.
fn trusting(signer: &Ed25519Signer) -> TrustRootStore {
    TrustRootStore::with_roots(vec![TrustRoot {
        key_id: signer.key_id().into(),
        public_key: format!(
            "ed25519:{}",
            URL_SAFE_NO_PAD.encode(signer.public_key_bytes())
        ),
        kind: TrustRootKind::CertIssuer,
        agent: None,
        label: "producer".into(),
        added_at: "2026-10-26T00:00:00Z".into(),
    }])
}

fn verify(pkg: &Path, store: &TrustRootStore) -> (Vec<VerifyCheck>, PackageVerdict) {
    let checks = verify_package_with_options(pkg, store, false).unwrap();
    let verdict = treeship_core::session::package_verdict(&checks, false);
    (checks, verdict)
}

fn row<'a>(checks: &'a [VerifyCheck], name: &str) -> Option<&'a VerifyCheck> {
    checks.iter().find(|c| c.name == name)
}

/// Attach `bytes` the way the CLI does: only when the trace already names
/// their digest.
fn attach(pkg: &Path, bytes: &[u8]) -> String {
    let receipt = read_package(pkg).unwrap();
    let named: std::collections::BTreeSet<String> =
        signed_digests(pkg, &receipt).into_keys().collect();
    content::write_blob(pkg, bytes, &named).unwrap()
}

#[test]
fn a_package_with_no_content_has_no_content_row() {
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let pkg = build(tmp.path(), &signer);

    let (checks, verdict) = verify(&pkg, &trusting(&signer));
    assert_eq!(verdict, PackageVerdict::Verified);
    assert!(
        row(&checks, "content").is_none(),
        "a package that never opted into content should not be told it is missing some"
    );
}

#[test]
fn the_digest_in_the_signed_statement_is_what_makes_content_attachable() {
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let pkg = build(tmp.path(), &signer);
    let receipt = read_package(&pkg).unwrap();

    let named = signed_digests(&pkg, &receipt);
    let want = content::normalize_digest(&content::digest_bytes(BODY)).unwrap();
    let refs = named
        .get(&want)
        .expect("the fetch step's output digest should be collected");
    assert_eq!(refs.len(), 1);
    let r = refs.iter().next().unwrap();
    assert_eq!(r.field, "meta.output_digest");

    // Bytes the trace does not mention cannot be filed, whatever they are.
    let others: std::collections::BTreeSet<String> = named.into_keys().collect();
    assert!(matches!(
        content::write_blob(&pkg, b"a body nobody signed", &others),
        Err(content::ContentError::Unreferenced(_))
    ));
}

#[test]
fn attached_content_verifies_and_can_be_opened_byte_for_byte() {
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let pkg = build(tmp.path(), &signer);
    let digest = attach(&pkg, BODY);

    let (checks, verdict) = verify(&pkg, &trusting(&signer));
    let content_row = row(&checks, "content").expect("a content row");
    assert_eq!(
        content_row.status,
        VerifyStatus::Pass,
        "{}",
        content_row.detail
    );
    assert!(
        content_row.detail.contains("1 of 1 digest"),
        "the row should say how much of what the trace commits to is openable: {}",
        content_row.detail
    );
    assert_eq!(verdict, PackageVerdict::Verified);

    // The bytes come back exactly, and the digest in the signed statement is
    // what a reader checks them against.
    assert_eq!(content::read_blob(&pkg, &digest).unwrap(), BODY);
    assert_eq!(content::digest_bytes(BODY), digest);
}

#[test]
fn substituted_content_fails_even_though_every_signature_still_holds() {
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let pkg = build(tmp.path(), &signer);
    let digest = attach(&pkg, BODY);
    let hex_digest = content::normalize_digest(&digest).unwrap();

    // Swap the body, keep the name. Nothing in the sealed set is touched, so
    // the signatures and the Merkle root are untouched too -- the only thing
    // that catches this is recomputing the hash of the file.
    std::fs::write(
        pkg.join("content").join(&hex_digest),
        br#"{"temperature_2m":31.0,"weather_code":0}"#,
    )
    .unwrap();

    let (checks, verdict) = verify(&pkg, &trusting(&signer));
    let content_row = row(&checks, "content").expect("a content row");
    assert_eq!(content_row.status, VerifyStatus::Fail);
    assert!(
        content_row.detail.contains("substituted"),
        "{}",
        content_row.detail
    );
    assert!(matches!(verdict, PackageVerdict::Failed(_)));
    // The signatures are not what broke, and the row names the right thing.
    assert!(checks
        .iter()
        .any(|c| c.name.starts_with("signature:") && c.status == VerifyStatus::Pass));

    // A reader asking for those bytes is refused rather than handed them.
    assert!(matches!(
        content::read_blob(&pkg, &digest),
        Err(content::ContentError::DigestMismatch { .. })
    ));
}

#[test]
fn content_no_signed_statement_names_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let pkg = build(tmp.path(), &signer);
    attach(&pkg, BODY);

    // Correctly named -- the file does hash to its own name -- but the trace
    // never commits to it. Bytes inside a package read as part of it, so an
    // attachment the trace does not account for is a failure, not a note.
    let extra = b"an invoice the trace never mentioned";
    let extra_hex = hex::encode(Sha256::digest(extra));
    std::fs::write(pkg.join("content").join(&extra_hex), extra).unwrap();

    let (checks, verdict) = verify(&pkg, &trusting(&signer));
    let content_row = row(&checks, "content").expect("a content row");
    assert_eq!(content_row.status, VerifyStatus::Fail);
    assert!(
        content_row.detail.contains("named by no signed statement"),
        "{}",
        content_row.detail
    );
    assert!(matches!(verdict, PackageVerdict::Failed(_)));
}

#[test]
fn a_file_in_content_that_is_not_a_blob_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let pkg = build(tmp.path(), &signer);
    attach(&pkg, BODY);
    std::fs::write(pkg.join("content").join("response.json"), BODY).unwrap();

    let (checks, _) = verify(&pkg, &trusting(&signer));
    let content_row = row(&checks, "content").expect("a content row");
    assert_eq!(content_row.status, VerifyStatus::Fail);
    assert!(
        content_row.detail.contains("response.json"),
        "{}",
        content_row.detail
    );
}

#[test]
fn dropping_content_leaves_the_package_verified() {
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let pkg = build(tmp.path(), &signer);
    let digest = attach(&pkg, BODY);

    assert!(content::remove_blob(&pkg, &digest).unwrap());

    // This is the property that makes disclosure an operation rather than a
    // promise: the bytes are gone, the commitment to them is not, and the
    // verdict does not move.
    let (checks, verdict) = verify(&pkg, &trusting(&signer));
    assert_eq!(verdict, PackageVerdict::Verified);
    let content_row = row(&checks, "content").expect("an empty content dir still reports");
    assert_eq!(content_row.status, VerifyStatus::Pass);
    assert!(
        content_row.detail.contains("0 of 1 digest"),
        "the row should say the trace commits to more than it carries: {}",
        content_row.detail
    );
}

#[test]
fn attaching_content_after_sealing_changes_no_signature() {
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let pkg = build(tmp.path(), &signer);

    let before = verify_package_with_options(&pkg, &trusting(&signer), false).unwrap();
    attach(&pkg, BODY);
    let after = verify_package_with_options(&pkg, &trusting(&signer), false).unwrap();

    // Every row that existed before says the same thing after. The content
    // row is the only addition, because the bytes are bound by their hash
    // and not by anything the sealed set would have to be re-signed over.
    for b in &before {
        let a = row(&after, &b.name).unwrap_or_else(|| panic!("row {} should survive", b.name));
        assert_eq!(a.status, b.status, "row {} changed status", b.name);
        assert_eq!(a.detail, b.detail, "row {} changed detail", b.name);
    }
    assert_eq!(after.len(), before.len() + 1);
    assert!(row(&before, "content").is_none());
    assert!(row(&after, "content").is_some());
}
