//! Audit 2026-09, AUD-31 / AUD-32 and QA TS-002b: `package verify` checks
//! signatures, id re-derivation, chain linkage and signer trust from the
//! package's own envelopes, and a fabricated or edited artifact fails.

use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use treeship_core::attestation::{sign, Ed25519Signer, Signer};
use treeship_core::session::{
    build_package_with_approvals,
    event::SessionEvent,
    manifest::SessionManifest,
    receipt::{ArtifactEntry, ReceiptComposer},
    verify_package_structural, verify_package_with_options, ApprovalsBundle, VerifyCheck,
    VerifyStatus,
};
use treeship_core::statements::{payload_type, ActionStatement};
use treeship_core::trust::{TrustRoot, TrustRootKind, TrustRootStore};

struct Signed {
    id: String,
    digest: String,
    envelope: Vec<u8>,
    signed_at: String,
}

fn sign_action(signer: &Ed25519Signer, action: &str, parent: Option<&str>) -> Signed {
    let mut stmt = ActionStatement::new("agent://t", action);
    stmt.parent_id = parent.map(str::to_string);
    let r = sign(&payload_type("action"), &stmt, signer).unwrap();
    Signed {
        id: r.artifact_id.clone(),
        digest: r.digest.clone(),
        envelope: r.envelope.to_json().unwrap(),
        signed_at: stmt.timestamp.clone(),
    }
}

/// The `session.close` action `session close` signs: chained, naming the
/// session, and naming the record key when an agent's own key will sign
/// the record.
fn sign_close(signer: &Ed25519Signer, parent: &str, record_key: Option<&Ed25519Signer>) -> Signed {
    let mut stmt = ActionStatement::new("agent://t", "session.close");
    stmt.parent_id = Some(parent.to_string());
    let mut meta = serde_json::json!({"session_close": true, "session_id": "ssn_sigtest"});
    if let Some(k) = record_key {
        meta["record_key"] = serde_json::json!({
            "key_id": k.key_id(),
            "public_key": format!("ed25519:{}", URL_SAFE_NO_PAD.encode(k.public_key_bytes())),
        });
    }
    stmt.meta = Some(meta);
    let r = sign(&payload_type("action"), &stmt, signer).unwrap();
    Signed {
        id: r.artifact_id.clone(),
        digest: r.digest.clone(),
        envelope: r.envelope.to_json().unwrap(),
        signed_at: stmt.timestamp.clone(),
    }
}

fn entry(s: &Signed, unchained: bool) -> ArtifactEntry {
    ArtifactEntry {
        artifact_id: s.id.clone(),
        payload_type: payload_type("action"),
        digest: Some(s.digest.clone()),
        signed_at: Some(s.signed_at.clone()),
        unchained,
    }
}

fn manifest() -> SessionManifest {
    SessionManifest::new(
        "ssn_sigtest".into(),
        "agent://t".into(),
        "2026-09-09T00:00:00Z".into(),
        1788912000000,
    )
}

/// A package from real signed envelopes: root <- a <- b <- close, plus one
/// unchained (listed before the close; the close is always last).
fn build(dir: &Path, signer: &Ed25519Signer) -> (PathBuf, Vec<Signed>) {
    build_with(dir, signer, None, None)
}

/// `build`, with the close naming `record_key`, and an artifact signed by
/// `extra` chained after b, before the close.
fn build_with(
    dir: &Path,
    signer: &Ed25519Signer,
    record_key: Option<&Ed25519Signer>,
    extra: Option<&Ed25519Signer>,
) -> (PathBuf, Vec<Signed>) {
    let root = sign_action(signer, "session.start", None);
    let a = sign_action(signer, "step.a", Some(&root.id));
    let b = sign_action(signer, "step.b", Some(&a.id));
    let loose = sign_action(signer, "step.loose", None);
    let mut arts = vec![root, a, b, loose];
    let mut entries = vec![
        entry(&arts[0], false),
        entry(&arts[1], false),
        entry(&arts[2], false),
        entry(&arts[3], true),
    ];
    let mut head = arts[2].id.clone();
    if let Some(x) = extra {
        let injected = sign_action(x, "step.injected", Some(&head));
        head = injected.id.clone();
        entries.push(entry(&injected, false));
        arts.push(injected);
    }
    let close = sign_close(signer, &head, record_key);
    entries.push(entry(&close, false));
    arts.push(close);
    let mut signer_keys = vec![(
        signer.key_id().to_string(),
        format!(
            "ed25519:{}",
            URL_SAFE_NO_PAD.encode(signer.public_key_bytes())
        ),
    )];
    for k in [record_key, extra].into_iter().flatten() {
        signer_keys.push((
            k.key_id().to_string(),
            format!("ed25519:{}", URL_SAFE_NO_PAD.encode(k.public_key_bytes())),
        ));
    }
    let events: Vec<SessionEvent> = vec![];
    let receipt = ReceiptComposer::compose(&manifest(), &events, entries);
    let bundle = ApprovalsBundle {
        sealed_envelopes: arts
            .iter()
            .map(|s| (s.id.clone(), s.envelope.clone()))
            .collect(),
        signer_keys,
        ..ApprovalsBundle::default()
    };
    let out = build_package_with_approvals(&receipt, dir, Some(&bundle)).unwrap();
    (out.path, arts)
}

/// The sealed session.close's id: the last artifact the receipt lists.
fn close_id(pkg: &Path) -> String {
    let receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pkg.join("receipt.json")).unwrap()).unwrap();
    receipt["artifacts"].as_array().unwrap().last().unwrap()["artifact_id"]
        .as_str()
        .unwrap()
        .to_string()
}

/// What `session close` does after building the package: sign a
/// `session.v1` record over the SHA-256 of receipt.json and the session id,
/// and write it as record.json (0.31.4+).
fn seal_record(pkg: &Path, signer: &Ed25519Signer) {
    use sha2::{Digest, Sha256};
    use treeship_core::statements::ReceiptStatement;
    let receipt = std::fs::read(pkg.join("receipt.json")).unwrap();
    let mut stmt = ReceiptStatement::new("system://treeship-session", "session.v1");
    stmt.subject = Some(treeship_core::statements::SubjectRef {
        artifact_id: Some(close_id(pkg)),
        ..Default::default()
    });
    stmt.payload = Some(serde_json::json!({
        "receipt_digest": format!("sha256:{}", hex::encode(Sha256::digest(&receipt))),
        "session_id": "ssn_sigtest",
    }));
    let r = sign(&payload_type("receipt"), &stmt, signer).unwrap();
    std::fs::write(pkg.join("record.json"), r.envelope.to_json().unwrap()).unwrap();
}

fn find<'a>(checks: &'a [VerifyCheck], name: &str) -> Option<&'a VerifyCheck> {
    checks.iter().find(|c| c.name == name)
}

fn fails(checks: &[VerifyCheck]) -> Vec<String> {
    checks
        .iter()
        .filter(|c| c.status == VerifyStatus::Fail)
        .map(|c| format!("{}: {}", c.name, c.detail))
        .collect()
}

#[test]
fn a_genuine_package_verifies_every_signature_and_the_chain() {
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let (pkg, arts) = build(tmp.path(), &signer);
    seal_record(&pkg, &signer);
    assert!(pkg.join("keys.json").exists());
    for a in &arts {
        assert!(pkg
            .join("artifacts")
            .join(format!("{}.json", a.id))
            .exists());
    }
    let checks = verify_package_with_options(&pkg, &TrustRootStore::empty(), false).unwrap();
    assert!(fails(&checks).is_empty(), "{:?}", fails(&checks));
    for a in &arts {
        assert_eq!(
            find(&checks, &format!("signature:{}", a.id))
                .unwrap()
                .status,
            VerifyStatus::Pass
        );
    }
    assert_eq!(
        find(&checks, "chain_linkage").unwrap().status,
        VerifyStatus::Pass
    );
    let comp = find(&checks, "chain_completeness").unwrap();
    assert_eq!(comp.status, VerifyStatus::Warn);
    assert!(comp.detail.contains(&arts[3].id));
    // The key is real but not pinned here: a warning, not a pass.
    let trust = find(&checks, "signer_trust").unwrap();
    assert_eq!(trust.status, VerifyStatus::Warn);
    assert!(trust.detail.contains("treeship trust add key_t"));

    // Pin it and the trust row passes.
    let pinned = TrustRootStore::with_roots(vec![TrustRoot {
        key_id: "key_t".into(),
        public_key: format!(
            "ed25519:{}",
            URL_SAFE_NO_PAD.encode(signer.public_key_bytes())
        ),
        kind: TrustRootKind::CertIssuer,
        label: "test".into(),
        added_at: "2026-09-09T00:00:00Z".into(),
    }]);
    let checks = verify_package_with_options(&pkg, &pinned, false).unwrap();
    assert_eq!(
        find(&checks, "signer_trust").unwrap().status,
        VerifyStatus::Pass
    );
}

#[test]
fn a_fabricated_artifact_in_the_sealed_set_fails() {
    // The auditor's PoC: replace a sealed id with an invented one and rebuild
    // the Merkle tree so every structural check still passes.
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let (pkg, arts) = build(tmp.path(), &signer);
    let evil = "art_ev11wire1000000usd0000000000000";
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pkg.join("receipt.json")).unwrap()).unwrap();
    receipt["artifacts"][1]["artifact_id"] = serde_json::Value::String(evil.into());
    receipt["artifacts"][1]["digest"] =
        serde_json::Value::String(format!("sha256:{}", "ab".repeat(32)));
    let ids: Vec<String> = receipt["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["artifact_id"].as_str().unwrap().to_string())
        .collect();
    let mut tree = treeship_core::merkle::MerkleTree::new();
    for id in &ids {
        tree.append(id);
    }
    let root = format!("mroot_{}", hex::encode(tree.root().unwrap()));
    let proofs: Vec<serde_json::Value> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| serde_json::json!({"artifact_id": id, "leaf_index": i, "proof": tree.inclusion_proof(i).unwrap()}))
        .collect();
    receipt["merkle"]["root"] = serde_json::Value::String(root.clone());
    receipt["merkle"]["inclusion_proofs"] = serde_json::Value::Array(proofs.clone());
    std::fs::write(
        pkg.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    std::fs::write(
        pkg.join("merkle.json"),
        serde_json::to_vec_pretty(&receipt["merkle"]).unwrap(),
    )
    .unwrap();
    let _ = std::fs::remove_file(
        pkg.join("proofs")
            .join(format!("{}.proof.json", arts[1].id)),
    );
    std::fs::write(
        pkg.join("proofs").join(format!("{evil}.proof.json")),
        serde_json::to_vec_pretty(&proofs[1]).unwrap(),
    )
    .unwrap();

    let checks = verify_package_with_options(&pkg, &TrustRootStore::empty(), false).unwrap();
    assert_eq!(
        find(&checks, "merkle_root").unwrap().status,
        VerifyStatus::Pass,
        "structure is self-consistent by construction"
    );
    let sig =
        find(&checks, &format!("signature:{evil}")).expect("signature row for the fabricated id");
    assert_eq!(sig.status, VerifyStatus::Fail);
    assert!(sig.detail.contains("not in the package"));
    assert_eq!(
        find(&checks, "chain_linkage").unwrap().status,
        VerifyStatus::Fail
    );
    assert!(!fails(&checks).is_empty());
}

#[test]
fn one_edited_byte_in_a_sealed_envelope_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let (pkg, arts) = build(tmp.path(), &signer);
    let path = pkg.join("artifacts").join(format!("{}.json", arts[2].id));
    let mut env: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let payload = env["payload"].as_str().unwrap().to_string();
    let bytes = URL_SAFE_NO_PAD
        .decode(payload.trim_end_matches('='))
        .unwrap();
    let edited = String::from_utf8(bytes)
        .unwrap()
        .replace("step.b", "transfer.money");
    env["payload"] = serde_json::Value::String(URL_SAFE_NO_PAD.encode(edited.as_bytes()));
    std::fs::write(&path, serde_json::to_vec(&env).unwrap()).unwrap();

    let checks = verify_package_with_options(&pkg, &TrustRootStore::empty(), false).unwrap();
    let sig = find(&checks, &format!("signature:{}", arts[2].id)).unwrap();
    assert_eq!(sig.status, VerifyStatus::Fail, "{sig:?}");
}

#[test]
fn a_reordered_chain_fails_linkage() {
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let (pkg, _arts) = build(tmp.path(), &signer);
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pkg.join("receipt.json")).unwrap()).unwrap();
    let arr = receipt["artifacts"].as_array_mut().unwrap();
    arr.swap(1, 2);
    let ids: Vec<String> = arr
        .iter()
        .map(|a| a["artifact_id"].as_str().unwrap().to_string())
        .collect();
    let mut tree = treeship_core::merkle::MerkleTree::new();
    for id in &ids {
        tree.append(id);
    }
    receipt["merkle"]["root"] =
        serde_json::Value::String(format!("mroot_{}", hex::encode(tree.root().unwrap())));
    receipt["merkle"]["inclusion_proofs"] = serde_json::Value::Array(ids.iter().enumerate().map(|(i, id)| serde_json::json!({"artifact_id": id, "leaf_index": i, "proof": tree.inclusion_proof(i).unwrap()})).collect());
    std::fs::write(
        pkg.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    std::fs::write(
        pkg.join("merkle.json"),
        serde_json::to_vec_pretty(&receipt["merkle"]).unwrap(),
    )
    .unwrap();
    for (i, id) in ids.iter().enumerate() {
        std::fs::write(pkg.join("proofs").join(format!("{id}.proof.json")), serde_json::to_vec_pretty(&serde_json::json!({"artifact_id": id, "leaf_index": i, "proof": tree.inclusion_proof(i).unwrap()})).unwrap()).unwrap();
    }
    let checks = verify_package_with_options(&pkg, &TrustRootStore::empty(), false).unwrap();
    let link = find(&checks, "chain_linkage").unwrap();
    assert_eq!(link.status, VerifyStatus::Fail, "{link:?}");
}

#[test]
fn a_package_without_envelopes_fails_unless_structural_only() {
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let (pkg, _arts) = build(tmp.path(), &signer);
    std::fs::remove_dir_all(pkg.join("artifacts")).unwrap();
    std::fs::remove_file(pkg.join("keys.json")).unwrap();
    let checks = verify_package_with_options(&pkg, &TrustRootStore::empty(), false).unwrap();
    assert_eq!(
        find(&checks, "envelopes").unwrap().status,
        VerifyStatus::Fail
    );
    let checks = verify_package_structural(&pkg).unwrap();
    assert_eq!(
        find(&checks, "envelopes").unwrap().status,
        VerifyStatus::Warn
    );
    assert!(fails(&checks).is_empty(), "{:?}", fails(&checks));
}

#[test]
fn a_package_with_envelopes_but_no_close_record_fails_by_default() {
    // CLI-4: 0.31.2 and 0.31.3 wrote this shape, and so does deleting
    // record.json from any later package; nothing signed tells them apart.
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let (pkg, _) = build(tmp.path(), &signer);
    assert!(!pkg.join("record.json").exists());
    let checks = verify_package_with_options(&pkg, &TrustRootStore::empty(), false).unwrap();
    let row = find(&checks, "receipt_binding").unwrap();
    assert_eq!(row.status, VerifyStatus::Fail, "{}", row.detail);
    assert!(
        row.detail.contains("--structural") && row.detail.contains("not under a signature"),
        "{}",
        row.detail
    );
    // Reading it as structure is the reader's explicit choice, and a warning.
    let checks = verify_package_structural_with(&pkg);
    assert_eq!(
        find(&checks, "receipt_binding").unwrap().status,
        VerifyStatus::Warn
    );
    // The same package with its record verifies.
    seal_record(&pkg, &signer);
    let checks = verify_package_with_options(&pkg, &TrustRootStore::empty(), false).unwrap();
    assert_eq!(
        find(&checks, "receipt_binding").unwrap().status,
        VerifyStatus::Pass
    );
}

fn verify_package_structural_with(pkg: &Path) -> Vec<VerifyCheck> {
    verify_package_with_options(pkg, &TrustRootStore::empty(), true).unwrap()
}

/// Sign `stmt` as a close record under `signer` and add its key to keys.json.
fn write_record(
    pkg: &Path,
    signer: &Ed25519Signer,
    stmt: &treeship_core::statements::ReceiptStatement,
) {
    let r = sign(&payload_type("receipt"), stmt, signer).unwrap();
    std::fs::write(pkg.join("record.json"), r.envelope.to_json().unwrap()).unwrap();
    let mut keys: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pkg.join("keys.json")).unwrap()).unwrap();
    keys["keys"][signer.key_id()] = serde_json::Value::String(format!(
        "ed25519:{}",
        URL_SAFE_NO_PAD.encode(signer.public_key_bytes())
    ));
    std::fs::write(pkg.join("keys.json"), serde_json::to_vec(&keys).unwrap()).unwrap();
}

fn pinned(signer: &Ed25519Signer) -> TrustRootStore {
    TrustRootStore::with_roots(vec![TrustRoot {
        key_id: signer.key_id().into(),
        public_key: format!(
            "ed25519:{}",
            URL_SAFE_NO_PAD.encode(signer.public_key_bytes())
        ),
        kind: TrustRootKind::CertIssuer,
        label: "producer".into(),
        added_at: "2026-09-25T00:00:00Z".into(),
    }])
}

#[test]
fn a_close_record_forged_under_a_key_added_to_keys_json_fails() {
    // H1: rewrite receipt.json, add a key to keys.json, sign a fresh record
    // over the new digest. Every artifact still verifies under the pinned
    // producer key; the record's key signed nothing and is pinned nowhere.
    use sha2::{Digest, Sha256};
    let tmp = tempfile::tempdir().unwrap();
    let producer = Ed25519Signer::generate("key_t").unwrap();
    let (pkg, _) = build(tmp.path(), &producer);
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pkg.join("receipt.json")).unwrap()).unwrap();
    receipt["session"]["name"] = "EVIL".into();
    std::fs::write(
        pkg.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    let attacker = Ed25519Signer::generate("key_attacker").unwrap();
    let mut stmt =
        treeship_core::statements::ReceiptStatement::new("system://treeship-session", "session.v1");
    // The attacker can copy the close's id into the subject.
    stmt.subject = Some(treeship_core::statements::SubjectRef {
        artifact_id: Some(close_id(&pkg)),
        ..Default::default()
    });
    stmt.payload = Some(serde_json::json!({
        "receipt_digest": format!("sha256:{}", hex::encode(Sha256::digest(std::fs::read(pkg.join("receipt.json")).unwrap()))),
        "session_id": "ssn_sigtest",
    }));
    write_record(&pkg, &attacker, &stmt);
    for (trust, strict_label) in [
        (TrustRootStore::empty(), "unpinned"),
        (pinned(&producer), "producer pinned"),
    ] {
        let checks = verify_package_with_options(&pkg, &trust, false).unwrap();
        let row = find(&checks, "receipt_binding").unwrap();
        assert_eq!(
            row.status,
            VerifyStatus::Fail,
            "{strict_label}: {}",
            row.detail
        );
        assert!(row.detail.contains("key_attacker"), "{}", row.detail);
        assert!(matches!(
            treeship_core::session::package_verdict(&checks, false),
            treeship_core::session::PackageVerdict::Failed(_)
        ));
    }
}

#[test]
fn a_record_that_is_not_a_session_v1_receipt_fails() {
    use sha2::{Digest, Sha256};
    let tmp = tempfile::tempdir().unwrap();
    let producer = Ed25519Signer::generate("key_t").unwrap();
    let (pkg, _) = build(tmp.path(), &producer);
    let mut stmt =
        treeship_core::statements::ReceiptStatement::new("system://treeship-session", "webhook");
    stmt.payload = Some(serde_json::json!({
        "receipt_digest": format!("sha256:{}", hex::encode(Sha256::digest(std::fs::read(pkg.join("receipt.json")).unwrap()))),
        "session_id": "ssn_sigtest",
    }));
    write_record(&pkg, &producer, &stmt);
    let checks = verify_package_with_options(&pkg, &pinned(&producer), false).unwrap();
    let row = find(&checks, "receipt_binding").unwrap();
    assert_eq!(row.status, VerifyStatus::Fail, "{}", row.detail);
    assert!(row.detail.contains("session.v1"), "{}", row.detail);
}

#[test]
fn verified_needs_rows_that_passed_not_just_none_that_failed() {
    // H2: an empty package (no artifacts, no record) produced no FAIL row
    // on a default verify, and read `verified`.
    use treeship_core::session::{package_verdict, PackageVerdict};
    let tmp = tempfile::tempdir().unwrap();
    let events: Vec<SessionEvent> = vec![];
    let receipt = ReceiptComposer::compose(&manifest(), &events, vec![]);
    let pkg = build_package_with_approvals(&receipt, tmp.path(), None)
        .unwrap()
        .path;
    let checks = verify_package_with_options(&pkg, &TrustRootStore::empty(), false).unwrap();
    assert!(matches!(
        package_verdict(&checks, false),
        PackageVerdict::Failed(_)
    ));
    let checks = verify_package_with_options(&pkg, &TrustRootStore::empty(), true).unwrap();
    assert!(matches!(
        package_verdict(&checks, true),
        PackageVerdict::Failed(_)
    ));

    // The rule itself: each positive row is required.
    let full = vec![
        VerifyCheck::pass("signature:art_a", "ok"),
        VerifyCheck::pass("receipt_binding", "ok"),
        VerifyCheck::pass("signer_trust", "ok"),
    ];
    assert_eq!(package_verdict(&full, false), PackageVerdict::Verified);
    let mut warn_trust = full.clone();
    warn_trust[2] = VerifyCheck::warn("signer_trust", "unpinned");
    assert_eq!(
        package_verdict(&warn_trust, false),
        PackageVerdict::SignaturesPass
    );
    for drop in 0..3 {
        let mut partial = full.clone();
        partial.remove(drop);
        assert!(
            matches!(package_verdict(&partial, false), PackageVerdict::Failed(_)),
            "missing row {drop} must not verify"
        );
    }
    let mut unbound = full.clone();
    unbound[1] = VerifyCheck::warn("receipt_binding", "no record");
    assert!(matches!(
        package_verdict(&unbound, false),
        PackageVerdict::Failed(_)
    ));
}

/// Sign a close record as `signer`, naming the sealed close, over the
/// current receipt.json (what an attacker holding `signer` can do).
fn record_by(pkg: &Path, signer: &Ed25519Signer) {
    seal_record(pkg, signer);
    let mut keys: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pkg.join("keys.json")).unwrap()).unwrap();
    keys["keys"][signer.key_id()] = serde_json::Value::String(format!(
        "ed25519:{}",
        URL_SAFE_NO_PAD.encode(signer.public_key_bytes())
    ));
    std::fs::write(pkg.join("keys.json"), serde_json::to_vec(&keys).unwrap()).unwrap();
}

fn pinned_all(signers: &[&Ed25519Signer]) -> TrustRootStore {
    TrustRootStore::with_roots(
        signers
            .iter()
            .map(|s| TrustRoot {
                key_id: s.key_id().into(),
                public_key: format!("ed25519:{}", URL_SAFE_NO_PAD.encode(s.public_key_bytes())),
                kind: TrustRootKind::CertIssuer,
                label: "pinned".into(),
                added_at: "2026-09-26T00:00:00Z".into(),
            })
            .collect(),
    )
}

#[test]
fn a_record_signed_by_another_pinned_key_fails() {
    // Bypass E: the reader pins the producer and, for unrelated reasons,
    // Bob. Bob rewrites the receipt and signs a record naming the close.
    // Being pinned does not let Bob vouch for someone else's session.
    let tmp = tempfile::tempdir().unwrap();
    let producer = Ed25519Signer::generate("key_producer").unwrap();
    let bob = Ed25519Signer::generate("key_bob").unwrap();
    let (pkg, _) = build(tmp.path(), &producer);
    let mut receipt: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pkg.join("receipt.json")).unwrap()).unwrap();
    receipt["session"]["name"] = "EVIL".into();
    std::fs::write(
        pkg.join("receipt.json"),
        serde_json::to_vec_pretty(&receipt).unwrap(),
    )
    .unwrap();
    record_by(&pkg, &bob);
    let checks = verify_package_with_options(&pkg, &pinned_all(&[&producer, &bob]), false).unwrap();
    let row = find(&checks, "receipt_binding").unwrap();
    assert_eq!(row.status, VerifyStatus::Fail, "{}", row.detail);
    assert!(
        row.detail.contains("key_bob") && row.detail.contains("neither the signer"),
        "{}",
        row.detail
    );
}

#[test]
fn an_agent_record_key_named_by_the_signed_close_verifies_with_the_ship_key_pinned() {
    // The honest agent-own-key shape: the ship signs the close, which names
    // the agent's record key; the agent signs the record. Pinning the ship
    // key is enough.
    let tmp = tempfile::tempdir().unwrap();
    let ship = Ed25519Signer::generate("key_ship").unwrap();
    let agent = Ed25519Signer::generate("key_agent").unwrap();
    let (pkg, _) = build_with(tmp.path(), &ship, Some(&agent), None);
    seal_record(&pkg, &agent);
    let checks = verify_package_with_options(&pkg, &pinned_all(&[&ship]), false).unwrap();
    assert!(fails(&checks).is_empty(), "{:?}", fails(&checks));
    assert_eq!(
        find(&checks, "signer_trust").unwrap().status,
        VerifyStatus::Pass
    );
    assert_eq!(
        treeship_core::session::package_verdict(&checks, false),
        treeship_core::session::PackageVerdict::Verified
    );
    // A different key the close does not name cannot sign the record.
    let other = Ed25519Signer::generate("key_other").unwrap();
    record_by(&pkg, &other);
    let checks = verify_package_with_options(&pkg, &pinned_all(&[&ship, &other]), false).unwrap();
    assert_eq!(
        find(&checks, "receipt_binding").unwrap().status,
        VerifyStatus::Fail
    );
}

#[test]
fn a_record_naming_something_other_than_the_sealed_close_fails() {
    use sha2::{Digest, Sha256};
    use treeship_core::statements::{ReceiptStatement, SubjectRef};
    let tmp = tempfile::tempdir().unwrap();
    let producer = Ed25519Signer::generate("key_t").unwrap();
    let (pkg, arts) = build(tmp.path(), &producer);
    let mut stmt = ReceiptStatement::new("system://treeship-session", "session.v1");
    stmt.subject = Some(SubjectRef {
        artifact_id: Some(arts[2].id.clone()),
        ..Default::default()
    });
    stmt.payload = Some(serde_json::json!({
        "receipt_digest": format!("sha256:{}", hex::encode(Sha256::digest(std::fs::read(pkg.join("receipt.json")).unwrap()))),
        "session_id": "ssn_sigtest",
    }));
    let r = sign(&payload_type("receipt"), &stmt, &producer).unwrap();
    std::fs::write(pkg.join("record.json"), r.envelope.to_json().unwrap()).unwrap();
    let checks = verify_package_with_options(&pkg, &pinned_all(&[&producer]), false).unwrap();
    let row = find(&checks, "receipt_binding").unwrap();
    assert_eq!(row.status, VerifyStatus::Fail, "{}", row.detail);
    assert!(row.detail.contains("session.close"), "{}", row.detail);
}

#[test]
fn an_artifact_by_an_unvouched_key_in_a_trusted_package_fails() {
    // Bypass B: the producer is pinned; one chained artifact is signed by a
    // key nobody pinned and the close does not name. Not a warning.
    let tmp = tempfile::tempdir().unwrap();
    let producer = Ed25519Signer::generate("key_producer").unwrap();
    let intruder = Ed25519Signer::generate("key_intruder").unwrap();
    let (pkg, _) = build_with(tmp.path(), &producer, None, Some(&intruder));
    seal_record(&pkg, &producer);
    let checks = verify_package_with_options(&pkg, &pinned_all(&[&producer]), false).unwrap();
    let row = find(&checks, "signer_trust").unwrap();
    assert_eq!(row.status, VerifyStatus::Fail, "{}", row.detail);
    assert!(row.detail.contains("key_intruder"), "{}", row.detail);
    // With nothing pinned the reader has decided nothing: a warning.
    let checks = verify_package_with_options(&pkg, &TrustRootStore::empty(), false).unwrap();
    assert_eq!(
        find(&checks, "signer_trust").unwrap().status,
        VerifyStatus::Warn
    );
}
