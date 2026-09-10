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

/// A package from real signed envelopes: root <- a <- b, plus one unchained.
fn build(dir: &Path, signer: &Ed25519Signer) -> (PathBuf, Vec<Signed>) {
    let root = sign_action(signer, "session.start", None);
    let a = sign_action(signer, "step.a", Some(&root.id));
    let b = sign_action(signer, "step.b", Some(&a.id));
    let loose = sign_action(signer, "step.loose", None);
    let arts = vec![root, a, b, loose];
    let entries = vec![
        entry(&arts[0], false),
        entry(&arts[1], false),
        entry(&arts[2], false),
        entry(&arts[3], true),
    ];
    let events: Vec<SessionEvent> = vec![];
    let receipt = ReceiptComposer::compose(&manifest(), &events, entries);
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
    (out.path, arts)
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
