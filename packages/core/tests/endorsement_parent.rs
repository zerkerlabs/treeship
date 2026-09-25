//! Audit 2026-09-25, CLI-1 / W1-1: an endorsement signs the parent it chains
//! onto. Before, storage recorded the parent (the most recent artifact) and
//! the verifier, finding no signed `parentId`, read the endorsement's subject
//! as its parent; endorsing anything but the latest artifact then reported
//! the chain as tampered.
//!
//! These tests build packages from really-signed envelopes and check the
//! package verifier's `chain_linkage` row, plus `signed_parent` itself and the
//! byte stability of an endorsement with no parent.

use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use treeship_core::attestation::{sign, Ed25519Signer, Envelope, Signer};
use treeship_core::session::{
    build_package_with_approvals,
    event::SessionEvent,
    manifest::SessionManifest,
    receipt::{ArtifactEntry, ReceiptComposer},
    verify_package_with_options, ApprovalsBundle, VerifyCheck, VerifyStatus,
};
use treeship_core::statements::{payload_type, ActionStatement, EndorsementStatement, SubjectRef};
use treeship_core::trust::TrustRootStore;
use treeship_core::verify::{signed_parent, SignedParent};

struct Signed {
    id: String,
    digest: String,
    envelope: Vec<u8>,
    signed_at: String,
    kind: &'static str,
}

fn action(signer: &Ed25519Signer, name: &str, parent: Option<&str>) -> Signed {
    let mut stmt = ActionStatement::new("agent://t", name);
    stmt.parent_id = parent.map(str::to_string);
    let r = sign(&payload_type("action"), &stmt, signer).unwrap();
    Signed {
        id: r.artifact_id,
        digest: r.digest,
        envelope: r.envelope.to_json().unwrap(),
        signed_at: stmt.timestamp,
        kind: "action",
    }
}

fn endorsement(signer: &Ed25519Signer, subject: &str, parent: Option<&str>) -> Signed {
    let mut stmt = EndorsementStatement::new("human://reviewer", "review");
    stmt.subject = SubjectRef {
        artifact_id: Some(subject.to_string()),
        digest: None,
        uri: None,
    };
    stmt.parent_id = parent.map(str::to_string);
    let r = sign(&payload_type("endorsement"), &stmt, signer).unwrap();
    Signed {
        id: r.artifact_id,
        digest: r.digest,
        envelope: r.envelope.to_json().unwrap(),
        signed_at: stmt.timestamp,
        kind: "endorsement",
    }
}

/// A package whose chained entries are `arts` in order.
fn build(dir: &Path, signer: &Ed25519Signer, arts: &[Signed]) -> PathBuf {
    let entries: Vec<ArtifactEntry> = arts
        .iter()
        .map(|s| ArtifactEntry {
            artifact_id: s.id.clone(),
            payload_type: payload_type(s.kind),
            digest: Some(s.digest.clone()),
            signed_at: Some(s.signed_at.clone()),
            unchained: false,
        })
        .collect();
    let manifest = SessionManifest::new(
        "ssn_endorse".into(),
        "agent://t".into(),
        "2026-09-25T00:00:00Z".into(),
        1790294400000,
    );
    let events: Vec<SessionEvent> = vec![];
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
    build_package_with_approvals(&receipt, dir, Some(&bundle))
        .unwrap()
        .path
}

fn linkage(pkg: &Path) -> VerifyCheck {
    let checks = verify_package_with_options(pkg, &TrustRootStore::empty(), false).unwrap();
    for c in &checks {
        if c.name.starts_with("signature:") {
            assert_eq!(c.status, VerifyStatus::Pass, "{}: {}", c.name, c.detail);
        }
    }
    checks
        .into_iter()
        .find(|c| c.name == "chain_linkage")
        .expect("chain_linkage row")
}

#[test]
fn endorsing_an_older_artifact_links_through_the_signed_parent() {
    // a <- x <- E(endorses a) <- b : the CLI-1 repro.
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let a = action(&signer, "a", None);
    let x = action(&signer, "x", Some(&a.id));
    let e = endorsement(&signer, &a.id, Some(&x.id));
    let b = action(&signer, "b", Some(&e.id));
    let pkg = build(tmp.path(), &signer, &[a, x, e, b]);
    let row = linkage(&pkg);
    assert_eq!(row.status, VerifyStatus::Pass, "{}", row.detail);
}

#[test]
fn a_signed_parent_naming_the_wrong_artifact_fails_not_warns() {
    // Correctly signed, but the endorsement's parentId names its subject, not
    // the artifact it follows. A present parentId never takes the legacy path.
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let a = action(&signer, "a", None);
    let x = action(&signer, "x", Some(&a.id));
    let e = endorsement(&signer, &a.id, Some(&a.id));
    let (e_id, x_id) = (e.id.clone(), x.id.clone());
    let pkg = build(tmp.path(), &signer, &[a, x, e]);
    let row = linkage(&pkg);
    assert_eq!(row.status, VerifyStatus::Fail, "{}", row.detail);
    assert!(
        row.detail.contains(&e_id) && row.detail.contains(&x_id),
        "{}",
        row.detail
    );
}

#[test]
fn an_endorsement_with_no_signed_parent_warns_and_is_named() {
    // The 0.31.9 shape: endorses `a`, chained after `x`, no parentId.
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let a = action(&signer, "a", None);
    let x = action(&signer, "x", Some(&a.id));
    let e = endorsement(&signer, &a.id, None);
    let b = action(&signer, "b", Some(&e.id));
    let e_id = e.id.clone();
    let pkg = build(tmp.path(), &signer, &[a, x, e, b]);
    let row = linkage(&pkg);
    assert_eq!(row.status, VerifyStatus::Warn, "{}", row.detail);
    assert!(row.detail.contains(&e_id), "{}", row.detail);
}

#[test]
fn a_legacy_endorsement_does_not_mask_a_real_break() {
    // One legacy endorsement plus one action whose signed parent is wrong:
    // the row fails; the warning cannot soften a genuine mismatch.
    let tmp = tempfile::tempdir().unwrap();
    let signer = Ed25519Signer::generate("key_t").unwrap();
    let a = action(&signer, "a", None);
    let e = endorsement(&signer, &a.id, None);
    let b = action(&signer, "b", Some(&a.id));
    let pkg = build(tmp.path(), &signer, &[a, e, b]);
    assert_eq!(linkage(&pkg).status, VerifyStatus::Fail);
}

#[test]
fn signed_parent_reads_the_edge_each_statement_signs() {
    use serde_json::json;
    let named = |s: &str| SignedParent::Named(s.to_string());
    assert_eq!(
        signed_parent(&json!({"type": "treeship/action/v1", "parentId": "art_p"})),
        named("art_p")
    );
    assert_eq!(
        signed_parent(&json!({"type": "treeship/endorsement/v1",
            "subject": {"artifactId": "art_s"}, "parentId": "art_p"})),
        named("art_p"),
        "an endorsement's parentId wins over its subject"
    );
    assert_eq!(
        signed_parent(&json!({"type": "treeship/endorsement/v1",
            "subject": {"artifactId": "art_s"}})),
        SignedParent::LegacyEndorsement,
        "an endorsement's subject is what it endorses, never its parent"
    );
    assert_eq!(
        signed_parent(&json!({"type": "treeship/receipt/v1",
            "subject": {"artifactId": "art_s"}})),
        named("art_s")
    );
    assert_eq!(
        signed_parent(&json!({"type": "treeship/action/v1", "subject": {"artifactId": "ord_1"}})),
        SignedParent::None,
        "an external subject is not an edge"
    );
    assert_eq!(
        signed_parent(&json!({"type": "treeship/handoff/v1", "artifacts": ["art_h", "art_i"]})),
        named("art_h")
    );
    assert_eq!(
        signed_parent(
            &json!({"type": "treeship/session-participant/v1", "invitation_ref": "art_inv"})
        ),
        named("art_inv")
    );
    assert_eq!(
        signed_parent(&json!({"type": "treeship/action/v1"})),
        SignedParent::None
    );
    // A present key decides: a null or non-string parent names nothing and
    // never falls through to the legacy path or the subject edge (#474, F1).
    for bad in [json!(null), json!(7), json!({"id": "art_p"})] {
        assert_eq!(
            signed_parent(&json!({"type": "treeship/endorsement/v1",
                "subject": {"artifactId": "art_s"}, "parentId": bad})),
            SignedParent::None,
            "endorsement parentId {bad}"
        );
        assert_eq!(
            signed_parent(&json!({"type": "treeship/receipt/v1",
                "subject": {"artifactId": "art_s"}, "parent_id": bad})),
            SignedParent::None,
            "receipt parent_id {bad}"
        );
        assert_eq!(
            signed_parent(&json!({"type": "treeship/session-participant/v1",
                "invitation_ref": bad})),
            SignedParent::None,
            "participant invitation_ref {bad}"
        );
    }
}

#[test]
fn an_endorsement_without_a_parent_keeps_its_bytes() {
    // Hand-computed: field order is the struct's, and absent options are
    // omitted. Adding `parentId` must not change this.
    let mut stmt = EndorsementStatement::new("human://r", "review");
    stmt.timestamp = "2026-09-25T00:00:00Z".into();
    stmt.subject = SubjectRef {
        artifact_id: Some("art_00112233445566778899aabbccddeeff".into()),
        digest: None,
        uri: None,
    };
    assert_eq!(
        String::from_utf8(serde_json::to_vec(&stmt).unwrap()).unwrap(),
        r#"{"type":"treeship/endorsement/v1","timestamp":"2026-09-25T00:00:00Z","endorser":"human://r","subject":{"artifactId":"art_00112233445566778899aabbccddeeff"},"kind":"review"}"#
    );
}

#[test]
fn an_endorsement_signed_by_0_31_9_round_trips_byte_for_byte() {
    // The endorsement in the T2 vector honest/legacy-endorsement-0.31.9 was
    // written by the treeship 0.31.9 release binary (see that directory's
    // README for provenance). Its signature is checked against the key the
    // package names, then its payload is decoded into today's struct and
    // re-encoded: the bytes must match, or old endorsements would re-sign or
    // re-derive differently.
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors/packages/honest/legacy-endorsement-0.31.9");
    let keys: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("keys.json")).unwrap()).unwrap();
    let mut found = 0;
    for f in std::fs::read_dir(dir.join("artifacts")).unwrap() {
        let raw = std::fs::read(f.unwrap().path()).unwrap();
        let env = Envelope::from_json(&raw).unwrap();
        if env.payload_type != payload_type("endorsement") {
            continue;
        }
        found += 1;
        let sig = &env.signatures[0];
        let pk = keys["keys"][&sig.keyid].as_str().unwrap();
        let vk = treeship_core::trust::decode_ed25519_pubkey(pk).unwrap();
        treeship_core::attestation::verify_with_key(&env, &sig.keyid, vk)
            .expect("the 0.31.9 endorsement verifies under its own key");
        let bytes = env.payload_bytes().unwrap();
        let stmt: EndorsementStatement = serde_json::from_slice(&bytes).unwrap();
        assert!(stmt.parent_id.is_none(), "0.31.9 signed no parentId");
        assert_eq!(serde_json::to_vec(&stmt).unwrap(), bytes);
    }
    assert_eq!(found, 1, "the vector carries exactly one endorsement");
}
