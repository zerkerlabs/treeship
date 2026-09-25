//! Audit 2026-09-25, CLI-3 / W1-3: a countersigned room participant verifies
//! inside a package. The joining agent and the host sign the participant's
//! canonical bytes, not the DSSE PAE, so the generic per-artifact check failed
//! every honest room. The package verifier now checks a participant against
//! the invitation it redeems, taken from the same sealed set.
//!
//! Every package here is built from really-signed envelopes. The joining
//! agent's key is deliberately NOT in the package's keys.json: across two
//! ships it never is.

use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use sha2::{Digest, Sha256};
use treeship_core::attestation::{sign, Ed25519Signer, Envelope, Signer};
use treeship_core::session::{
    build_package_with_approvals,
    event::SessionEvent,
    manifest::SessionManifest,
    receipt::{ArtifactEntry, ReceiptComposer},
    verify_package_with_options, ApprovalsBundle, VerifyCheck, VerifyStatus,
};
use treeship_core::statements::invitation::{
    GrantedCapabilities, InvitationStatement, InviteeRestriction,
};
use treeship_core::statements::session_participant::{
    participant_artifact_id, SessionParticipantStatement,
};
use treeship_core::statements::{payload_type, ActionStatement};
use treeship_core::trust::TrustRootStore;

const SESSION: &str = "ssn_room";

struct Art {
    id: String,
    kind: &'static str,
    envelope: Envelope,
    digest: String,
    unchained: bool,
}

fn b64(s: &Ed25519Signer) -> String {
    URL_SAFE_NO_PAD.encode(s.public_key_bytes())
}

fn caps() -> GrantedCapabilities {
    GrantedCapabilities {
        action_types: vec!["tool.call".into()],
    }
}

fn root(host: &Ed25519Signer) -> Art {
    let stmt = ActionStatement::new("agent://host", "session.start");
    let r = sign(&payload_type("action"), &stmt, host).unwrap();
    Art {
        id: r.artifact_id,
        kind: "action",
        envelope: r.envelope,
        digest: r.digest,
        unchained: false,
    }
}

/// An invitation to `session`, naming `issuer` and signed by `signer`.
fn invitation(signer: &Ed25519Signer, issuer: &str, session: &str) -> Art {
    let stmt = InvitationStatement::new(
        session,
        issuer,
        InviteeRestriction::Open,
        caps(),
        "2099-01-01T00:00:00Z",
        "00112233445566778899aabbccddeeff",
    );
    let r = sign(&payload_type("invitation"), &stmt, signer).unwrap();
    Art {
        id: r.artifact_id,
        kind: "invitation",
        envelope: r.envelope,
        digest: r.digest,
        unchained: true,
    }
}

/// A participant redeeming `inv`, signed by `joiner`, countersigned by
/// `countersigner` when given.
fn participant(
    inv: &Art,
    joiner: &Ed25519Signer,
    countersigner: Option<&Ed25519Signer>,
    session: &str,
) -> Art {
    let stmt = SessionParticipantStatement::new(
        session,
        &inv.id,
        b64(joiner),
        "2026-09-25T00:00:10Z",
        caps(),
    );
    let pending = stmt.pending_envelope(joiner).unwrap();
    let id = participant_artifact_id(&pending).unwrap();
    let envelope = match countersigner {
        Some(h) => SessionParticipantStatement::attach_host_countersign(&pending, h).unwrap(),
        None => pending,
    };
    let digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(envelope.to_json().unwrap()))
    );
    Art {
        id,
        kind: "session-participant",
        envelope,
        digest,
        unchained: true,
    }
}

fn build(dir: &Path, host: &Ed25519Signer, arts: &[&Art]) -> PathBuf {
    let entries: Vec<ArtifactEntry> = arts
        .iter()
        .map(|a| ArtifactEntry {
            artifact_id: a.id.clone(),
            payload_type: payload_type(a.kind),
            digest: Some(a.digest.clone()),
            signed_at: Some("2026-09-25T00:00:05Z".into()),
            unchained: a.unchained,
        })
        .collect();
    let manifest = SessionManifest::new(
        SESSION.into(),
        "agent://host".into(),
        "2026-09-25T00:00:00Z".into(),
        1790294400000,
    );
    let events: Vec<SessionEvent> = vec![];
    let receipt = ReceiptComposer::compose(&manifest, &events, entries);
    let bundle = ApprovalsBundle {
        sealed_envelopes: arts
            .iter()
            .map(|a| (a.id.clone(), a.envelope.to_json().unwrap()))
            .collect(),
        // Only the host's key: the joiner is on another ship.
        signer_keys: vec![(host.key_id().to_string(), format!("ed25519:{}", b64(host)))],
        ..ApprovalsBundle::default()
    };
    let pkg = build_package_with_approvals(&receipt, dir, Some(&bundle))
        .unwrap()
        .path;
    seal_record(&pkg, host);
    pkg
}

/// The close record `session close` writes (0.31.4+): a `session.v1` record
/// signed by the host over the SHA-256 of receipt.json and the session id.
fn seal_record(pkg: &Path, host: &Ed25519Signer) {
    use treeship_core::statements::ReceiptStatement;
    let receipt = std::fs::read(pkg.join("receipt.json")).unwrap();
    let mut stmt = ReceiptStatement::new("system://treeship-session", "session.v1");
    stmt.payload = Some(serde_json::json!({
        "receipt_digest": format!("sha256:{}", hex::encode(Sha256::digest(&receipt))),
        "session_id": SESSION,
    }));
    let r = sign(&payload_type("receipt"), &stmt, host).unwrap();
    std::fs::write(pkg.join("record.json"), r.envelope.to_json().unwrap()).unwrap();
}

fn row(pkg: &Path, id: &str) -> VerifyCheck {
    verify_package_with_options(pkg, &TrustRootStore::empty(), false)
        .unwrap()
        .into_iter()
        .find(|c| c.name == format!("signature:{id}"))
        .expect("signature row for the participant")
}

fn keys() -> (Ed25519Signer, Ed25519Signer, Ed25519Signer) {
    (
        Ed25519Signer::generate("key_host").unwrap(),
        Ed25519Signer::generate("key_joiner").unwrap(),
        Ed25519Signer::generate("key_stranger").unwrap(),
    )
}

#[test]
fn a_countersigned_participant_from_another_ship_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let (host, joiner, _) = keys();
    let (r, inv) = (root(&host), invitation(&host, &b64(&host), SESSION));
    let p = participant(&inv, &joiner, Some(&host), SESSION);
    let pkg = build(tmp.path(), &host, &[&r, &inv, &p]);
    let checks = verify_package_with_options(&pkg, &TrustRootStore::empty(), false).unwrap();
    let fails: Vec<_> = checks
        .iter()
        .filter(|c| c.status == VerifyStatus::Fail)
        .map(|c| format!("{}: {}", c.name, c.detail))
        .collect();
    assert!(fails.is_empty(), "{fails:?}");
    let pr = row(&pkg, &p.id);
    assert_eq!(pr.status, VerifyStatus::Pass, "{}", pr.detail);
    assert!(
        pr.detail.contains("key_host") && pr.detail.contains(&inv.id),
        "{}",
        pr.detail
    );
    // The host key is what signer_trust judges; the joiner is not a package key.
    let trust = checks.iter().find(|c| c.name == "signer_trust").unwrap();
    assert!(
        trust.detail.contains("key_host") && !trust.detail.contains("key_joiner"),
        "{}",
        trust.detail
    );
}

#[test]
fn a_participant_without_the_host_countersign_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let (host, joiner, _) = keys();
    let (r, inv) = (root(&host), invitation(&host, &b64(&host), SESSION));
    let p = participant(&inv, &joiner, None, SESSION);
    let pkg = build(tmp.path(), &host, &[&r, &inv, &p]);
    let pr = row(&pkg, &p.id);
    assert_eq!(pr.status, VerifyStatus::Fail);
    assert!(pr.detail.contains("countersign"), "{}", pr.detail);
}

#[test]
fn a_countersign_by_a_key_other_than_the_issuer_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let (host, joiner, stranger) = keys();
    let (r, inv) = (root(&host), invitation(&host, &b64(&host), SESSION));
    let p = participant(&inv, &joiner, Some(&stranger), SESSION);
    let pkg = build(tmp.path(), &host, &[&r, &inv, &p]);
    assert_eq!(row(&pkg, &p.id).status, VerifyStatus::Fail);
}

#[test]
fn an_invitation_that_is_not_sealed_fails_and_never_falls_back() {
    // The participant is otherwise perfect; its invitation is not in the
    // sealed set, so the host key cannot be established from the package.
    let tmp = tempfile::tempdir().unwrap();
    let (host, joiner, _) = keys();
    let (r, inv) = (root(&host), invitation(&host, &b64(&host), SESSION));
    let p = participant(&inv, &joiner, Some(&host), SESSION);
    let pkg = build(tmp.path(), &host, &[&r, &p]);
    let pr = row(&pkg, &p.id);
    assert_eq!(pr.status, VerifyStatus::Fail);
    assert!(pr.detail.contains("not sealed"), "{}", pr.detail);
}

#[test]
fn a_sealed_invitation_whose_envelope_is_missing_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let (host, joiner, _) = keys();
    let (r, inv) = (root(&host), invitation(&host, &b64(&host), SESSION));
    let p = participant(&inv, &joiner, Some(&host), SESSION);
    let pkg = build(tmp.path(), &host, &[&r, &inv, &p]);
    std::fs::remove_file(pkg.join("artifacts").join(format!("{}.json", inv.id))).unwrap();
    assert_eq!(row(&pkg, &p.id).status, VerifyStatus::Fail);
}

#[test]
fn an_invitation_naming_an_issuer_other_than_its_signer_fails() {
    // Signed by the host's package key but naming the stranger as issuer,
    // and the stranger countersigns: every signature holds, but the key the
    // countersign is checked against is not a key the package carries.
    let tmp = tempfile::tempdir().unwrap();
    let (host, joiner, stranger) = keys();
    let (r, inv) = (root(&host), invitation(&host, &b64(&stranger), SESSION));
    let p = participant(&inv, &joiner, Some(&stranger), SESSION);
    let pkg = build(tmp.path(), &host, &[&r, &inv, &p]);
    let pr = row(&pkg, &p.id);
    assert_eq!(pr.status, VerifyStatus::Fail);
    assert!(pr.detail.contains("issuer"), "{}", pr.detail);
}

#[test]
fn a_participant_joining_another_session_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let (host, joiner, _) = keys();
    let (r, inv) = (root(&host), invitation(&host, &b64(&host), "ssn_elsewhere"));
    let p = participant(&inv, &joiner, Some(&host), "ssn_elsewhere");
    let pkg = build(tmp.path(), &host, &[&r, &inv, &p]);
    let pr = row(&pkg, &p.id);
    assert_eq!(pr.status, VerifyStatus::Fail);
    assert!(pr.detail.contains(SESSION), "{}", pr.detail);
}

#[test]
fn an_edited_participant_payload_fails() {
    let tmp = tempfile::tempdir().unwrap();
    let (host, joiner, _) = keys();
    let (r, inv) = (root(&host), invitation(&host, &b64(&host), SESSION));
    let mut p = participant(&inv, &joiner, Some(&host), SESSION);
    // Widen the granted capabilities after both signatures were made.
    let mut stmt: SessionParticipantStatement = p.envelope.unmarshal_statement().unwrap();
    stmt.capabilities.action_types.push("admin.*".into());
    p.envelope.payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&stmt).unwrap());
    p.digest = format!(
        "sha256:{}",
        hex::encode(Sha256::digest(p.envelope.to_json().unwrap()))
    );
    let pkg = build(tmp.path(), &host, &[&r, &inv, &p]);
    assert_eq!(row(&pkg, &p.id).status, VerifyStatus::Fail);
}
