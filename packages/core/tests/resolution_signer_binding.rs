//! The signer of a card or revocation is the key whose signature VERIFIED,
//! never the keyid a signature names. `verify_any` accepts an envelope as soon
//! as any one signature verifies against any known key, so a forged first
//! signature naming a victim's pinned key beside a real one from any other
//! pinned party used to make a card key-bound to the victim, and a revocation
//! honored as the victim's own. verify_resolution also never compared the
//! revocation's `payload.card` with the card.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use treeship_core::attestation::envelope::{Envelope, Signature};
use treeship_core::attestation::{sign, Ed25519Signer, Signer};
use treeship_core::statements::{payload_type, ReceiptStatement};
use treeship_core::trust::{TrustRoot, TrustRootKind, TrustRootStore};
use treeship_core::verify::presentation::verify_presentation;
use treeship_core::verify::resolution::{verify_resolution, ResolutionBundle};

const NOW: &str = "2026-09-28T00:00:00Z";
const NOW_UNIX: u64 = 1_790_553_600;

fn root(s: &Ed25519Signer, kind: TrustRootKind) -> TrustRoot {
    // key_victim is pinned as agent://victim, key_attacker as agent://attacker.
    let agent = s
        .key_id()
        .strip_prefix("key_")
        .map(|n| format!("agent://{n}"));
    TrustRoot {
        key_id: s.key_id().to_string(),
        public_key: format!("ed25519:{}", URL_SAFE_NO_PAD.encode(s.public_key_bytes())),
        kind,
        agent,
        label: String::new(),
        added_at: String::new(),
    }
}

/// (artifact id, envelope)
fn receipt(kind: &str, payload: serde_json::Value, signer: &Ed25519Signer) -> (String, Envelope) {
    let mut stmt = ReceiptStatement::new("ship://ship_test", kind);
    stmt.payload = Some(payload);
    let r = sign(&payload_type("receipt"), &stmt, signer).unwrap();
    (r.artifact_id, r.envelope)
}

/// Prepend a forged signature naming `claimed` (garbage bytes) in front of
/// the real one.
fn with_forged_first(mut env: Envelope, claimed: &str) -> Envelope {
    env.signatures.insert(
        0,
        Signature {
            keyid: claimed.to_string(),
            sig: URL_SAFE_NO_PAD.encode([7u8; 64]),
        },
    );
    env
}

fn two_agents() -> (Ed25519Signer, Ed25519Signer, TrustRootStore) {
    let victim = Ed25519Signer::generate("key_victim").unwrap();
    let attacker = Ed25519Signer::generate("key_attacker").unwrap();
    let trust = TrustRootStore::with_roots(vec![
        root(&victim, TrustRootKind::AgentCert),
        root(&attacker, TrustRootKind::AgentCert),
    ]);
    (victim, attacker, trust)
}

fn bundle(card: Envelope, revocations: Vec<Envelope>) -> ResolutionBundle {
    ResolutionBundle {
        agent: "agent://victim".into(),
        card,
        certs: vec![],
        revocations,
    }
}

fn presentation(card_id: &str, card: &Envelope, revocations: &[Envelope]) -> serde_json::Value {
    serde_json::json!({
        "type": "treeship/presentation/v1",
        "agent": "agent://victim",
        "card": { "artifact_id": card_id, "envelope_json": serde_json::to_string(card).unwrap() },
        "certs": [],
        "revocations": revocations.iter().map(|r| serde_json::json!({
            "artifact_id": "art_rev", "envelope_json": serde_json::to_string(r).unwrap()
        })).collect::<Vec<_>>(),
    })
}

#[test]
fn a_forged_card_is_not_key_bound_to_the_victim_in_resolution_or_presentation() {
    let (_victim, attacker, trust) = two_agents();
    let (id, card) = receipt(
        "agent_card.v1",
        serde_json::json!({ "agent": "agent://victim", "keyid": "key_victim",
                            "capabilities": { "tools": ["db.drop"] } }),
        &attacker,
    );
    let card = with_forged_first(card, "key_victim");
    let v = verify_resolution(&bundle(card.clone(), vec![]), &trust, NOW).unwrap();
    assert!(v.sig_ok, "the attacker's own signature does verify");
    assert!(
        !v.key_bound,
        "a forged first keyid must not bind the card to the victim"
    );

    let p = verify_presentation(&presentation(&id, &card, &[]), &trust, None, NOW_UNIX).unwrap();
    assert!(
        p.sig_ok && !p.key_bound,
        "presentation verdict wrong: sig_ok={} key_bound={} revoked={:?}",
        p.sig_ok,
        p.key_bound,
        p.revoked
    );
}

#[test]
fn a_forged_revocation_is_ignored_in_resolution_and_presentation() {
    let (victim, attacker, trust) = two_agents();
    let (id, card) = receipt(
        "agent_card.v1",
        serde_json::json!({ "agent": "agent://victim", "keyid": "key_victim" }),
        &victim,
    );
    let (_, rev) = receipt(
        "agent_card_revocation.v1",
        serde_json::json!({ "card": id, "reason": "pwned" }),
        &attacker,
    );
    let rev = with_forged_first(rev, "key_victim");
    let v = verify_resolution(&bundle(card.clone(), vec![rev.clone()]), &trust, NOW).unwrap();
    assert!(
        v.key_bound && !v.revoked,
        "resolution verdict wrong: key_bound={} revoked={}",
        v.key_bound,
        v.revoked
    );
    let p = verify_presentation(&presentation(&id, &card, &[rev]), &trust, None, NOW_UNIX).unwrap();
    assert!(
        p.key_bound && p.revoked.is_none(),
        "presentation verdict wrong: sig_ok={} key_bound={} revoked={:?}",
        p.sig_ok,
        p.key_bound,
        p.revoked
    );
}

#[test]
fn a_revocation_for_another_card_does_not_revoke_this_one() {
    let victim = Ed25519Signer::generate("key_victim").unwrap();
    let trust = TrustRootStore::with_roots(vec![root(&victim, TrustRootKind::AgentCert)]);
    let (id, card) = receipt(
        "agent_card.v1",
        serde_json::json!({ "agent": "agent://victim", "keyid": "key_victim" }),
        &victim,
    );
    let (_, other) = receipt(
        "agent_card_revocation.v1",
        serde_json::json!({ "card": "art_some_old_card", "reason": "rotated" }),
        &victim,
    );
    let (_, mine) = receipt(
        "agent_card_revocation.v1",
        serde_json::json!({ "card": id, "reason": "rotated" }),
        &victim,
    );
    let v = verify_resolution(&bundle(card.clone(), vec![other.clone()]), &trust, NOW).unwrap();
    assert!(!v.revoked, "another card's revocation revoked this one");
    let v = verify_resolution(&bundle(card.clone(), vec![mine.clone()]), &trust, NOW).unwrap();
    assert!(v.revoked && v.revocation_reason.as_deref() == Some("rotated"));
    let p =
        verify_presentation(&presentation(&id, &card, &[mine]), &trust, None, NOW_UNIX).unwrap();
    assert!(
        p.revoked.is_some(),
        "presentation verdict wrong: sig_ok={} key_bound={} revoked={:?}",
        p.sig_ok,
        p.key_bound,
        p.revoked
    );
}

#[test]
fn a_presentation_naming_a_different_card_id_is_refused() {
    let victim = Ed25519Signer::generate("key_victim").unwrap();
    let trust = TrustRootStore::with_roots(vec![root(&victim, TrustRootKind::AgentCert)]);
    let (_, card) = receipt(
        "agent_card.v1",
        serde_json::json!({ "agent": "agent://victim", "keyid": "key_victim" }),
        &victim,
    );
    let err = match verify_presentation(
        &presentation("art_not_this_card", &card, &[]),
        &trust,
        None,
        NOW_UNIX,
    ) {
        Ok(_) => panic!("a card id that is not what the envelope re-derives to must be refused"),
        Err(e) => e,
    };
    assert!(err.contains("re-derives"), "{err}");
}

/// With no trusted key verifying the card, the card id is still derived from
/// the card's bytes, so a staple cannot be made to prove a different id.
#[test]
fn an_unverified_card_still_has_its_id_checked() {
    let victim = Ed25519Signer::generate("key_victim").unwrap();
    let empty = TrustRootStore::with_roots(vec![]);
    let (id, card) = receipt(
        "agent_card.v1",
        serde_json::json!({ "agent": "agent://victim", "keyid": "key_victim" }),
        &victim,
    );
    // The honest id passes the check (and is simply unverified).
    let p = verify_presentation(&presentation(&id, &card, &[]), &empty, None, NOW_UNIX).unwrap();
    assert!(!p.sig_ok && !p.key_bound);
    // A different id is refused even though nothing verified the card.
    match verify_presentation(
        &presentation("art_other", &card, &[]),
        &empty,
        None,
        NOW_UNIX,
    ) {
        Ok(_) => panic!("an unverified card's id went unchecked"),
        Err(e) => assert!(e.contains("re-derives"), "{e}"),
    }
}

/// A key pinned as agent://attacker signs, with its own key and no forgery, a
/// card claiming agent://victim: the signature verifies, the card is nobody's.
#[test]
fn a_pinned_key_cannot_sign_itself_into_another_agents_name() {
    let (_victim, attacker, trust) = two_agents();
    let (id, card) = receipt(
        "agent_card.v1",
        serde_json::json!({ "agent": "agent://victim", "keyid": "key_attacker" }),
        &attacker,
    );
    let v = verify_resolution(&bundle(card.clone(), vec![]), &trust, NOW).unwrap();
    assert!(
        v.sig_ok && !v.key_bound,
        "resolution: key_bound={}",
        v.key_bound
    );
    let p = verify_presentation(&presentation(&id, &card, &[]), &trust, None, NOW_UNIX).unwrap();
    assert!(
        p.sig_ok && !p.key_bound,
        "presentation: key_bound={}",
        p.key_bound
    );
    // And the attacker's honest card for its own name stays key-bound.
    let (own_id, own) = receipt(
        "agent_card.v1",
        serde_json::json!({ "agent": "agent://attacker", "keyid": "key_attacker" }),
        &attacker,
    );
    let mut b = bundle(own.clone(), vec![]);
    b.agent = "agent://attacker".into();
    assert!(verify_resolution(&b, &trust, NOW).unwrap().key_bound);
    let mut pres = presentation(&own_id, &own, &[]);
    pres["agent"] = serde_json::json!("agent://attacker");
    assert!(
        verify_presentation(&pres, &trust, None, NOW_UNIX)
            .unwrap()
            .key_bound
    );
}

/// A revocation with reason `compromised` retires the key: a newer card the
/// same key minted is revoked with the old one.
#[test]
fn a_compromised_key_revokes_its_newer_cards_too() {
    let (victim, _attacker, trust) = two_agents();
    let (old_id, _old) = receipt(
        "agent_card.v1",
        serde_json::json!({ "agent": "agent://victim", "keyid": "key_victim" }),
        &victim,
    );
    let (_, rev) = receipt(
        "agent_card_revocation.v1",
        serde_json::json!({ "card": old_id, "keyid": "key_victim", "reason": "compromised" }),
        &victim,
    );
    let (new_id, new_card) = receipt(
        "agent_card.v1",
        serde_json::json!({ "agent": "agent://victim", "keyid": "key_victim", "capabilities": { "tools": ["db.drop"] } }),
        &victim,
    );
    let v = verify_resolution(&bundle(new_card.clone(), vec![rev.clone()]), &trust, NOW).unwrap();
    assert!(
        v.key_bound && v.revoked,
        "resolution: revoked={}",
        v.revoked
    );
    let p = verify_presentation(
        &presentation(&new_id, &new_card, &[rev]),
        &trust,
        None,
        NOW_UNIX,
    )
    .unwrap();
    assert!(
        p.revoked.is_some(),
        "presentation did not revoke the re-mint"
    );
}
