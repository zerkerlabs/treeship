//! Cross-SDK vectors for the resolution and presentation verifiers:
//! `tests/vectors/resolution/vectors.json`. The same file drives
//! `packages/verify-js/test/resolution-vectors.test.ts` through the wasm
//! build, so the Rust and JS verdicts cannot drift.
//!
//! Regenerate with `TREESHIP_WRITE_VECTORS=1 cargo test -p treeship-core
//! --test resolution_vectors`. Keys are derived from fixed seeds, so the file
//! is stable except for the signed_at timestamps inside the statements.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use treeship_core::attestation::envelope::{Envelope, Signature};
use treeship_core::attestation::{sign, Ed25519Signer, Signer};
use treeship_core::statements::{payload_type, ReceiptStatement};
use treeship_core::trust::{TrustRoot, TrustRootKind, TrustRootStore};
use treeship_core::verify::presentation::verify_presentation;
use treeship_core::verify::resolution::{verify_resolution, ResolutionBundle};

const NOW: &str = "2026-09-28T00:00:00Z";
const NOW_UNIX: u64 = 1_790_553_600;

fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vectors/resolution/vectors.json")
}

fn signer(key_id: &str, seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_bytes(key_id, &[seed; 32]).unwrap()
}

fn root_json(s: &Ed25519Signer, kind: &str, agent: Option<&str>, label: &str) -> serde_json::Value {
    let mut v = serde_json::json!({
        "key_id": s.key_id(),
        "public_key": format!("ed25519:{}", URL_SAFE_NO_PAD.encode(s.public_key_bytes())),
        "kind": kind,
        "label": label,
        "added_at": "",
    });
    if let Some(a) = agent {
        v["agent"] = serde_json::json!(a);
    }
    v
}

fn receipt(kind: &str, payload: serde_json::Value, s: &Ed25519Signer) -> (String, Envelope) {
    let mut stmt = ReceiptStatement::new("ship://ship_test", kind);
    stmt.timestamp = NOW.to_string();
    stmt.payload = Some(payload);
    let r = sign(&payload_type("receipt"), &stmt, s).unwrap();
    (r.artifact_id, r.envelope)
}

fn forged_first(mut env: Envelope, claimed: &str) -> Envelope {
    env.signatures.insert(
        0,
        Signature {
            keyid: claimed.into(),
            sig: URL_SAFE_NO_PAD.encode([7u8; 64]),
        },
    );
    env
}

fn case(
    name: &str,
    why: &str,
    trust: &[serde_json::Value],
    card_id: &str,
    card: &Envelope,
    revocations: &[Envelope],
    sig_ok: bool,
    key_bound: bool,
    revoked: bool,
) -> serde_json::Value {
    let key_bound_reason: Option<&str> = match (key_bound, name) {
        (true, _) => None,
        (false, "forged_first_signature") => Some("key_not_verified"),
        (false, "pinned_attacker_claims_victims_name") => Some("pin_scoped_to_other"),
        (false, "legacy_unscoped_pin") => Some("pin_unscoped"),
        (false, _) => None,
    };
    let revs: Vec<serde_json::Value> = revocations
        .iter()
        .map(|r| serde_json::to_value(r).unwrap())
        .collect();
    serde_json::json!({
        "name": name,
        "why": why,
        "now": NOW,
        "trust_roots": { "version": 1, "roots": trust },
        "bundle": {
            "agent": "agent://victim",
            "card": card,
            "certs": [],
            "revocations": revs,
        },
        "presentation": {
            "type": "treeship/presentation/v1",
            "agent": "agent://victim",
            "card": { "artifact_id": card_id, "envelope_json": serde_json::to_string(card).unwrap() },
            "certs": [],
            "revocations": revocations.iter().map(|r| serde_json::json!({
                "artifact_id": "art_rev", "envelope_json": serde_json::to_string(r).unwrap()
            })).collect::<Vec<_>>(),
        },
        "expected": { "sig_ok": sig_ok, "key_bound": key_bound, "revoked": revoked, "key_bound_reason": key_bound_reason },
    })
}

fn build() -> serde_json::Value {
    let victim = signer("key_victim", 1);
    let attacker = signer("key_attacker", 2);
    let both = vec![
        root_json(&victim, "agent_cert", Some("agent://victim"), ""),
        root_json(&attacker, "agent_cert", Some("agent://attacker"), ""),
    ];
    // A pin from before the `agent` field, with a label that is not an agent name.
    let legacy_unscoped = vec![root_json(&victim, "agent_cert", None, "the counterparty")];
    let payload = serde_json::json!({ "agent": "agent://victim", "keyid": "key_victim",
                                      "capabilities": { "tools": ["db.drop"] } });
    let (honest_id, honest) = receipt("agent_card.v1", payload.clone(), &victim);
    let (forged_id, forged) = receipt("agent_card.v1", payload, &attacker);
    let forged = forged_first(forged, "key_victim");
    let (_, forged_rev) = receipt(
        "agent_card_revocation.v1",
        serde_json::json!({ "card": honest_id, "reason": "pwned" }),
        &attacker,
    );
    let forged_rev = forged_first(forged_rev, "key_victim");
    let (_, other_rev) = receipt(
        "agent_card_revocation.v1",
        serde_json::json!({ "card": "art_some_old_card", "reason": "rotated" }),
        &victim,
    );
    let (_, own_rev) = receipt(
        "agent_card_revocation.v1",
        serde_json::json!({ "card": honest_id, "reason": "rotated" }),
        &victim,
    );
    // An attacker whose key is pinned (as agent://attacker) signs a card claiming the victim's name with its own key.
    let (claim_id, claim) = receipt(
        "agent_card.v1",
        serde_json::json!({ "agent": "agent://victim", "keyid": "key_attacker" }),
        &attacker,
    );
    // A compromised key: the old card revoked with reason "compromised", then the same key re-minted a newer card.
    let (_, compromised_rev) = receipt(
        "agent_card_revocation.v1",
        serde_json::json!({ "card": honest_id, "keyid": "key_victim", "reason": "compromised" }),
        &victim,
    );
    let (remint_id, remint) = receipt(
        "agent_card.v1",
        serde_json::json!({ "agent": "agent://victim", "keyid": "key_victim", "capabilities": { "tools": ["db.drop"] } }),
        &victim,
    );
    serde_json::json!({
        "schema": "treeship/resolution-vectors/v1",
        "cases": [
            case("honest_pinned_card", "the victim's own card, key pinned under agent_cert", &both, &honest_id, &honest, &[], true, true, false),
            case("forged_first_signature", "signed by another pinned party with a garbage first signature naming the victim's key: signed, but not the victim's", &both, &forged_id, &forged, &[], true, false, false),
            case("forged_revocation", "a revocation by another pinned party with a garbage first signature naming the victim's key is not the victim's", &both, &honest_id, &honest, std::slice::from_ref(&forged_rev), true, true, false),
            case("revocation_for_another_card", "the victim's own revocation of a different card leaves this one standing", &both, &honest_id, &honest, std::slice::from_ref(&other_rev), true, true, false),
            case("own_revocation", "the victim's revocation naming this card is honored", &both, &honest_id, &honest, std::slice::from_ref(&own_rev), true, true, true),
            case("pinned_attacker_claims_victims_name", "a key pinned as agent://attacker signs a card for agent://victim: verified, but bound to nobody", &both, &claim_id, &claim, &[], true, false, false),
            case("legacy_unscoped_pin", "the victim's key on a pin with no agent scope and a non-agent label binds no card", &legacy_unscoped, &honest_id, &honest, &[], true, false, false),
            case("compromised_key_remint", "a newer card from a key revoked as compromised is revoked with it", &both, &remint_id, &remint, std::slice::from_ref(&compromised_rev), true, true, true),
        ],
    })
}

#[test]
fn vectors_verify_the_same_way_in_rust() {
    let path = vectors_path();
    if std::env::var_os("TREESHIP_WRITE_VECTORS").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(&build()).unwrap()).unwrap();
    }
    let doc: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for c in doc["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let roots: Vec<TrustRoot> = c["trust_roots"]["roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| TrustRoot {
                key_id: r["key_id"].as_str().unwrap().into(),
                public_key: r["public_key"].as_str().unwrap().into(),
                kind: match r["kind"].as_str().unwrap() {
                    "agent_cert" => TrustRootKind::AgentCert,
                    "revoker" => TrustRootKind::Revoker,
                    _ => TrustRootKind::CertIssuer,
                },
                agent: r["agent"].as_str().map(str::to_string),
                label: r["label"].as_str().unwrap_or("").to_string(),
                added_at: String::new(),
            })
            .collect();
        let trust = TrustRootStore::with_roots(roots);
        let bundle = ResolutionBundle {
            agent: c["bundle"]["agent"].as_str().unwrap().into(),
            card: serde_json::from_value(c["bundle"]["card"].clone()).unwrap(),
            certs: vec![],
            revocations: serde_json::from_value(c["bundle"]["revocations"].clone()).unwrap(),
        };
        let v = verify_resolution(&bundle, &trust, NOW).unwrap();
        let e = &c["expected"];
        assert_eq!(v.sig_ok, e["sig_ok"], "{name}: resolution sig_ok");
        assert_eq!(v.key_bound, e["key_bound"], "{name}: resolution key_bound");
        assert_eq!(v.revoked, e["revoked"], "{name}: resolution revoked");
        if let Some(r) = e["key_bound_reason"].as_str() {
            assert_eq!(
                v.key_bound_reason.as_deref(),
                Some(r),
                "{name}: resolution key_bound_reason"
            );
        }
        let p = verify_presentation(&c["presentation"], &trust, None, NOW_UNIX).unwrap();
        assert_eq!(p.sig_ok, e["sig_ok"], "{name}: presentation sig_ok");
        assert_eq!(
            p.key_bound, e["key_bound"],
            "{name}: presentation key_bound"
        );
        assert_eq!(
            p.revoked.is_some(),
            e["revoked"],
            "{name}: presentation revoked"
        );
        if let Some(r) = e["key_bound_reason"].as_str() {
            assert_eq!(
                p.key_bound_reason.as_deref(),
                Some(r),
                "{name}: presentation key_bound_reason"
            );
        }
    }
}
