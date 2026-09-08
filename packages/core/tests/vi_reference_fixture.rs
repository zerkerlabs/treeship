//! Byte-level interop with the Verifiable Intent reference SDK.
//!
//! `fixtures/vi/reference-v0.1.json` was produced by the reference SDK
//! (agent-intent/verifiable-intent @ 356c296) with its deterministic demo
//! keys: an L1 issuer credential, an autonomous L2 mandate binding the demo
//! agent key, and a merchant checkout JWT. These tests parse what the
//! reference signed, re-serialize it byte-identically, verify it, and build
//! an L3 pair from it the way `treeship vi attest` does. The Python side of
//! the same contract (the reference verifying what treeship signed) lives in
//! `tests/vi-interop`.

use serde_json::Value;
use treeship_core::attestation::Ed25519Signer;
use treeship_core::vi::{
    build_attestation_claim, build_l3, jws::sha256_b64u, l3::check_request, verify_l2_against_l1,
    verify_l3, AgentKey, AttestationStatement, Jwk, L2View, L3Request, LineItem, SdJwt,
};

fn fixture() -> Value {
    let raw = include_str!("fixtures/vi/reference-v0.1.json");
    serde_json::from_str(raw).expect("fixture json")
}

fn request(fx: &Value, amount: i64, item: &str) -> L3Request {
    L3Request {
        nonce: "n-fixture".into(),
        iat: 1_757_000_000,
        exp: 1_757_000_300,
        iss: Some("https://agent.example.com".into()),
        aud_network: "https://www.mastercard.com".into(),
        aud_merchant: "https://tennis-warehouse.com".into(),
        payee: fx["merchants"][0].clone(),
        payment_amount: serde_json::json!({"currency": "USD", "amount": amount}),
        checkout_jwt: fx["checkout_jwt"].as_str().unwrap().to_string(),
        line_items: vec![LineItem {
            id: item.into(),
            quantity: 1,
        }],
        attestation: None,
    }
}

#[test]
fn reference_tokens_reserialize_byte_identically() {
    let fx = fixture();
    for k in ["l1", "l2"] {
        let raw = fx[k].as_str().unwrap();
        let parsed = SdJwt::parse(raw).unwrap();
        assert_eq!(
            parsed.serialize(),
            raw,
            "{k} must round-trip exactly (sd_hash depends on it)"
        );
    }
}

#[test]
fn l2_verifies_against_l1_and_the_issuer() {
    let fx = fixture();
    let l1 = SdJwt::parse(fx["l1"].as_str().unwrap()).unwrap();
    let l2 = SdJwt::parse(fx["l2"].as_str().unwrap()).unwrap();
    let issuer = Jwk::from_value(&fx["issuer_public_jwk"]).unwrap();
    let r = verify_l2_against_l1(&l1, &l2, Some(&issuer), 1_757_000_100);
    assert!(
        r.ok(),
        "{:?}",
        r.checks.iter().filter(|c| !c.pass).collect::<Vec<_>>()
    );
    let view = L2View::from_sd_jwt(l2).unwrap();
    assert!(view.autonomous);
    assert_eq!(view.agent_kid.as_deref(), Some("agent-key-1"));
    // The reference demo mandate allows more than one merchant; the one the
    // fixture's checkout names must be among them, resolved inline.
    assert!(view
        .allowed_merchants()
        .iter()
        .any(|m| m["id"] == "merchant-uuid-1"));
    assert!(view
        .allowed_payees()
        .iter()
        .any(|m| m["id"] == "merchant-uuid-1"));
    assert!(
        view.allowed_merchants()
            .iter()
            .all(|m| m.get("...").is_none()),
        "refs must be inlined"
    );
    assert!(view.item_disclosure("BAB86345").is_some());
    assert_eq!(
        view.payment_instrument().unwrap()["id"],
        fx["payment_instrument"]["id"]
    );
}

#[test]
fn l3_pair_builds_verifies_and_carries_the_attestation() {
    let fx = fixture();
    let l2 = L2View::parse(fx["l2"].as_str().unwrap()).unwrap();
    let key = AgentKey::from_private_jwk(&fx["agent_private_jwk"]).unwrap();
    assert_eq!(key.kid, "agent-key-1");

    let signer = Ed25519Signer::generate("key_test").unwrap();
    let checkout_hash = sha256_b64u(fx["checkout_jwt"].as_str().unwrap().as_bytes());
    let stmt = AttestationStatement::new(
        "agent://shopping",
        Some("ssn_fixture".into()),
        "art_head",
        "mroot_00",
        3,
        None,
        &sha256_b64u(l2.base_jwt().as_bytes()),
        &checkout_hash,
        "2026-09-08T00:00:00Z",
    );
    let (claim, _) = build_attestation_claim(&stmt, &signer).unwrap();
    let mut req = request(&fx, 27_999, "BAB86345");
    req.attestation = Some(serde_json::to_value(&claim).unwrap());

    let bundle = build_l3(&l2, &key, &req).unwrap();
    assert_eq!(bundle.checkout_hash, checkout_hash);
    assert!(bundle.l2_payment_presentation.starts_with(&l2.base_jwt()));

    let r = verify_l3(
        &l2,
        Some(&bundle.l3a),
        Some(&bundle.l3b),
        Some(&bundle.l2_payment_presentation),
        Some(&bundle.l2_checkout_presentation),
        1_757_000_100,
    );
    assert!(
        r.ok(),
        "{:?}",
        r.checks.iter().filter(|c| !c.pass).collect::<Vec<_>>()
    );
    let att = r.attestation.expect("attestation summary");
    assert_eq!(att.chain_head, "art_head");
    assert_eq!(att.transaction_id, checkout_hash);
    assert_eq!(r.checkout_hash.as_deref(), Some(checkout_hash.as_str()));

    // Reparse from the wire and verify again: what leaves the process is what verifies.
    let l3a = SdJwt::parse(&bundle.l3a.serialize()).unwrap();
    let l3b = SdJwt::parse(&bundle.l3b.serialize()).unwrap();
    let r2 = verify_l3(
        &l2,
        Some(&l3a),
        Some(&l3b),
        Some(&bundle.l2_payment_presentation),
        Some(&bundle.l2_checkout_presentation),
        1_757_000_100,
    );
    assert!(r2.ok());
}

#[test]
fn requests_outside_the_mandate_are_refused_before_signing() {
    let fx = fixture();
    let l2 = L2View::parse(fx["l2"].as_str().unwrap()).unwrap();
    let key = AgentKey::from_private_jwk(&fx["agent_private_jwk"]).unwrap();
    let over = request(&fx, 40_001, "BAB86345");
    let cr = check_request(&over, &l2);
    assert!(!cr.satisfied);
    assert!(cr.violations.iter().any(|v| v.contains("exceeds maximum")));
    assert!(build_l3(&l2, &key, &over).is_err());
    let wrong_item = request(&fx, 27_999, "ZX-9999");
    assert!(build_l3(&l2, &key, &wrong_item).is_err());
    let other_key = AgentKey::generate();
    assert!(
        build_l3(&l2, &other_key, &request(&fx, 27_999, "BAB86345")).is_err(),
        "a key the L2 did not delegate to cannot sign"
    );
}

#[test]
fn tampering_with_a_signed_half_fails_verification() {
    let fx = fixture();
    let l2 = L2View::parse(fx["l2"].as_str().unwrap()).unwrap();
    let key = AgentKey::from_private_jwk(&fx["agent_private_jwk"]).unwrap();
    let bundle = build_l3(&l2, &key, &request(&fx, 27_999, "BAB86345")).unwrap();
    // Swap the merchant presentation for the checkout one: sd_hash no longer binds.
    let r = verify_l3(
        &l2,
        Some(&bundle.l3a),
        None,
        Some(&bundle.l2_checkout_presentation),
        None,
        1_757_000_100,
    );
    assert!(!r.ok());
    assert!(r.checks.iter().any(|c| c.name == "l3a_sd_hash" && !c.pass));
    // Edit the payload: signature fails.
    let ser = bundle.l3b.serialize();
    let (jwt, rest) = ser.split_once('~').unwrap();
    let mut parts: Vec<&str> = jwt.split('.').collect();
    let payload = treeship_core::vi::jws::b64u_decode(parts[1]).unwrap();
    let edited = String::from_utf8(payload)
        .unwrap()
        .replace("tennis-warehouse", "evil");
    let p2 = treeship_core::vi::jws::b64u(edited.as_bytes());
    parts[1] = &p2;
    let tampered = format!("{}~{}", parts.join("."), rest);
    let l3b = SdJwt::parse(&tampered).unwrap();
    let r = verify_l3(
        &l2,
        None,
        Some(&l3b),
        None,
        Some(&bundle.l2_checkout_presentation),
        1_757_000_100,
    );
    assert!(r
        .checks
        .iter()
        .any(|c| c.name == "l3b_signature" && !c.pass));
}
