//! Building the two Layer 3 credentials the agent signs in autonomous mode:
//! L3a (payment mandate, for the network) and L3b (checkout mandate, for the
//! merchant), each a KB-SD-JWT bound to a recipient-specific presentation of
//! the L2 through `sd_hash`, and cross-bound to each other through
//! `transaction_id == checkout_hash == B64U(SHA-256(checkout_jwt))`.

use serde_json::Value;

use super::constraints::{check_constraints, CheckResult};
use super::jws::{sha256_b64u, AgentKey};
use super::mandate::{merchant_matches, L2View, VCT_CHECKOUT_FINAL, VCT_PAYMENT_FINAL};
use super::sd_jwt::{
    create_disclosure, delegate_ref, hash_disclosure, presentation_hash, selective_presentation,
    SdJwt,
};
use super::ViError;

/// One cart line as the merchant's checkout names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineItem {
    /// Product id or SKU, as the L2's acceptable items name it.
    pub id: String,
    pub quantity: u32,
}

/// Everything the agent decided, ready to be signed.
#[derive(Debug, Clone)]
pub struct L3Request {
    /// Shared by L3a and L3b; distinct from the L2 nonce.
    pub nonce: String,
    pub iat: u64,
    /// Recommended 300 s; the reference rejects more than 3600 s after `iat`.
    pub exp: u64,
    pub iss: Option<String>,
    /// Payment network URI (L3a `aud`).
    pub aud_network: String,
    /// Merchant URI (L3b `aud`).
    pub aud_merchant: String,
    /// The merchant being paid, as the L2 allowlist names it (`id`, `name`,
    /// `website`); matched against the L2's disclosed merchants.
    pub payee: Value,
    /// `{currency, amount}` in integer minor units.
    pub payment_amount: Value,
    /// The merchant-signed checkout JWT.
    pub checkout_jwt: String,
    pub line_items: Vec<LineItem>,
    /// Extra `agent_attestation` claim to carry on both halves.
    pub attestation: Option<Value>,
}

/// The signed pair plus the presentations their `sd_hash` values cover.
#[derive(Debug, Clone)]
pub struct L3Bundle {
    pub l3a: SdJwt,
    pub l3b: SdJwt,
    pub l2_payment_presentation: String,
    pub l2_checkout_presentation: String,
    pub checkout_hash: String,
    pub constraint_result: CheckResult,
}

/// Build the fulfillment the payment constraints are checked against.
pub fn payment_fulfillment(req: &L3Request, l2: &L2View) -> Value {
    serde_json::json!({
        "payment_amount": req.payment_amount,
        "payee": req.payee,
        "allowed_merchants": l2.allowed_payees(),
    })
}

/// Build the fulfillment the checkout constraints are checked against.
pub fn checkout_fulfillment(req: &L3Request, l2: &L2View) -> Value {
    serde_json::json!({
        "merchant": req.payee,
        "line_items": req.line_items.iter().map(|li| serde_json::json!({"id": li.id, "quantity": li.quantity})).collect::<Vec<_>>(),
        "allowed_merchants": l2.allowed_merchants(),
    })
}

/// Run both constraint sets. Never build an L3 whose values the mandate
/// does not cover: that is the whole point of the layer.
pub fn check_request(req: &L3Request, l2: &L2View) -> CheckResult {
    let mut pay = check_constraints(
        &l2.payment_constraints(),
        &payment_fulfillment(req, l2),
        l2.autonomous,
    );
    let chk = check_constraints(
        &l2.checkout_constraints(),
        &checkout_fulfillment(req, l2),
        l2.autonomous,
    );
    pay.satisfied &= chk.satisfied;
    pay.violations.extend(chk.violations);
    pay.checked.extend(chk.checked);
    pay.skipped.extend(chk.skipped);
    if req.exp <= req.iat || req.exp - req.iat > 3600 {
        pay.satisfied = false;
        pay.violations
            .push("L3 exp must be after iat and at most 3600 s later".into());
    }
    pay
}

/// Sign L3a and L3b. Fails when the mandate is not autonomous, when the
/// request violates it, or when the L2 lacks the disclosures a recipient's
/// presentation needs.
pub fn build_l3(l2: &L2View, key: &AgentKey, req: &L3Request) -> Result<L3Bundle, ViError> {
    if !l2.autonomous {
        return Err(ViError::Mandate(
            "L3 credentials exist only for autonomous (open) mandates".into(),
        ));
    }
    let payment = l2
        .payment
        .as_ref()
        .ok_or_else(|| ViError::Mandate("L2 has no payment mandate".into()))?;
    let checkout = l2
        .checkout
        .as_ref()
        .ok_or_else(|| ViError::Mandate("L2 has no checkout mandate".into()))?;
    if let Some(kid) = &l2.agent_kid {
        if *kid != key.kid {
            return Err(ViError::Mandate(format!(
                "L2 delegates to kid '{kid}', this key is '{}'",
                key.kid
            )));
        }
    }
    let ours = key.public_jwk();
    if ours.x != l2.agent_jwk.x || ours.y != l2.agent_jwk.y {
        return Err(ViError::Mandate("L2 cnf.jwk is not this key".into()));
    }
    let constraint_result = check_request(req, l2);
    if !constraint_result.satisfied {
        return Err(ViError::Mandate(format!(
            "request violates the mandate: {}",
            constraint_result.violations.join("; ")
        )));
    }

    let checkout_hash = sha256_b64u(req.checkout_jwt.as_bytes());
    let base = l2.base_jwt();

    // Recipient-specific L2 presentations. The merchant disclosure is the
    // payee's; the item disclosures are the cart's. Both must exist in the
    // L2 the agent was handed, or the credential cannot bind to them.
    let merchant_disc = l2.merchant_disclosure(&req.payee).ok_or_else(|| {
        ViError::Mandate("payee is not among the L2's disclosed merchants".into())
    })?;
    let mut item_discs: Vec<String> = Vec::new();
    for li in &req.line_items {
        let d = l2.item_disclosure(&li.id).ok_or_else(|| {
            ViError::Mandate(format!(
                "item {} is not among the L2's disclosed acceptable items",
                li.id
            ))
        })?;
        if !item_discs.contains(&d.disclosure) {
            item_discs.push(d.disclosure.clone());
        }
    }
    let mut pay_pres_discs = vec![payment.disclosure.clone(), merchant_disc.disclosure.clone()];
    pay_pres_discs.dedup();
    let l2_payment_presentation = selective_presentation(&base, &pay_pres_discs);
    let mut chk_pres_discs = vec![checkout.disclosure.clone()];
    chk_pres_discs.extend(item_discs);
    let l2_checkout_presentation = selective_presentation(&base, &chk_pres_discs);

    let payment_instrument = l2
        .payment_instrument()
        .ok_or_else(|| ViError::Mandate("L2 payment mandate has no payment_instrument".into()))?;

    // Resolve the payee to the L2's own disclosed merchant object so the
    // credential names exactly what the user authorized.
    let payee = l2
        .allowed_payees()
        .into_iter()
        .chain(l2.allowed_merchants())
        .find(|m| merchant_matches(m, &req.payee))
        .unwrap_or_else(|| req.payee.clone());

    let header = serde_json::json!({"alg": "ES256", "typ": "kb-sd-jwt", "kid": key.kid});

    // L3a
    let final_merchant = create_disclosure(None, &payee, None);
    let final_payment = create_disclosure(
        None,
        &serde_json::json!({
            "vct": VCT_PAYMENT_FINAL,
            "transaction_id": checkout_hash,
            "payee": payee,
            "payment_amount": req.payment_amount,
            "payment_instrument": payment_instrument,
        }),
        None,
    );
    let mut pa = serde_json::json!({
        "nonce": req.nonce,
        "aud": req.aud_network,
        "sd_hash": presentation_hash(&l2_payment_presentation),
        "iat": req.iat,
        "exp": req.exp,
        "delegate_payload": [delegate_ref(&hash_disclosure(&final_merchant)), delegate_ref(&hash_disclosure(&final_payment))],
        "_sd_alg": "sha-256",
    });
    if let Some(iss) = &req.iss {
        pa["iss"] = Value::String(iss.clone());
    }
    if let Some(att) = &req.attestation {
        pa["agent_attestation"] = att.clone();
    }
    let l3a = SdJwt::create(&header, &pa, vec![final_merchant, final_payment], key);

    // L3b
    let mut final_checkout_v = serde_json::json!({
        "vct": VCT_CHECKOUT_FINAL,
        "checkout_jwt": req.checkout_jwt,
        "checkout_hash": checkout_hash,
    });
    if !req.line_items.is_empty() {
        final_checkout_v["line_items"] = Value::Array(
            req.line_items
                .iter()
                .map(|li| serde_json::json!({"id": li.id, "quantity": li.quantity}))
                .collect(),
        );
    }
    let final_checkout = create_disclosure(None, &final_checkout_v, None);
    let mut pb = serde_json::json!({
        "nonce": req.nonce,
        "aud": req.aud_merchant,
        "sd_hash": presentation_hash(&l2_checkout_presentation),
        "iat": req.iat,
        "exp": req.exp,
        "delegate_payload": [delegate_ref(&hash_disclosure(&final_checkout))],
        "_sd_alg": "sha-256",
    });
    if let Some(iss) = &req.iss {
        pb["iss"] = Value::String(iss.clone());
    }
    if let Some(att) = &req.attestation {
        pb["agent_attestation"] = att.clone();
    }
    let l3b = SdJwt::create(&header, &pb, vec![final_checkout], key);

    Ok(L3Bundle {
        l3a,
        l3b,
        l2_payment_presentation,
        l2_checkout_presentation,
        checkout_hash,
        constraint_result,
    })
}
