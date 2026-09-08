//! Verifying Layer 3 credentials against their Layer 2, and Layer 2 against
//! Layer 1, with the same checks the reference `verify_chain` runs, plus the
//! Treeship attestation claim when present.

use serde_json::Value;

use super::attestation::{verify_attestation_claim, AttestationVerified, ATTESTATION_SCHEME};
use super::constraints::check_constraints;
use super::jws::{sha256_b64u, Jwk};
use super::mandate::{L2View, VCT_CHECKOUT_FINAL, VCT_PAYMENT_FINAL};
use super::sd_jwt::{presentation_hash, SdJwt};
use super::ViError;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Check {
    pub name: String,
    pub pass: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Report {
    pub checks: Vec<Check>,
    /// Set when an attestation claim was present and verified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<AttestationSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkout_hash: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AttestationSummary {
    pub artifact_id: String,
    pub key_id: String,
    pub public_key: String,
    pub session: Option<String>,
    pub chain_head: String,
    pub checkpoint: String,
    pub approval_use: Option<String>,
    pub mandate_digest: String,
    pub transaction_id: String,
    pub chain_length: u64,
    pub timestamp: String,
    pub actor: String,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.checks.iter().all(|c| c.pass)
    }
    pub fn passed(&self) -> usize {
        self.checks.iter().filter(|c| c.pass).count()
    }
    pub fn failed(&self) -> usize {
        self.checks.len() - self.passed()
    }
    fn push(&mut self, name: &str, pass: bool, detail: impl Into<String>) -> bool {
        self.checks.push(Check {
            name: name.into(),
            pass,
            detail: detail.into(),
        });
        pass
    }
}

fn header_ok(h: &Value, expected_typ: &str) -> Result<(), String> {
    if h.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err(format!(
            "alg must be ES256, got {}",
            h.get("alg").cloned().unwrap_or(Value::Null)
        ));
    }
    if h.get("typ").and_then(Value::as_str) != Some(expected_typ) {
        return Err(format!(
            "typ must be '{expected_typ}', got {}",
            h.get("typ").cloned().unwrap_or(Value::Null)
        ));
    }
    Ok(())
}

/// Verify the L2 issuer signature with the user key L1 binds, and L2's
/// `sd_hash` against the L1 serialization. `issuer_jwk` verifies L1 itself.
pub fn verify_l2_against_l1(l1: &SdJwt, l2: &SdJwt, issuer_jwk: Option<&Jwk>, now: u64) -> Report {
    let mut r = Report::default();
    match issuer_jwk {
        Some(jwk) => {
            r.push(
                "l1_signature",
                l1.verify_signature(jwk).is_ok(),
                "L1 issuer signature (ES256)",
            );
        }
        None => {
            r.push("l1_signature", true, "not checked: no issuer key given");
        }
    }
    r.push(
        "l1_header",
        header_ok(l1.header(), "sd+jwt").is_ok(),
        "L1 header alg/typ",
    );
    let l1_exp = l1.payload().get("exp").and_then(Value::as_u64);
    r.push(
        "l1_not_expired",
        l1_exp.map(|e| now <= e + 300).unwrap_or(true),
        format!(
            "exp {}",
            l1_exp
                .map(|e| e.to_string())
                .unwrap_or_else(|| "absent".into())
        ),
    );
    let user_jwk = l1
        .payload()
        .get("cnf")
        .and_then(|c| c.get("jwk"))
        .and_then(|j| Jwk::from_value(j).ok());
    match user_jwk {
        Some(jwk) => {
            r.push(
                "l2_signature",
                l2.verify_signature(&jwk).is_ok(),
                "L2 signed by the user key L1 binds (cnf.jwk)",
            );
        }
        None => {
            r.push("l2_signature", false, "L1 has no cnf.jwk to verify L2 with");
        }
    }
    let expected = sha256_b64u(l1.serialize().as_bytes());
    let actual = l2
        .payload()
        .get("sd_hash")
        .and_then(Value::as_str)
        .unwrap_or("");
    r.push(
        "l2_sd_hash",
        actual == expected,
        "L2 sd_hash binds the presented L1",
    );
    r
}

/// Verify L3a and/or L3b against `l2`. The presentations are the exact L2
/// strings each recipient was handed; when absent the full L2 serialization
/// is used, as the reference does. `now` is Unix seconds.
pub fn verify_l3(
    l2: &L2View,
    l3a: Option<&SdJwt>,
    l3b: Option<&SdJwt>,
    l2_payment_presentation: Option<&str>,
    l2_checkout_presentation: Option<&str>,
    now: u64,
) -> Report {
    let mut r = Report::default();
    r.push(
        "l2_mode",
        l2.autonomous,
        if l2.autonomous {
            "autonomous (open) mandates"
        } else {
            "not autonomous: L3 has no meaning"
        },
    );
    r.push(
        "l2_header",
        header_ok(l2.sd_jwt.header(), "kb-sd-jwt+kb").is_ok(),
        "L2 header alg/typ",
    );
    if !l2.autonomous {
        return r;
    }
    let full = l2.sd_jwt.serialize();
    let agent_jwk = &l2.agent_jwk;

    let mut l3a_claims: Option<Value> = None;
    let mut l3b_claims: Option<Value> = None;
    let mut attestation: Option<AttestationVerified> = None;

    for (l3, label, pres, pair_disc, required_vct) in [
        (
            l3a,
            "l3a",
            l2_payment_presentation,
            l2.payment.as_ref().map(|m| m.disclosure.clone()),
            VCT_PAYMENT_FINAL,
        ),
        (
            l3b,
            "l3b",
            l2_checkout_presentation,
            l2.checkout.as_ref().map(|m| m.disclosure.clone()),
            VCT_CHECKOUT_FINAL,
        ),
    ] {
        let Some(l3) = l3 else { continue };
        let p = l3.payload();
        r.push(
            &format!("{label}_no_cnf"),
            p.get("cnf").is_none(),
            "terminal delegation: no cnf",
        );
        r.push(
            &format!("{label}_signature"),
            l3.verify_signature(agent_jwk).is_ok(),
            "signed by the agent key L2 delegates to (cnf.jwk)",
        );
        r.push(
            &format!("{label}_header"),
            header_ok(l3.header(), "kb-sd-jwt").is_ok(),
            "header alg/typ",
        );
        let kid = l3.header().get("kid").and_then(Value::as_str).unwrap_or("");
        let kid_ok = !kid.is_empty() && l2.agent_kid.as_deref().map(|k| k == kid).unwrap_or(true);
        r.push(
            &format!("{label}_kid"),
            kid_ok,
            format!("header kid '{kid}' matches L2 cnf.jwk.kid"),
        );
        let pres_str = pres.map(str::to_string).unwrap_or_else(|| full.clone());
        let sd_ok =
            p.get("sd_hash").and_then(Value::as_str) == Some(presentation_hash(&pres_str).as_str());
        r.push(
            &format!("{label}_sd_hash"),
            sd_ok,
            "sd_hash binds the L2 presentation this recipient saw",
        );
        if let Some(pd) = &pair_disc {
            let included = pres_str.split('~').any(|s| s == pd);
            r.push(
                &format!("{label}_pair_binding"),
                included,
                "presentation includes this mandate's disclosure",
            );
        }
        let sd_alg_ok = p.get("_sd_alg").map(|v| v == "sha-256").unwrap_or(true);
        r.push(&format!("{label}_sd_alg"), sd_alg_ok, "_sd_alg sha-256");
        let iat = p.get("iat").and_then(Value::as_u64);
        let exp = p.get("exp").and_then(Value::as_u64);
        r.push(
            &format!("{label}_iat"),
            iat.map(|i| i <= now + 300).unwrap_or(true),
            "iat not in the future",
        );
        r.push(
            &format!("{label}_exp"),
            exp.map(|e| now <= e + 300).unwrap_or(true),
            format!(
                "not expired (exp {})",
                exp.map(|e| e.to_string())
                    .unwrap_or_else(|| "absent".into())
            ),
        );
        if let (Some(i), Some(e)) = (iat, exp) {
            r.push(
                &format!("{label}_lifetime"),
                e >= i && e - i <= 3600,
                "exp at most 1 hour after iat",
            );
        }
        let claims = l3.resolve();
        let delegates = claims
            .get("delegate_payload")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mandate = delegates
            .iter()
            .find(|d| d.get("vct").and_then(Value::as_str) == Some(required_vct))
            .cloned();
        r.push(
            &format!("{label}_mandate_present"),
            mandate.is_some(),
            format!("carries a {required_vct} disclosure"),
        );
        if let Some(m) = &mandate {
            if required_vct == VCT_PAYMENT_FINAL {
                let tid = m
                    .get("transaction_id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty());
                r.push(
                    "l3a_transaction_id",
                    tid.is_some(),
                    "transaction_id present",
                );
                let payee_ok = m
                    .get("payee")
                    .and_then(Value::as_object)
                    .map(|p| {
                        p.get("name")
                            .and_then(Value::as_str)
                            .filter(|s| !s.trim().is_empty())
                            .is_some()
                            && p.get("website")
                                .and_then(Value::as_str)
                                .filter(|s| !s.trim().is_empty())
                                .is_some()
                    })
                    .unwrap_or(false);
                r.push("l3a_payee", payee_ok, "payee has name and website");
                let amount_ok = m
                    .get("payment_amount")
                    .and_then(Value::as_object)
                    .map(|a| {
                        a.get("currency")
                            .and_then(Value::as_str)
                            .filter(|s| !s.trim().is_empty())
                            .is_some()
                            && a.get("amount")
                                .map(|x| x.is_i64() || x.is_u64())
                                .unwrap_or(false)
                    })
                    .unwrap_or(false);
                r.push(
                    "l3a_payment_amount",
                    amount_ok,
                    "payment_amount has currency and integer amount",
                );
                let pi = m.get("payment_instrument").cloned().unwrap_or(Value::Null);
                let pi_ok = pi
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .is_some()
                    && pi
                        .get("type")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .is_some();
                r.push(
                    "l3a_payment_instrument",
                    pi_ok,
                    "payment_instrument has id and type",
                );
                if let Some(l2pi) = l2.payment_instrument() {
                    let same = pi.get("id") == l2pi.get("id") && pi.get("type") == l2pi.get("type");
                    r.push(
                        "l3a_instrument_matches_l2",
                        same,
                        "payment_instrument is the one L2 authorized",
                    );
                }
                let fulfillment = serde_json::json!({
                    "payment_amount": m.get("payment_amount").cloned().unwrap_or(Value::Null),
                    "payee": m.get("payee").cloned().unwrap_or(Value::Null),
                    "allowed_merchants": l2.allowed_payees(),
                });
                let cr = check_constraints(&l2.payment_constraints(), &fulfillment, true);
                r.push(
                    "l3a_constraints",
                    cr.satisfied,
                    if cr.satisfied {
                        format!("checked: {}", cr.checked.join(", "))
                    } else {
                        cr.violations.join("; ")
                    },
                );
            } else {
                let cj = m
                    .get("checkout_jwt")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty());
                let ch = m
                    .get("checkout_hash")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty());
                r.push(
                    "l3b_checkout_fields",
                    cj.is_some() && ch.is_some(),
                    "checkout_jwt and checkout_hash present",
                );
                if let (Some(cj), Some(ch)) = (cj, ch) {
                    r.push(
                        "l3b_checkout_hash",
                        sha256_b64u(cj.as_bytes()) == ch,
                        "checkout_hash = B64U(SHA-256(checkout_jwt))",
                    );
                    r.checkout_hash = Some(ch.to_string());
                }
                if let Some(items) = m.get("line_items").and_then(Value::as_array) {
                    let merchant = l3a_payee_from(&l3a_claims).unwrap_or(Value::Null);
                    let fulfillment = serde_json::json!({
                        "merchant": merchant,
                        "line_items": items,
                        "allowed_merchants": l2.allowed_merchants(),
                    });
                    let constraints: Vec<Value> = l2
                        .checkout_constraints()
                        .into_iter()
                        .filter(|c| {
                            merchant.is_object()
                                || c.get("type").and_then(Value::as_str)
                                    != Some("mandate.checkout.allowed_merchants")
                        })
                        .collect();
                    let cr = check_constraints(&constraints, &fulfillment, true);
                    r.push(
                        "l3b_constraints",
                        cr.satisfied,
                        if cr.satisfied {
                            format!("checked: {}", cr.checked.join(", "))
                        } else {
                            cr.violations.join("; ")
                        },
                    );
                }
            }
        }
        if let Some(att) = p.get("agent_attestation") {
            let ty = att.get("type").and_then(Value::as_str).unwrap_or("");
            if ty == ATTESTATION_SCHEME {
                match verify_attestation_claim(att) {
                    Ok(v) => {
                        r.push(
                            &format!("{label}_attestation"),
                            true,
                            format!(
                                "Treeship attestation {} signed by {}",
                                v.artifact_id, v.key_id
                            ),
                        );
                        if attestation
                            .as_ref()
                            .map(|a| a.artifact_id != v.artifact_id)
                            .unwrap_or(false)
                        {
                            r.push(
                                "attestation_same_on_both",
                                false,
                                "L3a and L3b carry different attestations",
                            );
                        }
                        attestation = Some(v);
                    }
                    Err(e) => {
                        r.push(&format!("{label}_attestation"), false, e.to_string());
                    }
                }
            } else {
                r.push(
                    &format!("{label}_attestation"),
                    true,
                    format!("unknown attestation scheme '{ty}' ignored, as the spec requires"),
                );
            }
        }
        if required_vct == VCT_PAYMENT_FINAL {
            l3a_claims = Some(claims);
        } else {
            l3b_claims = Some(claims);
        }
    }

    if let (Some(a), Some(b)) = (&l3a_claims, &l3b_claims) {
        let tid = find_delegate(a, VCT_PAYMENT_FINAL).and_then(|m| {
            m.get("transaction_id")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
        let ch = find_delegate(b, VCT_CHECKOUT_FINAL).and_then(|m| {
            m.get("checkout_hash")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
        r.push(
            "l3_cross_reference",
            tid.is_some() && tid == ch,
            "L3a transaction_id == L3b checkout_hash",
        );
        let na = a.get("nonce");
        let nb = b.get("nonce");
        r.push(
            "l3_shared_nonce",
            na.is_some() && na == nb,
            "both halves carry the same nonce",
        );
    }

    if let Some(v) = attestation {
        let s = &v.statement;
        let md_ok = s.mandate_digest == sha256_b64u(l2.base_jwt().as_bytes());
        r.push(
            "attestation_mandate_digest",
            md_ok,
            "attestation names this L2 (SHA-256 of its base JWT)",
        );
        if let Some(ch) = &r.checkout_hash {
            r.push(
                "attestation_transaction_id",
                &s.transaction_id == ch,
                "attestation names this transaction",
            );
        }
        r.attestation = Some(AttestationSummary {
            artifact_id: v.artifact_id,
            key_id: v.key_id,
            public_key: v.public_key,
            session: s.session.clone(),
            chain_head: s.chain_head.clone(),
            checkpoint: s.checkpoint.clone(),
            approval_use: s.approval_use.clone(),
            mandate_digest: s.mandate_digest.clone(),
            transaction_id: s.transaction_id.clone(),
            chain_length: s.chain_length,
            timestamp: s.timestamp.clone(),
            actor: s.actor.clone(),
        });
    }
    r
}

fn find_delegate(claims: &Value, vct: &str) -> Option<Value> {
    claims
        .get("delegate_payload")
        .and_then(Value::as_array)
        .and_then(|a| {
            a.iter()
                .find(|d| d.get("vct").and_then(Value::as_str) == Some(vct))
                .cloned()
        })
}

fn l3a_payee_from(l3a_claims: &Option<Value>) -> Option<Value> {
    l3a_claims
        .as_ref()
        .and_then(|c| find_delegate(c, VCT_PAYMENT_FINAL))
        .and_then(|m| m.get("payee").cloned())
}

impl From<ViError> for Check {
    fn from(e: ViError) -> Self {
        Check {
            name: "error".into(),
            pass: false,
            detail: e.to_string(),
        }
    }
}
