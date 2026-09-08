//! A parsed view of a Layer 2 mandate: what an agent needs to know before it
//! acts, and what a verifier needs to check an L3 against.

use serde_json::Value;

use super::jws::Jwk;
use super::sd_jwt::SdJwt;
use super::ViError;

pub const VCT_CHECKOUT_OPEN: &str = "mandate.checkout.open.1";
pub const VCT_PAYMENT_OPEN: &str = "mandate.payment.open.1";
pub const VCT_CHECKOUT_FINAL: &str = "mandate.checkout.1";
pub const VCT_PAYMENT_FINAL: &str = "mandate.payment.1";

/// One mandate disclosure inside an L2: the disclosure string (needed for
/// selective presentations and the reference binding) and its value.
#[derive(Debug, Clone)]
pub struct MandateDisc {
    pub disclosure: String,
    pub hash: String,
    pub value: Value,
}

impl MandateDisc {
    pub fn vct(&self) -> &str {
        self.value.get("vct").and_then(Value::as_str).unwrap_or("")
    }

    pub fn constraints(&self) -> Vec<Value> {
        self.value
            .get("constraints")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }
}

/// The L2 mandate as the agent sees it.
#[derive(Debug, Clone)]
pub struct L2View {
    pub sd_jwt: SdJwt,
    /// The agent key the user delegated to (`cnf.jwk` of the open mandates).
    pub agent_jwk: Jwk,
    /// `cnf.jwk.kid`, which every L3 header must repeat.
    pub agent_kid: Option<String>,
    pub checkout: Option<MandateDisc>,
    pub payment: Option<MandateDisc>,
    /// Every other disclosure (merchants, items), by hash.
    pub standalone: Vec<MandateDisc>,
    pub autonomous: bool,
}

impl L2View {
    /// Parse a serialized L2 (full or partial presentation).
    pub fn parse(serialized: &str) -> Result<Self, ViError> {
        Self::from_sd_jwt(SdJwt::parse(serialized)?)
    }

    pub fn from_sd_jwt(sd_jwt: SdJwt) -> Result<Self, ViError> {
        let payload = sd_jwt.payload();
        if !payload.is_object() {
            return Err(ViError::Malformed(
                "L2 payload must be a JSON object".into(),
            ));
        }
        let refs: Vec<String> = payload
            .get("delegate_payload")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|i| i.get("...").and_then(Value::as_str))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        let mut checkout = None;
        let mut payment = None;
        let mut standalone = Vec::new();
        for (disclosure, hash, value) in sd_jwt.disclosure_entries() {
            let md = MandateDisc {
                disclosure,
                hash: hash.clone(),
                value,
            };
            let vct = md.vct().to_string();
            let is_mandate_ref = refs.contains(&hash);
            match vct.as_str() {
                VCT_CHECKOUT_OPEN | VCT_CHECKOUT_FINAL if is_mandate_ref => {
                    if checkout.is_some() {
                        return Err(ViError::Mandate("L2 carries more than one checkout mandate; multi-pair mandates are not supported".into()));
                    }
                    checkout = Some(md);
                }
                VCT_PAYMENT_OPEN | VCT_PAYMENT_FINAL if is_mandate_ref => {
                    if payment.is_some() {
                        return Err(ViError::Mandate("L2 carries more than one payment mandate; multi-pair mandates are not supported".into()));
                    }
                    payment = Some(md);
                }
                _ => standalone.push(md),
            }
        }
        if checkout.is_none() && payment.is_none() {
            return Err(ViError::Mandate(
                "L2 delegate_payload resolved zero mandate disclosures".into(),
            ));
        }
        let autonomous = [&checkout, &payment]
            .iter()
            .filter_map(|m| m.as_ref())
            .any(|m| m.vct() == VCT_CHECKOUT_OPEN || m.vct() == VCT_PAYMENT_OPEN);

        let mut agent_jwk: Option<Jwk> = None;
        for m in [&checkout, &payment].into_iter().flatten() {
            if let Some(jwk_v) = m.value.get("cnf").and_then(|c| c.get("jwk")) {
                let jwk = Jwk::from_value(jwk_v)?;
                if let Some(prev) = &agent_jwk {
                    if prev.x != jwk.x || prev.y != jwk.y || prev.kid != jwk.kid {
                        return Err(ViError::Mandate(
                            "L2 mandate cnf.jwk values differ between checkout and payment".into(),
                        ));
                    }
                }
                agent_jwk = Some(jwk);
            }
        }
        let agent_jwk = match agent_jwk {
            Some(j) => j,
            None if autonomous => {
                return Err(ViError::Mandate(
                    "L2 open mandates carry no cnf.jwk (no agent delegation)".into(),
                ))
            }
            None => Jwk {
                kty: "EC".into(),
                crv: "P-256".into(),
                x: String::new(),
                y: String::new(),
                kid: None,
            },
        };
        let agent_kid = agent_jwk.kid.clone();
        Ok(Self {
            sd_jwt,
            agent_jwk,
            agent_kid,
            checkout,
            payment,
            standalone,
            autonomous,
        })
    }

    pub fn base_jwt(&self) -> String {
        self.sd_jwt.base_jwt()
    }

    /// Replace `{"...": hash}` references inside a constraint list with the
    /// disclosed values, so the checker sees inline merchants and items.
    pub fn inline_refs(&self, v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                if let Some(h) = m.get("...").and_then(Value::as_str) {
                    if m.len() == 1 {
                        if let Some(d) = self.standalone.iter().find(|d| d.hash == h) {
                            return d.value.clone();
                        }
                    }
                }
                Value::Object(
                    m.iter()
                        .map(|(k, x)| (k.clone(), self.inline_refs(x)))
                        .collect(),
                )
            }
            Value::Array(a) => Value::Array(a.iter().map(|x| self.inline_refs(x)).collect()),
            other => other.clone(),
        }
    }

    pub fn checkout_constraints(&self) -> Vec<Value> {
        self.checkout
            .as_ref()
            .map(|c| {
                c.constraints()
                    .iter()
                    .map(|x| self.inline_refs(x))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn payment_constraints(&self) -> Vec<Value> {
        self.payment
            .as_ref()
            .map(|p| {
                p.constraints()
                    .iter()
                    .map(|x| self.inline_refs(x))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The payment instrument the user authorized; L3a must repeat it.
    pub fn payment_instrument(&self) -> Option<Value> {
        self.payment
            .as_ref()
            .and_then(|p| p.value.get("payment_instrument").cloned())
    }

    /// Merchants the checkout mandate allows, inlined.
    pub fn allowed_merchants(&self) -> Vec<Value> {
        self.checkout_constraints()
            .iter()
            .filter(|c| {
                c.get("type").and_then(Value::as_str) == Some("mandate.checkout.allowed_merchants")
            })
            .flat_map(|c| {
                c.get("allowed")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
            })
            .collect()
    }

    /// Payees the payment mandate allows, inlined.
    pub fn allowed_payees(&self) -> Vec<Value> {
        self.payment_constraints()
            .iter()
            .filter(|c| {
                c.get("type").and_then(Value::as_str) == Some("mandate.payment.allowed_payees")
            })
            .flat_map(|c| {
                c.get("allowed")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
            })
            .collect()
    }

    /// The standalone disclosure for a merchant, matched by id, else by
    /// name and website.
    pub fn merchant_disclosure(&self, merchant: &Value) -> Option<&MandateDisc> {
        self.standalone
            .iter()
            .find(|d| merchant_matches(&d.value, merchant))
    }

    /// The standalone disclosure for a product, by `id` or `sku`.
    pub fn item_disclosure(&self, item_id: &str) -> Option<&MandateDisc> {
        self.standalone.iter().find(|d| {
            let id = d.value.get("id").and_then(Value::as_str);
            let sku = d.value.get("sku").and_then(Value::as_str);
            (id == Some(item_id) || sku == Some(item_id)) && d.value.get("title").is_some()
        })
    }

    /// The allowed merchant matching `id`, by id or by name.
    pub fn find_allowed_merchant(&self, id_or_name: &str) -> Option<Value> {
        self.allowed_merchants()
            .into_iter()
            .chain(self.allowed_payees())
            .find(|m| {
                m.get("id").and_then(Value::as_str) == Some(id_or_name)
                    || m.get("name").and_then(Value::as_str) == Some(id_or_name)
            })
    }
}

/// The reference's merchant match: by id when both sides have one, else by
/// exact name and website.
pub fn merchant_matches(candidate: &Value, target: &Value) -> bool {
    let (Some(c), Some(t)) = (candidate.as_object(), target.as_object()) else {
        return false;
    };
    let cid = c
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let tid = t
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    if let (Some(a), Some(b)) = (cid, tid) {
        return a == b;
    }
    let name = c
        .get("name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    let site = c
        .get("website")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty());
    name.is_some()
        && site.is_some()
        && name == t.get("name").and_then(Value::as_str)
        && site == t.get("website").and_then(Value::as_str)
}
