//! SD-JWT serialization, disclosures and selective presentations, matching
//! the reference SDK's `crypto/sd_jwt.py` and `crypto/disclosure.py`.
//!
//! Serialized form: `<h.p.s>~<disclosure>~<disclosure>~...~` (trailing `~`).
//! A disclosure is the base64url of a compact JSON array `[salt, name,
//! value]` for an object property or `[salt, value]` for an array element.
//! Its hash is `B64U(SHA-256(ASCII(disclosure)))`, over the encoded string,
//! never the decoded bytes.

use serde_json::Value;

use super::jws::{b64u, b64u_decode, json_compact_ascii, sha256_b64u, AgentKey, CompactJws, Jwk};
use super::ViError;

/// A parsed SD-JWT: the issuer JWS plus the disclosures that travelled with
/// it. Raw segments are kept so `serialize` reproduces the input exactly.
#[derive(Debug, Clone)]
pub struct SdJwt {
    pub jws: CompactJws,
    pub disclosures: Vec<String>,
}

impl SdJwt {
    /// Parse `<jwt>~<d1>~...~`. Empty segments (the trailing one) are dropped.
    pub fn parse(serialized: &str) -> Result<Self, ViError> {
        let mut parts = serialized.trim().split('~');
        let jwt = parts.next().unwrap_or_default();
        let jws = CompactJws::parse(jwt)?;
        let disclosures: Vec<String> = parts
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect();
        for d in &disclosures {
            decode_disclosure(d)?;
        }
        Ok(Self { jws, disclosures })
    }

    /// Sign a new SD-JWT. `payload` must already carry `_sd` / `_sd_alg` /
    /// `delegate_payload` as the layer requires.
    pub fn create(
        header: &Value,
        payload: &Value,
        disclosures: Vec<String>,
        key: &AgentKey,
    ) -> Self {
        Self {
            jws: CompactJws::sign(header, payload, key),
            disclosures,
        }
    }

    pub fn header(&self) -> &Value {
        &self.jws.header
    }

    pub fn payload(&self) -> &Value {
        &self.jws.payload
    }

    /// The issuer JWS alone, `h.p.s`.
    pub fn base_jwt(&self) -> String {
        self.jws.serialize()
    }

    /// Full serialization with every disclosure.
    pub fn serialize(&self) -> String {
        selective_presentation(&self.base_jwt(), &self.disclosures)
    }

    /// Verify the issuer signature with a P-256 public key.
    pub fn verify_signature(&self, jwk: &Jwk) -> Result<(), ViError> {
        self.jws.verify(jwk)
    }

    /// Decoded disclosure values, in disclosure order.
    pub fn disclosure_values(&self) -> Vec<Vec<Value>> {
        self.disclosures
            .iter()
            .filter_map(|d| decode_disclosure(d).ok())
            .collect()
    }

    /// `(disclosure string, hash, value)` for each disclosure, where value
    /// is the last element of the decoded array.
    pub fn disclosure_entries(&self) -> Vec<(String, String, Value)> {
        self.disclosures
            .iter()
            .filter_map(|d| {
                let arr = decode_disclosure(d).ok()?;
                let v = arr.last().cloned()?;
                Some((d.clone(), hash_disclosure(d), v))
            })
            .collect()
    }

    /// Find the disclosure whose value satisfies `pred`.
    pub fn find_disclosure(&self, pred: impl Fn(&Value) -> bool) -> Option<String> {
        self.disclosure_entries()
            .into_iter()
            .find(|(_, _, v)| pred(v))
            .map(|(d, _, _)| d)
    }

    /// Resolve disclosures into the payload the way the reference's
    /// `resolve_disclosures` does: object-property disclosures whose hash is
    /// in `_sd` are merged in; `delegate_payload` entries of the form
    /// `{"...": <hash>}` are replaced by the disclosed value.
    pub fn resolve(&self) -> Value {
        let mut result = self.payload().clone();
        let sd_hashes: Vec<String> = result
            .get("_sd")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let entries: Vec<(String, String, Vec<Value>)> = self
            .disclosures
            .iter()
            .filter_map(|d| {
                decode_disclosure(d)
                    .ok()
                    .map(|arr| (d.clone(), hash_disclosure(d), arr))
            })
            .collect();
        for (_, h, arr) in &entries {
            if sd_hashes.contains(h) && arr.len() == 3 {
                if let Some(name) = arr[1].as_str() {
                    if let Some(obj) = result.as_object_mut() {
                        obj.insert(name.to_string(), arr[2].clone());
                    }
                }
            }
        }
        if let Some(items) = result
            .get("delegate_payload")
            .and_then(Value::as_array)
            .cloned()
        {
            let resolved: Vec<Value> = items
                .into_iter()
                .map(|item| {
                    let r = item.get("...").and_then(Value::as_str).map(str::to_string);
                    match r {
                        Some(h) => entries
                            .iter()
                            .find(|(_, eh, _)| *eh == h)
                            .and_then(|(_, _, arr)| arr.last().cloned())
                            .unwrap_or(item),
                        None => item,
                    }
                })
                .collect();
            if let Some(obj) = result.as_object_mut() {
                obj.insert("delegate_payload".into(), Value::Array(resolved));
            }
        }
        result
    }
}

/// `[salt, value]` or `[salt, name, value]`, base64url of compact JSON.
pub fn create_disclosure(name: Option<&str>, value: &Value, salt: Option<&str>) -> String {
    let salt = salt.map(str::to_string).unwrap_or_else(random_salt);
    let arr = match name {
        Some(n) => serde_json::json!([salt, n, value]),
        None => serde_json::json!([salt, value]),
    };
    b64u(json_compact_ascii(&arr).as_bytes())
}

pub fn decode_disclosure(disclosure: &str) -> Result<Vec<Value>, ViError> {
    let raw = b64u_decode(disclosure)?;
    let v: Value = serde_json::from_slice(&raw)
        .map_err(|e| ViError::Malformed(format!("disclosure json: {e}")))?;
    match v {
        Value::Array(a) if a.len() == 2 || a.len() == 3 => Ok(a),
        _ => Err(ViError::Malformed(
            "disclosure must be a 2- or 3-element array".into(),
        )),
    }
}

/// `B64U(SHA-256(ASCII(disclosure)))`.
pub fn hash_disclosure(disclosure: &str) -> String {
    sha256_b64u(disclosure.as_bytes())
}

/// `{"...": <hash>}`, the reference's delegate_payload entry.
pub fn delegate_ref(disclosure_hash: &str) -> Value {
    serde_json::json!({ "...": disclosure_hash })
}

/// `<base_jwt>~<d1>~...~`: the presentation whose ASCII bytes `sd_hash`
/// covers. `disclosures` may be empty (then it is `<base_jwt>~`).
pub fn selective_presentation(base_jwt: &str, disclosures: &[String]) -> String {
    let mut s = String::from(base_jwt);
    for d in disclosures {
        s.push('~');
        s.push_str(d);
    }
    s.push('~');
    s
}

/// `B64U(SHA-256(ASCII(presentation)))`.
pub fn presentation_hash(presentation: &str) -> String {
    sha256_b64u(presentation.as_bytes())
}

fn random_salt() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b64u(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disclosure_hash_matches_reference_bytes() {
        // create_disclosure(None, {"id":"x"}, salt="c2FsdA") in the reference:
        // b64u('["c2FsdA",{"id":"x"}]') and hash over that ASCII string.
        let d = create_disclosure(None, &serde_json::json!({"id":"x"}), Some("c2FsdA"));
        assert_eq!(d, b64u(br#"["c2FsdA",{"id":"x"}]"#));
        assert_eq!(hash_disclosure(&d), sha256_b64u(d.as_bytes()));
        assert_eq!(decode_disclosure(&d).unwrap().len(), 2);
    }

    #[test]
    fn serialize_round_trips_and_resolves() {
        let key = AgentKey::generate();
        let d1 = create_disclosure(
            None,
            &serde_json::json!({"vct":"mandate.checkout.1","checkout_hash":"h"}),
            None,
        );
        let d2 = create_disclosure(Some("email"), &serde_json::json!("a@b.c"), None);
        let payload = serde_json::json!({
            "nonce": "n", "aud": "a", "iat": 1, "_sd_alg": "sha-256",
            "_sd": [hash_disclosure(&d2)],
            "delegate_payload": [delegate_ref(&hash_disclosure(&d1))]
        });
        let header = serde_json::json!({"alg":"ES256","typ":"kb-sd-jwt","kid":key.kid});
        let sd = SdJwt::create(&header, &payload, vec![d1.clone(), d2.clone()], &key);
        let ser = sd.serialize();
        assert!(ser.ends_with('~'));
        let back = SdJwt::parse(&ser).unwrap();
        assert_eq!(back.serialize(), ser);
        back.verify_signature(&key.public_jwk()).unwrap();
        let resolved = back.resolve();
        assert_eq!(resolved["email"], "a@b.c");
        assert_eq!(resolved["delegate_payload"][0]["vct"], "mandate.checkout.1");
        assert_eq!(
            presentation_hash(&selective_presentation(&back.base_jwt(), &[d1])),
            sha256_b64u(format!("{}~{}~", back.base_jwt(), back.disclosures[0]).as_bytes())
        );
    }
}
