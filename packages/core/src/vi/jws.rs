//! base64url, SHA-256, P-256 keys and ES256 compact JWS, byte-for-byte the
//! way the VI reference SDK does them.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{
    signature::Signer as _, signature::Verifier as _, Signature, SigningKey, VerifyingKey,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::ViError;

/// base64url without padding, as every VI string field uses.
pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url, accepting the unpadded form (and padded, leniently).
pub fn b64u_decode(s: &str) -> Result<Vec<u8>, ViError> {
    let trimmed = s.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|e| ViError::Malformed(format!("base64url: {e}")))
}

/// `B64U(SHA-256(bytes))`: the spec's hash form for `sd_hash`, disclosure
/// hashes and `checkout_hash`.
pub fn sha256_b64u(bytes: &[u8]) -> String {
    b64u(&Sha256::digest(bytes))
}

/// Compact JSON exactly as Python's `json.dumps(obj, separators=(",", ":"))`
/// emits it with its default `ensure_ascii=True`: non-ASCII characters
/// become `\uXXXX` escapes (surrogate pairs above the BMP). The reference
/// verifier re-serializes a token's header and payload from the parsed
/// dicts before checking the signature, so our signed bytes must survive
/// that round trip unchanged.
pub fn json_compact_ascii(v: &Value) -> String {
    let raw = serde_json::to_string(v).expect("serde_json::Value serializes");
    if raw.is_ascii() {
        return raw;
    }
    let mut out = String::with_capacity(raw.len() + 16);
    for ch in raw.chars() {
        if ch.is_ascii() {
            out.push(ch);
        } else {
            let mut buf = [0u16; 2];
            for unit in ch.encode_utf16(&mut buf) {
                use std::fmt::Write;
                let _ = write!(out, "\\u{unit:04x}");
            }
        }
    }
    out
}

/// A P-256 public key in JWK form (`kty`, `crv`, `x`, `y`, optional `kid`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
}

impl Jwk {
    /// Parse a JWK from a JSON value, accepting extra members (`d`, `use`).
    pub fn from_value(v: &Value) -> Result<Self, ViError> {
        let get = |k: &str| -> Result<String, ViError> {
            v.get(k)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| ViError::Key(format!("jwk missing '{k}'")))
        };
        let kty = get("kty")?;
        let crv = get("crv")?;
        if kty != "EC" || crv != "P-256" {
            return Err(ViError::Key(format!(
                "jwk must be EC/P-256, got {kty}/{crv}"
            )));
        }
        Ok(Self {
            kty,
            crv,
            x: get("x")?,
            y: get("y")?,
            kid: v.get("kid").and_then(Value::as_str).map(str::to_string),
        })
    }

    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("Jwk serializes")
    }

    /// The verifying key this JWK names.
    pub fn verifying_key(&self) -> Result<VerifyingKey, ViError> {
        let x = b64u_decode(&self.x)?;
        let y = b64u_decode(&self.y)?;
        if x.len() != 32 || y.len() != 32 {
            return Err(ViError::Key("jwk x/y must be 32 bytes each".into()));
        }
        let mut sec1 = Vec::with_capacity(65);
        sec1.push(0x04);
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        VerifyingKey::from_sec1_bytes(&sec1).map_err(|e| ViError::Key(format!("jwk point: {e}")))
    }

    /// Verify a raw `r || s` ES256 signature over `signing_input`.
    pub fn verify(&self, signing_input: &[u8], sig: &[u8]) -> Result<(), ViError> {
        let vk = self.verifying_key()?;
        let sig = Signature::from_slice(sig)
            .map_err(|e| ViError::Signature(format!("ES256 signature bytes: {e}")))?;
        vk.verify(signing_input, &sig)
            .map_err(|_| ViError::Signature("ES256 signature did not verify".into()))
    }
}

/// A P-256 signing key: the agent's key that L2 binds under `cnf` and that
/// signs L3a and L3b.
#[derive(Clone)]
pub struct AgentKey {
    signing: SigningKey,
    /// The key id the L2 mandate's `cnf.jwk.kid` carries and every L3
    /// header repeats. Chosen at generation; stable for the key's life.
    pub kid: String,
}

impl std::fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKey").field("kid", &self.kid).finish()
    }
}

impl AgentKey {
    /// Generate a fresh key. The kid is the first 16 hex characters of
    /// SHA-256 over the SEC1 compressed point, prefixed `vik_`.
    pub fn generate() -> Self {
        let signing = SigningKey::random(&mut rand::rngs::OsRng);
        let kid = kid_for(signing.verifying_key());
        Self { signing, kid }
    }

    /// Rebuild from the 32-byte private scalar and an explicit kid.
    pub fn from_secret(d: &[u8], kid: impl Into<String>) -> Result<Self, ViError> {
        let signing =
            SigningKey::from_slice(d).map_err(|e| ViError::Key(format!("P-256 scalar: {e}")))?;
        Ok(Self {
            signing,
            kid: kid.into(),
        })
    }

    /// Import a private JWK (`d` present). Keeps the JWK's `kid` when it has
    /// one, else derives the same kid `generate` would.
    pub fn from_private_jwk(v: &Value) -> Result<Self, ViError> {
        let d = v
            .get("d")
            .and_then(Value::as_str)
            .ok_or_else(|| ViError::Key("private jwk missing 'd'".into()))?;
        let d = b64u_decode(d)?;
        let signing =
            SigningKey::from_slice(&d).map_err(|e| ViError::Key(format!("P-256 scalar: {e}")))?;
        let kid = v
            .get("kid")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| kid_for(signing.verifying_key()));
        let key = Self { signing, kid };
        // The public half in the JWK, if present, must be this key's.
        if v.get("x").is_some() {
            let claimed = Jwk::from_value(v)?;
            let ours = key.public_jwk();
            if claimed.x != ours.x || claimed.y != ours.y {
                return Err(ViError::Key("private jwk x/y do not match d".into()));
            }
        }
        Ok(key)
    }

    /// The 32-byte private scalar, for sealing at rest.
    pub fn secret_bytes(&self) -> [u8; 32] {
        let b = self.signing.to_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&b);
        out
    }

    /// The public JWK with this key's kid, as a wallet binds it under `cnf`.
    pub fn public_jwk(&self) -> Jwk {
        let point = self.signing.verifying_key().to_encoded_point(false);
        Jwk {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: b64u(point.x().expect("uncompressed point has x")),
            y: b64u(point.y().expect("uncompressed point has y")),
            kid: Some(self.kid.clone()),
        }
    }

    /// The private JWK (`d` included). For export to a wallet or HSM only.
    pub fn private_jwk(&self) -> Value {
        let mut v = self.public_jwk().to_value();
        v["d"] = Value::String(b64u(&self.secret_bytes()));
        v
    }

    /// ES256: raw `r || s`, 64 bytes, deterministic (RFC 6979).
    pub fn sign(&self, signing_input: &[u8]) -> Vec<u8> {
        let sig: Signature = self.signing.sign(signing_input);
        sig.to_bytes().to_vec()
    }
}

fn kid_for(vk: &VerifyingKey) -> String {
    let compressed = vk.to_encoded_point(true);
    let h = Sha256::digest(compressed.as_bytes());
    format!("vik_{}", hex::encode(&h[..8]))
}

/// A decoded compact JWS: the raw segments are kept so a parsed token
/// re-serializes byte-identically (which `sd_hash` depends on).
#[derive(Debug, Clone)]
pub struct CompactJws {
    pub header: Value,
    pub payload: Value,
    pub raw_header_b64: String,
    pub raw_payload_b64: String,
    pub signature: Vec<u8>,
}

impl CompactJws {
    /// Sign `header` and `payload` with `key`, producing `h.p.s`.
    pub fn sign(header: &Value, payload: &Value, key: &AgentKey) -> Self {
        let h = b64u(json_compact_ascii(header).as_bytes());
        let p = b64u(json_compact_ascii(payload).as_bytes());
        let signing_input = format!("{h}.{p}");
        let signature = key.sign(signing_input.as_bytes());
        Self {
            header: header.clone(),
            payload: payload.clone(),
            raw_header_b64: h,
            raw_payload_b64: p,
            signature,
        }
    }

    pub fn parse(token: &str) -> Result<Self, ViError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(ViError::Malformed(format!(
                "jwt: expected 3 parts, got {}",
                parts.len()
            )));
        }
        let header: Value = serde_json::from_slice(&b64u_decode(parts[0])?)
            .map_err(|e| ViError::Malformed(format!("jwt header json: {e}")))?;
        let payload: Value = serde_json::from_slice(&b64u_decode(parts[1])?)
            .map_err(|e| ViError::Malformed(format!("jwt payload json: {e}")))?;
        Ok(Self {
            header,
            payload,
            raw_header_b64: parts[0].to_string(),
            raw_payload_b64: parts[1].to_string(),
            signature: b64u_decode(parts[2])?,
        })
    }

    pub fn serialize(&self) -> String {
        format!(
            "{}.{}.{}",
            self.raw_header_b64,
            self.raw_payload_b64,
            b64u(&self.signature)
        )
    }

    /// The bytes the signature covers.
    pub fn signing_input(&self) -> Vec<u8> {
        format!("{}.{}", self.raw_header_b64, self.raw_payload_b64).into_bytes()
    }

    /// Verify with a P-256 public key.
    pub fn verify(&self, jwk: &Jwk) -> Result<(), ViError> {
        jwk.verify(&self.signing_input(), &self.signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_ascii_matches_python_ensure_ascii() {
        let v = serde_json::json!({"a": "caf\u{e9} \u{1F600}", "n": 1});
        // Python: json.dumps({"a": "café 😀", "n": 1}, separators=(",",":"))
        assert_eq!(
            json_compact_ascii(&v),
            r#"{"a":"caf\u00e9 \ud83d\ude00","n":1}"#
        );
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let key = AgentKey::generate();
        let header = serde_json::json!({"alg":"ES256","typ":"kb-sd-jwt","kid":key.kid});
        let payload = serde_json::json!({"nonce":"n","aud":"https://m.example","iat":1});
        let jws = CompactJws::sign(&header, &payload, &key);
        let parsed = CompactJws::parse(&jws.serialize()).unwrap();
        assert_eq!(parsed.header["kid"], key.kid);
        parsed.verify(&key.public_jwk()).unwrap();
        let other = AgentKey::generate();
        assert!(parsed.verify(&other.public_jwk()).is_err());
    }

    #[test]
    fn private_jwk_round_trip_keeps_kid_and_checks_point() {
        let key = AgentKey::generate();
        let priv_jwk = key.private_jwk();
        let back = AgentKey::from_private_jwk(&priv_jwk).unwrap();
        assert_eq!(back.kid, key.kid);
        assert_eq!(back.public_jwk(), key.public_jwk());
        let mut bad = priv_jwk.clone();
        bad["x"] = Value::String(b64u(&[7u8; 32]));
        assert!(AgentKey::from_private_jwk(&bad).is_err());
    }
}
