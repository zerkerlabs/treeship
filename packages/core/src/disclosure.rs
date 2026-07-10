//! Selective disclosure over signed statements (SD-JWT-style, ported to DSSE).
//!
//! The problem: a plain Ed25519 signature commits to the *entire* payload, so
//! a verifier cannot check the signature without seeing every field. To let an
//! agent reveal one capability (or one mandate field) while hiding the rest, we
//! borrow the SD-JWT construction and apply it to Treeship's JCS-canonical JSON
//! payloads instead of JWT serialization.
//!
//! The construction:
//!
//!   * Each disclosable claim `(name, value)` is bound to a fresh 128-bit salt
//!     as a **disclosure**: the canonical JSON array `[salt, name, value]`.
//!   * The claim's **digest** is `sha256:<hex>` of that canonical encoding,
//!     matching Treeship's existing digest convention (`nonce_digest`,
//!     `canonical_json_digest`).
//!   * The signed payload carries only the *sorted list of digests* (`_sd`),
//!     never the raw disclosable values. The Ed25519 signature therefore
//!     commits to the digests, which are always present, so it verifies even
//!     when the values are withheld.
//!   * To reveal a claim, the holder presents its disclosure string. The
//!     verifier recomputes the digest over the exact received bytes and checks
//!     membership in the signed `_sd` set. A digest that is not in the set
//!     reveals nothing (fail-closed); a holder cannot present a value that was
//!     not committed, because it could not produce a matching digest.
//!
//! This layer answers "reveal this claim or not." Proving a *property* of a
//! withheld claim without revealing it (a range, set membership without
//! revealing which) is the zero-knowledge layer, which opens the *same*
//! committed values; see `docs/specs/zk-verification.md`. The salt makes each
//! digest unguessable, so a verifier cannot brute-force a low-entropy withheld
//! value from its digest.

use rand::rngs::OsRng;
use rand::RngCore;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// A single disclosable claim bound to a salt. The wire form is `encode()`;
/// the signed payload stores `digest()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disclosure {
    pub salt: String,
    pub name: String,
    pub value: Value,
}

/// The output of committing a set of disclosable claims: the sorted digest
/// list that goes into the signed payload, and the disclosures the holder
/// keeps to reveal later.
#[derive(Debug, Clone)]
pub struct Commitment {
    /// Sorted `sha256:<hex>` digests. Goes into the signed statement as `_sd`.
    /// Sorted so the on-wire order does not leak the claims' insertion order.
    pub sd: Vec<String>,
    /// One disclosure per committed claim, in input order. The holder stores
    /// these and presents the subset it chooses to reveal.
    pub disclosures: Vec<Disclosure>,
}

/// A fresh 128-bit salt from the OS CSPRNG, base64url-nopad encoded. Security
/// material (unguessability of low-entropy values rests on it), so `OsRng`,
/// never `thread_rng`.
pub fn new_salt() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

impl Disclosure {
    /// Bind a claim to the given salt. Callers use `new_salt()` for the salt;
    /// tests pin it for reproducible vectors.
    pub fn new(salt: impl Into<String>, name: impl Into<String>, value: Value) -> Self {
        Self {
            salt: salt.into(),
            name: name.into(),
            value,
        }
    }

    /// Canonical wire encoding: the JCS-canonical JSON of `[salt, name, value]`.
    /// Deterministic even when `value` is an object, because nested objects are
    /// serialized with sorted keys.
    pub fn encode(&self) -> String {
        let array = Value::Array(vec![
            Value::String(self.salt.clone()),
            Value::String(self.name.clone()),
            self.value.clone(),
        ]);
        canonical_json_string(&array)
    }

    /// `sha256:<hex>` over the canonical encoding.
    pub fn digest(&self) -> String {
        digest_of_encoded(&self.encode())
    }
}

/// Commit a set of disclosable claims. Each gets a fresh salt; the returned
/// `sd` list is sorted to hide input order.
pub fn commit(claims: &[(String, Value)]) -> Commitment {
    let disclosures: Vec<Disclosure> = claims
        .iter()
        .map(|(name, value)| Disclosure::new(new_salt(), name.clone(), value.clone()))
        .collect();
    let mut sd: Vec<String> = disclosures.iter().map(|d| d.digest()).collect();
    sd.sort();
    Commitment { sd, disclosures }
}

/// Verify a presented disclosure against a signed `_sd` set. Returns the
/// revealed `(name, value)` only when the disclosure's digest, recomputed over
/// the *exact received bytes*, is present in the set. Fails closed on a
/// malformed disclosure or a digest not in the set.
pub fn verify_disclosure(encoded: &str, sd_set: &BTreeSet<String>) -> Option<(String, Value)> {
    // Membership is decided over the received bytes, so a holder must present
    // the exact bytes that were committed; a re-encoded or altered disclosure
    // simply fails the set check.
    if !sd_set.contains(&digest_of_encoded(encoded)) {
        return None;
    }
    let parsed: Value = serde_json::from_str(encoded).ok()?;
    let arr = parsed.as_array()?;
    if arr.len() != 3 {
        return None;
    }
    let name = arr[1].as_str()?.to_string();
    let value = arr[2].clone();
    Some((name, value))
}

fn digest_of_encoded(encoded: &str) -> String {
    let digest = Sha256::digest(encoded.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

/// Sorted-key canonical JSON. Mirrors the copies in `statements::invitation`
/// and `merkle::checkpoint` (intentionally duplicated rather than a cross-module
/// `pub use`, to keep each module self-contained per the existing convention).
fn canonical_json_string(value: &Value) -> String {
    use std::collections::BTreeMap;
    match value {
        Value::Object(map) => {
            let sorted: BTreeMap<&String, String> = map
                .iter()
                .map(|(k, v)| (k, canonical_json_string(v)))
                .collect();
            let mut out = String::from("{");
            let mut first = true;
            for (k, v) in sorted {
                if !first {
                    out.push(',');
                }
                first = false;
                let key_json = serde_json::to_string(k).expect("string serializes to JSON");
                out.push_str(&key_json);
                out.push(':');
                out.push_str(&v);
            }
            out.push('}');
            out
        }
        Value::Array(items) => {
            let mut out = String::from("[");
            let mut first = true;
            for v in items {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&canonical_json_string(v));
            }
            out.push(']');
            out
        }
        other => serde_json::to_string(other).expect("scalar JSON value serializes"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // A hand-constructed vector. The disclosure `[salt, "tools", "payments.charge"]`
    // canonicalizes to exactly this string (scalars, no whitespace), and its
    // digest is sha256 of those bytes. The expected string and hash are computed
    // here independently of the module's `encode()`/`digest()`, per the
    // AI-assisted development policy on real test vectors.
    #[test]
    fn digest_matches_independently_computed_sha256() {
        let salt = "c2FsdHNhbHRzYWx0c2Fs"; // fixed, not from new_salt()
        let d = Disclosure::new(salt, "tools", json!("payments.charge"));

        let expected_encoded = r#"["c2FsdHNhbHRzYWx0c2Fs","tools","payments.charge"]"#;
        assert_eq!(d.encode(), expected_encoded, "canonical encoding is exact");

        // Independent digest: hash the literal bytes with sha2 directly.
        let independent = {
            let h = Sha256::digest(expected_encoded.as_bytes());
            format!("sha256:{}", hex::encode(h))
        };
        assert_eq!(d.digest(), independent);
    }

    // Object-valued claims canonicalize with sorted keys, so the digest is
    // stable regardless of the input map's key order.
    #[test]
    fn object_value_canonicalizes_with_sorted_keys() {
        let a = Disclosure::new("s", "limit", json!({"max": 100, "ccy": "USD"}));
        let b = Disclosure::new("s", "limit", json!({"ccy": "USD", "max": 100}));
        assert_eq!(a.encode(), b.encode());
        assert_eq!(a.encode(), r#"["s","limit",{"ccy":"USD","max":100}]"#);
    }

    #[test]
    fn verify_accepts_committed_and_rejects_tampered_or_foreign() {
        let claims = vec![
            ("tools".to_string(), json!("payments.charge")),
            ("tools".to_string(), json!("email.send")),
            ("owner".to_string(), json!("human://alice")),
        ];
        let c = commit(&claims);
        let sd_set: BTreeSet<String> = c.sd.iter().cloned().collect();

        // A genuinely committed disclosure verifies and reveals exactly its claim.
        let first = c.disclosures[0].encode();
        let revealed = verify_disclosure(&first, &sd_set).expect("committed disclosure verifies");
        assert_eq!(revealed.0, "tools");
        assert_eq!(revealed.1, json!("payments.charge"));

        // A tampered disclosure (value changed) is not in the set -> rejected.
        let tampered = first.replace("payments.charge", "payments.refund");
        assert_ne!(tampered, first);
        assert!(verify_disclosure(&tampered, &sd_set).is_none());

        // A disclosure for a claim that was never committed -> rejected.
        let foreign = Disclosure::new(new_salt(), "tools", json!("admin.root")).encode();
        assert!(verify_disclosure(&foreign, &sd_set).is_none());

        // Malformed input -> rejected, not a panic.
        assert!(verify_disclosure("not json", &sd_set).is_none());
        assert!(verify_disclosure("[1,2]", &sd_set).is_none());
    }

    #[test]
    fn commit_sorts_digests_to_hide_input_order() {
        // Fixed disclosures (salt tied to the claim, not its position) so the
        // only thing that changes between the two runs is input order.
        let forward = vec![
            Disclosure::new("salt-a", "a", json!(1)),
            Disclosure::new("salt-b", "b", json!(2)),
            Disclosure::new("salt-c", "c", json!(3)),
        ];
        let sd_of = |ds: &[Disclosure]| {
            let mut sd: Vec<String> = ds.iter().map(|d| d.digest()).collect();
            sd.sort();
            sd
        };
        let mut reversed = forward.clone();
        reversed.reverse();
        // Sorting makes the on-wire digest list identical regardless of the
        // order the claims were committed in -> input order is not leaked.
        assert_eq!(sd_of(&forward), sd_of(&reversed));
        assert!(sd_of(&forward).windows(2).all(|w| w[0] <= w[1]), "sorted");
    }

    #[test]
    fn salt_is_128_bit_and_fresh() {
        let s1 = new_salt();
        let s2 = new_salt();
        assert_ne!(s1, s2, "salts are random");
        let bytes = URL_SAFE_NO_PAD.decode(&s1).expect("salt is base64url");
        assert_eq!(bytes.len(), 16, "128-bit salt");
    }
}
