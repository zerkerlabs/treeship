//! RFC 8785 JSON Canonicalization Scheme, and the capsule digest built on it.
//!
//! This is **not** the encoding Treeship signs. That one lives in
//! [`crate::canonical`], it sorts object keys by code point, and it prints
//! numbers through `serde_json`. The two disagree, deliberately and
//! permanently: changing how a signed value was hashed would break
//! verification for every record already in the field, so interoperating with
//! anything that wants JCS means emitting a **second, additive** digest, never
//! rewriting the first.
//!
//! What JCS requires, and where the difference bites:
//!
//! * **Key order is UTF-16 code-unit order**, not code-point order. For keys
//!   inside the Basic Multilingual Plane the two agree. Above it they invert,
//!   because a non-BMP character encodes as a surrogate pair starting at
//!   `0xD800`, which sorts below every BMP character from `0xE000` up. A key
//!   of `U+1F600` therefore sorts *before* `U+E000` under JCS and *after* it
//!   under ours. [`canonical_string`] does the former, [`crate::canonical`]
//!   the latter, and each has a test holding it there.
//! * **Numbers follow ECMAScript**, which is where a general JCS
//!   implementation gets hard: shortest round-trip formatting, exponent
//!   thresholds, negative zero.
//!
//! That second problem is sidestepped rather than solved, and the reason is
//! worth stating. The Agent Action Capsule profile forbids JSON
//! floating-point values in digest-bearing material outright, and requires
//! integers outside the IEEE-754 safe range to be carried as decimal strings.
//! So a conformant producer never has a float to serialize. This module
//! therefore refuses them, with [`JcsError::FloatForbidden`], instead of
//! guessing at a conversion. Guessing is the failure the canonicalization rule
//! exists to prevent: two producers that each invent a mapping emit different
//! digests for the same value, and neither can tell.
//!
//! The consequence is a coverage limit, not a correctness one. Agent tool
//! arguments carry floats often, so some payloads are simply not exportable
//! until the profile says what to do with them. Refusing loudly is the right
//! behaviour while that is open.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;

/// Why a value cannot be canonicalized for a capsule digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JcsError {
    /// A JSON floating-point value appeared in digest-bearing material. The
    /// capsule profile forbids these; the producer must carry the value some
    /// other way rather than have us invent a serialization for it.
    FloatForbidden,
    /// An integer outside the IEEE-754 safe range. The profile requires these
    /// to be represented as decimal strings by the producer.
    UnsafeInteger(String),
}

impl fmt::Display for JcsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FloatForbidden => write!(
                f,
                "JSON floating-point values are forbidden in digest-bearing material; \
                 carry the value as a string, or leave it out of what is committed"
            ),
            Self::UnsafeInteger(n) => write!(
                f,
                "integer {n} is outside the IEEE-754 safe range and must be \
                 represented as a decimal string before it is committed"
            ),
        }
    }
}

impl std::error::Error for JcsError {}

/// The largest integer an IEEE-754 double represents exactly.
const SAFE_INTEGER: i128 = 9_007_199_254_740_991;

/// RFC 8785 canonical JSON for `value`.
///
/// Errors rather than guessing when the value holds a number the capsule
/// profile does not allow in digest-bearing material.
pub fn canonical_string(value: &Value) -> Result<String, JcsError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// The capsule digest: lowercase-hex SHA-256 over `UTF8(JCS(value))`.
///
/// Note the shape of the output. It is bare lowercase hex with no `sha256:`
/// prefix, because that is what the capsule profile specifies; Treeship's own
/// digests carry the prefix and are produced elsewhere.
pub fn capsule_digest(value: &Value) -> Result<String, JcsError> {
    let canonical = canonical_string(value)?;
    Ok(hex_lower(&Sha256::digest(canonical.as_bytes())))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn write_value(value: &Value, out: &mut String) -> Result<(), JcsError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 sorts members by the UTF-16 code units of the key, which
            // is not the same as Rust's ordering on `str` once a key leaves the
            // Basic Multilingual Plane.
            let mut members: Vec<(Vec<u16>, &String, &Value)> = map
                .iter()
                .map(|(k, v)| (k.encode_utf16().collect(), k, v))
                .collect();
            members.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (i, (_, key, v)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Integers only, and only inside the safe range. See the module note: the
/// capsule profile removes the hard part of ECMAScript number formatting by
/// forbidding the values that make it hard.
fn write_number(n: &serde_json::Number, out: &mut String) -> Result<(), JcsError> {
    if let Some(i) = n.as_i64() {
        if (i as i128).abs() > SAFE_INTEGER {
            return Err(JcsError::UnsafeInteger(i.to_string()));
        }
        out.push_str(&i.to_string());
        return Ok(());
    }
    if let Some(u) = n.as_u64() {
        if u as i128 > SAFE_INTEGER {
            return Err(JcsError::UnsafeInteger(u.to_string()));
        }
        out.push_str(&u.to_string());
        return Ok(());
    }
    Err(JcsError::FloatForbidden)
}

/// JSON string escaping as ECMAScript `JSON.stringify` performs it, which is
/// what RFC 8785 refers to: the two-character escapes where they exist, `\u`
/// for the remaining control characters, and every other character literal.
/// Non-ASCII is never escaped.
fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                use fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn members_sort_and_whitespace_goes() {
        assert_eq!(
            canonical_string(&json!({"b": 1, "a": 2})).unwrap(),
            r#"{"a":2,"b":1}"#
        );
        assert_eq!(
            canonical_string(&json!({"outer": {"z": [3, {"y": 1, "x": 2}], "a": null}})).unwrap(),
            r#"{"outer":{"a":null,"z":[3,{"x":2,"y":1}]}}"#
        );
    }

    /// Empty members and nulls participate. The withdrawn `jcs-n` construction
    /// strips them; the capsule profile requires a producer to fail closed on
    /// that identifier rather than accept it, so this encoding must never do it.
    #[test]
    fn empty_members_and_nulls_participate() {
        assert_eq!(
            canonical_string(&json!({"e": {}, "a": [], "n": null, "k": 1})).unwrap(),
            r#"{"a":[],"e":{},"k":1,"n":null}"#
        );
    }

    /// The divergence from [`crate::canonical`], pinned from both sides.
    ///
    /// A non-BMP key encodes as a surrogate pair starting at `0xD800`, so under
    /// UTF-16 ordering it sorts below a private-use BMP key at `U+E000`. Under
    /// code-point ordering it sorts above. Treeship's signing encoding does the
    /// latter, which is exactly why adopting this one is additive.
    #[test]
    fn utf16_key_order_inverts_code_point_order_above_the_bmp() {
        let value = json!({"\u{1f600}": 1, "\u{e000}": 2});

        let jcs = canonical_string(&value).unwrap();
        let astral = jcs.find('\u{1f600}').unwrap();
        let private_use = jcs.find('\u{e000}').unwrap();
        assert!(
            astral < private_use,
            "JCS orders by UTF-16 code unit, so the astral key comes first: {jcs}"
        );

        let ours = crate::canonical::canonical_json_string(&value);
        let astral_ours = ours.find('\u{1f600}').unwrap();
        let private_use_ours = ours.find('\u{e000}').unwrap();
        assert!(
            private_use_ours < astral_ours,
            "Treeship's signing encoding orders by code point: {ours}"
        );

        assert_ne!(jcs, ours, "the two encodings must not be conflated");
    }

    #[test]
    fn strings_escape_the_way_ecmascript_does() {
        assert_eq!(
            canonical_string(&json!("quote \" backslash \\ tab \t newline \n")).unwrap(),
            r#""quote \" backslash \\ tab \t newline \n""#
        );
        // Control characters without a short escape use \u00xx, lowercase hex.
        assert_eq!(canonical_string(&json!("\u{01}")).unwrap(), r#""\u0001""#);
        // Non-ASCII is never escaped.
        assert_eq!(canonical_string(&json!("café 😀")).unwrap(), "\"café 😀\"");
    }

    #[test]
    fn floats_are_refused_rather_than_guessed_at() {
        assert_eq!(
            canonical_string(&json!({"amount": 1.5})),
            Err(JcsError::FloatForbidden)
        );
        // Including one that happens to be integral: it is still a JSON
        // floating-point value, and the profile forbids the type, not the value.
        assert_eq!(canonical_string(&json!(1.0)), Err(JcsError::FloatForbidden));
        // And nested anywhere.
        assert_eq!(
            canonical_string(&json!({"a": {"b": [0, {"c": 0.5}]}})),
            Err(JcsError::FloatForbidden)
        );
    }

    #[test]
    fn integers_outside_the_safe_range_are_refused() {
        let big = json!(9_007_199_254_740_992i64);
        assert_eq!(
            canonical_string(&big),
            Err(JcsError::UnsafeInteger("9007199254740992".into()))
        );
        // The boundary itself is fine.
        assert_eq!(
            canonical_string(&json!(9_007_199_254_740_991i64)).unwrap(),
            "9007199254740991"
        );
        assert_eq!(
            canonical_string(&json!(-9_007_199_254_740_991i64)).unwrap(),
            "-9007199254740991"
        );
    }

    /// Known answers, computed with an independent SHA-256 implementation over
    /// the canonical bytes by hand, so this test fails if either the
    /// canonicalization or the digest step drifts. Deriving the expected value
    /// from this module would only prove it agrees with itself.
    #[test]
    fn known_answer_digests() {
        let cases: Vec<(serde_json::Value, &str)> = vec![
            (
                json!({"b": 1, "a": 2}),
                "d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772",
            ),
            (
                json!({"e": {}, "a": [], "n": null, "k": 1}),
                "ea64f41f98c81d7a0321157d4733ac05b84964695c0da9cf675da21cad3b6164",
            ),
            (
                json!("café 😀"),
                "89fa4ccbaa53bc2ebec0726f73beccbe1618075d3ef9e740cf34ec284b07a66e",
            ),
        ];
        for (value, expect) in cases {
            assert_eq!(
                capsule_digest(&value).unwrap(),
                expect,
                "digest drifted for {value}"
            );
        }
    }

    #[test]
    fn the_digest_is_bare_lowercase_hex_over_the_canonical_bytes() {
        let value = json!({"b": 1, "a": 2});
        let digest = capsule_digest(&value).unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        assert!(!digest.starts_with("sha256:"), "the profile wants bare hex");

        // It is the digest of the canonical bytes, not of any other encoding.
        let expected = {
            let mut h = Sha256::new();
            h.update(r#"{"a":2,"b":1}"#.as_bytes());
            hex_lower(&h.finalize())
        };
        assert_eq!(digest, expected);

        // Key order in the input cannot change it.
        assert_eq!(capsule_digest(&json!({"a": 2, "b": 1})).unwrap(), digest);
    }
}
