//! The one canonical-JSON encoding Treeship hashes.
//!
//! Three modules used to carry their own copy of this function
//! (`disclosure`, `merkle::checkpoint`, `statements::invitation`), and every
//! one of them feeds a digest that ends up inside a signed artifact. They were
//! the same algorithm written out three times, so nothing but review stopped
//! one from drifting away from the others and silently changing a digest that
//! older records were signed over. They now share this one.
//!
//! **What this encoding is, and is not.** Object keys are sorted by Rust's
//! string order, which is UTF-8 code-point order; RFC 8785 sorts by UTF-16
//! code units, and the two disagree once a key is outside the Basic
//! Multilingual Plane. Numbers are printed by `serde_json`, not by the
//! ECMAScript rules RFC 8785 requires. So this is *a* canonical JSON, pinned
//! by the tests below, and it is not JCS.
//!
//! That distinction matters for interoperability work. Changing how a signed
//! value was hashed breaks verification for every record already in the field,
//! so adopting RFC 8785 means emitting a **new, additive** digest alongside
//! this one. It never means changing this one.

use serde_json::Value;
use std::collections::BTreeMap;

/// Sorted-key canonical JSON: objects by key, arrays in order, scalars through
/// `serde_json`. No whitespace.
pub(crate) fn canonical_json_string(value: &Value) -> String {
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
                // Re-serialize the key as a JSON string to handle escapes.
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
            for item in items {
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&canonical_json_string(item));
            }
            out.push(']');
            out
        }
        other => serde_json::to_string(other).expect("scalar JSON value serializes"),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    /// The encoding is pinned byte for byte. A change here changes digests that
    /// signed records were produced under, so it has to be deliberate.
    #[test]
    fn the_encoding_is_pinned_byte_for_byte() {
        let pinned: Vec<(serde_json::Value, &str)> = vec![
            (json!({"b": 1, "a": 2}), r#"{"a":2,"b":1}"#),
            (
                json!({"outer": {"z": [3, {"y": 1, "x": 2}], "a": null}}),
                r#"{"outer":{"a":null,"z":[3,{"x":2,"y":1}]}}"#,
            ),
            (
                json!({"empty_obj": {}, "empty_arr": [], "null": null}),
                r#"{"empty_arr":[],"empty_obj":{},"null":null}"#,
            ),
            (json!([]), "[]"),
            (json!("bare string"), r#""bare string""#),
        ];
        for (value, expect) in pinned {
            assert_eq!(
                super::canonical_json_string(&value),
                expect,
                "encoding changed for {value}"
            );
        }
    }

    /// Empty members and nulls participate, they are never dropped. Worth
    /// pinning on its own: canonicalizations that strip them exist, and a
    /// stripping variant would change every digest that has one.
    #[test]
    fn empty_members_and_nulls_participate() {
        let with = json!({"a": 1, "e": {}, "n": null});
        let without = json!({"a": 1});
        assert_ne!(
            super::canonical_json_string(&with),
            super::canonical_json_string(&without)
        );
    }

    /// Key order is UTF-8 code-point order, which is where this encoding and
    /// RFC 8785 part company: JCS would order these by UTF-16 code units and
    /// put the astral key first.
    #[test]
    fn keys_sort_by_code_point_not_utf16_code_unit() {
        let out = super::canonical_json_string(&json!({"\u{1f600}": 2, "\u{e000}": 1}));
        let private_use = out.find('\u{e000}').expect("private-use key present");
        let astral = out.find('\u{1f600}').expect("astral key present");
        assert!(
            private_use < astral,
            "expected code-point order (U+E000 before U+1F600), got {out}"
        );
    }
}
