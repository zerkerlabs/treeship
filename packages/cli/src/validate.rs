//! Input validation shared by commands.
//!
//! Every refusal here is a usage error (exit 4, see `exit.rs`), raised
//! before anything is signed or written. The rule is the one the approval
//! expiry fix stated: keep garbage out of the signed bytes, because a
//! signature over a malformed value is still a signature and it is
//! permanent. Through 0.31.9 these were accepted: `--confidence 7.5`
//! (printed as 750%), `--kind bogus`, `--input-digest abc`, `--actor ""`,
//! `--meta '{bad'` on session events, `--valid-until notatime`, `--format
//! xml` (silently text), `--class bogus` and `--since yesterday` (silently
//! matched nothing), and a handoff of artifacts that do not exist (0.31.9
//! full test, CLI-14).

use crate::exit;

type Fallible = Result<(), Box<dyn std::error::Error>>;

/// `--format`: text or json, nothing else.
pub fn output_format(s: &str) -> Fallible {
    match s {
        "text" | "json" => Ok(()),
        other => Err(exit::usage(format!(
            "--format must be text or json, not {other:?}"
        ))),
    }
}

/// An actor URI: `scheme://name`, no whitespace, nothing empty.
pub fn actor_uri(flag: &str, s: &str) -> Fallible {
    let ok = !s.trim().is_empty()
        && !s.chars().any(char::is_whitespace)
        && s.split_once("://")
            .map(|(scheme, rest)| !scheme.is_empty() && !rest.is_empty())
            .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(exit::usage(format!(
            "{flag} must be a URI such as agent://researcher or human://alice, not {s:?}"
        )))
    }
}

/// A digest flag: `sha256:` followed by 64 hex characters.
pub fn sha256_digest(flag: &str, s: &str) -> Fallible {
    let hex = s.strip_prefix("sha256:").unwrap_or("");
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(exit::usage(format!(
            "{flag} must be sha256:<64 hex characters>, not {s:?}"
        )))
    }
}

/// A confidence: a finite number from 0.0 to 1.0.
pub fn confidence(c: Option<f64>) -> Fallible {
    match c {
        Some(v) if !(v.is_finite() && (0.0..=1.0).contains(&v)) => Err(exit::usage(format!(
            "--confidence must be between 0.0 and 1.0, not {v}"
        ))),
        _ => Ok(()),
    }
}

pub const ENDORSEMENT_KINDS: &[&str] = &["validation", "compliance", "countersignature", "review"];

pub fn endorsement_kind(s: &str) -> Fallible {
    if ENDORSEMENT_KINDS.contains(&s) {
        Ok(())
    } else {
        Err(exit::usage(format!(
            "--kind must be one of {}, not {s:?}",
            ENDORSEMENT_KINDS.join(", ")
        )))
    }
}

/// An RFC 3339 timestamp.
pub fn rfc3339(flag: &str, s: &str) -> Fallible {
    if treeship_core::statements::parse_rfc3339_to_unix(s).is_some() {
        Ok(())
    } else {
        Err(exit::usage(format!(
            "{flag} must be RFC 3339 (example: 2027-01-31T00:00:00Z), not {s:?}"
        )))
    }
}

/// A JSON object, for `--meta`.
pub fn json_object(
    flag: &str,
    s: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, Box<dyn std::error::Error>> {
    let v: serde_json::Value = serde_json::from_str(s)
        .map_err(|e| exit::usage(format!("{flag} is not valid JSON: {e}")))?;
    match v {
        serde_json::Value::Object(m) => Ok(m),
        _ => Err(exit::usage(format!(
            "{flag} must be a JSON object, not {s}"
        ))),
    }
}

pub const ATTESTATION_CLASSES: &[&str] = &["self", "runtime", "countersigned"];

pub fn attestation_class(s: &str) -> Fallible {
    if ATTESTATION_CLASSES.contains(&s) {
        Ok(())
    } else {
        Err(exit::usage(format!(
            "--class must be one of {}, not {s:?}",
            ATTESTATION_CLASSES.join(", ")
        )))
    }
}

/// `--since`: an RFC 3339 timestamp, or a duration back from now (`30d`,
/// `12h`, `45m`), returned as RFC 3339 so callers compare timestamps.
pub fn since(s: &str) -> Result<String, Box<dyn std::error::Error>> {
    if treeship_core::statements::parse_rfc3339_to_unix(s).is_some() {
        return Ok(s.to_string());
    }
    if let Some(secs) = duration_secs(s) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        return Ok(treeship_core::statements::unix_to_rfc3339(
            now.saturating_sub(secs),
        ));
    }
    Err(exit::usage(format!(
        "--since must be RFC 3339 or a duration back from now (30d, 12h, 45m), not {s:?}"
    )))
}

fn duration_secs(raw: &str) -> Option<u64> {
    let s = raw.trim();
    let (digits, mult) = if let Some(d) = s.strip_suffix('d') {
        (d, 86_400u64)
    } else if let Some(d) = s.strip_suffix('h') {
        (d, 3_600u64)
    } else if let Some(d) = s.strip_suffix('m') {
        (d, 60u64)
    } else if let Some(d) = s.strip_suffix('s') {
        (d, 1u64)
    } else {
        return None;
    };
    let n: u64 = digits.parse().ok()?;
    (n > 0).then_some(n.saturating_mul(mult))
}

/// Every id names an artifact in this store.
pub fn artifacts_exist(storage: &treeship_core::storage::Store, ids: &[String]) -> Fallible {
    for id in ids {
        if id.trim().is_empty() || !storage.exists(id) {
            return Err(exit::usage(format!(
                "--artifacts names {id:?}, which is not in this workspace's store"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actor_uris() {
        assert!(actor_uri("--actor", "agent://a").is_ok());
        assert!(actor_uri("--actor", "").is_err());
        assert!(actor_uri("--actor", "   ").is_err());
        assert!(actor_uri("--actor", "agent://").is_err());
        assert!(actor_uri("--actor", "://a").is_err());
        assert!(actor_uri("--actor", "agent://a b").is_err());
        assert!(actor_uri("--actor", "alice").is_err());
    }

    #[test]
    fn digests() {
        assert!(sha256_digest("--input-digest", &format!("sha256:{}", "ab".repeat(32))).is_ok());
        assert!(sha256_digest("--input-digest", "abc").is_err());
        assert!(sha256_digest("--input-digest", "sha256:abc").is_err());
        assert!(sha256_digest("--input-digest", &"zz".repeat(32)).is_err());
    }

    #[test]
    fn confidence_range() {
        assert!(confidence(None).is_ok());
        assert!(confidence(Some(0.0)).is_ok());
        assert!(confidence(Some(1.0)).is_ok());
        assert!(confidence(Some(7.5)).is_err());
        assert!(confidence(Some(-0.1)).is_err());
        assert!(confidence(Some(f64::NAN)).is_err());
    }

    #[test]
    fn since_forms() {
        assert_eq!(
            since("2026-07-01T00:00:00Z").unwrap(),
            "2026-07-01T00:00:00Z"
        );
        assert!(since("30d").unwrap().ends_with('Z'));
        assert!(since("yesterday").is_err());
        assert!(since("0d").is_err());
    }

    #[test]
    fn meta_objects() {
        assert!(json_object("--meta", "{\"a\":1}").is_ok());
        assert!(json_object("--meta", "{bad").is_err());
        assert!(json_object("--meta", "[1]").is_err());
    }

    #[test]
    fn every_refusal_is_a_usage_error() {
        for e in [
            output_format("xml").unwrap_err(),
            endorsement_kind("bogus").unwrap_err(),
            attestation_class("bogus").unwrap_err(),
            rfc3339("--valid-until", "notatime").unwrap_err(),
        ] {
            assert_eq!(exit::code_for(e.as_ref()), exit::USAGE);
        }
    }
}
