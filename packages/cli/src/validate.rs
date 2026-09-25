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

/// An actor URI: `scheme://name` (agent://, human://, system://, ship://)
/// or a DID (`did:key:z6Mk…`), no whitespace, nothing empty.
pub fn actor_uri(flag: &str, s: &str) -> Fallible {
    let no_ws = !s.trim().is_empty() && !s.chars().any(char::is_whitespace);
    let scheme_form = s
        .split_once("://")
        .map(|(scheme, rest)| !scheme.is_empty() && !rest.is_empty())
        .unwrap_or(false);
    let did_form = s
        .strip_prefix("did:")
        .and_then(|r| r.split_once(':'))
        .map(|(method, id)| !method.is_empty() && !id.is_empty())
        .unwrap_or(false);
    if no_ws && (scheme_form || did_form) {
        Ok(())
    } else {
        Err(exit::usage(format!(
            "{flag} must be a URI such as agent://researcher, human://alice or did:key:z6Mk…, not {s:?}"
        )))
    }
}

/// A digest flag: the lowercase prefix `sha256:` followed by 64 hex
/// characters. `SHA256:` and a bare hex string are refused, so a digest
/// is written one way everywhere it is compared.
pub fn sha256_digest(flag: &str, s: &str) -> Fallible {
    let hex = s.strip_prefix("sha256:").unwrap_or("");
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(exit::usage(format!(
            "{flag} must be sha256:<64 hex characters> (lowercase `sha256:` prefix; a bare hex digest or SHA256: is not accepted), not {s:?}"
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

/// An RFC 3339 timestamp, returned normalised to `YYYY-MM-DDTHH:MM:SSZ`.
/// Accepts fractional seconds and a numeric offset (what `toISOString()`
/// and `date --iso-8601=seconds` produce), which are folded into UTC.
pub fn rfc3339(flag: &str, s: &str) -> Result<String, Box<dyn std::error::Error>> {
    parse_rfc3339(s)
        .map(treeship_core::statements::unix_to_rfc3339)
        .ok_or_else(|| {
            exit::usage(format!(
                "{flag} must be an RFC 3339 timestamp such as 2027-01-31T00:00:00Z (fractional seconds and an offset like +02:00 are accepted), not {s:?}"
            ))
        })
}

/// `YYYY-MM-DDTHH:MM:SS[.fff][Z|±HH:MM]` to unix seconds (UTC).
fn parse_rfc3339(s: &str) -> Option<u64> {
    let s = s.trim();
    let (date, rest) = s.split_once(['T', 't', ' '])?;
    let (y, m, d) = parse_date(date)?;
    let rest = rest.trim_end();
    let (time, offset_secs) = if let Some(t) = rest.strip_suffix(['Z', 'z']) {
        (t, 0i64)
    } else if let Some(i) = rest.rfind(['+', '-']) {
        let (t, off) = rest.split_at(i);
        let sign = if off.starts_with('-') { -1 } else { 1 };
        let (oh, om) = off[1..].split_once(':')?;
        let oh: i64 = oh.parse().ok()?;
        let om: i64 = om.parse().ok()?;
        if oh > 23 || om > 59 {
            return None;
        }
        (t, sign * (oh * 3600 + om * 60))
    } else {
        return None;
    };
    let time = match time.split_once('.') {
        Some((t, frac)) if !frac.is_empty() && frac.bytes().all(|b| b.is_ascii_digit()) => t,
        Some(_) => return None,
        None => time,
    };
    let mut parts = time.split(':');
    let hh: i64 = parts.next()?.parse().ok()?;
    let mm: i64 = parts.next()?.parse().ok()?;
    let ss: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let secs = days_from_civil(y, m, d) * 86_400 + hh * 3600 + mm * 60 + ss - offset_secs;
    u64::try_from(secs).ok()
}

/// `YYYY-MM-DD` to (year, month, day), range-checked.
fn parse_date(s: &str) -> Option<(i64, i64, i64)> {
    let mut parts = s.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) || y < 1970 {
        return None;
    }
    Some((y, m, d))
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// days_from_civil).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
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
    if let Some(unix) = parse_rfc3339(s) {
        return Ok(treeship_core::statements::unix_to_rfc3339(unix));
    }
    // A date alone means its first second, UTC.
    if let Some((y, m, d)) = parse_date(s.trim()) {
        let unix = days_from_civil(y, m, d) * 86_400;
        return Ok(treeship_core::statements::unix_to_rfc3339(
            u64::try_from(unix).unwrap_or(0),
        ));
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
        "--since must be an RFC 3339 timestamp, a date (2026-07-01), or a duration back from now (30d, 12h, 45m), not {s:?}"
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
        assert!(actor_uri(
            "--actor",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
        )
        .is_ok());
        assert!(actor_uri("--actor", "").is_err());
        assert!(actor_uri("--actor", "   ").is_err());
        assert!(actor_uri("--actor", "agent://").is_err());
        assert!(actor_uri("--actor", "://a").is_err());
        assert!(actor_uri("--actor", "agent://a b").is_err());
        assert!(actor_uri("--actor", "alice").is_err());
        assert!(actor_uri("--actor", "did:key").is_err());
    }

    #[test]
    fn digests() {
        assert!(sha256_digest("--d", &format!("sha256:{}", "ab".repeat(32))).is_ok());
        assert!(sha256_digest("--d", "abc").is_err());
        assert!(sha256_digest("--d", "sha256:abc").is_err());
        assert!(sha256_digest("--d", &"zz".repeat(32)).is_err());
        assert!(sha256_digest("--d", &format!("SHA256:{}", "ab".repeat(32))).is_err());
        assert!(sha256_digest("--d", &"ab".repeat(32)).is_err());
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
    fn rfc3339_forms_normalise_to_utc() {
        assert_eq!(
            rfc3339("--x", "2027-01-31T00:00:00Z").unwrap(),
            "2027-01-31T00:00:00Z"
        );
        assert_eq!(
            rfc3339("--x", "2027-01-31T00:00:00.123Z").unwrap(),
            "2027-01-31T00:00:00Z"
        );
        assert_eq!(
            rfc3339("--x", "2027-01-31T02:00:00+02:00").unwrap(),
            "2027-01-31T00:00:00Z"
        );
        assert_eq!(
            rfc3339("--x", "2027-01-30T22:00:00-02:00").unwrap(),
            "2027-01-31T00:00:00Z"
        );
        assert_eq!(
            rfc3339("--x", "1970-01-01T00:00:00Z").unwrap(),
            "1970-01-01T00:00:00Z"
        );
        assert!(rfc3339("--x", "notatime").is_err());
        assert!(rfc3339("--x", "2027-01-31").is_err());
        assert!(rfc3339("--x", "2027-13-01T00:00:00Z").is_err());
        assert!(rfc3339("--x", "2027-01-31T25:00:00Z").is_err());
    }

    #[test]
    fn since_forms() {
        assert_eq!(
            since("2026-07-01T00:00:00Z").unwrap(),
            "2026-07-01T00:00:00Z"
        );
        assert_eq!(
            since("2026-07-01T02:00:00+02:00").unwrap(),
            "2026-07-01T00:00:00Z"
        );
        assert_eq!(since("2026-07-01").unwrap(), "2026-07-01T00:00:00Z");
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
            since("yesterday").unwrap_err(),
            sha256_digest("--d", "abc").unwrap_err(),
            actor_uri("--actor", "").unwrap_err(),
        ] {
            assert_eq!(exit::code_for(e.as_ref()), exit::USAGE);
        }
    }
}
