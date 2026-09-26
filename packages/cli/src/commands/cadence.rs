//! Checkpoint cadence: `checkpoint.every` in `.treeship/config.yaml`.
//!
//! Opt-in and off by default: nothing leaves the machine without an
//! explicit setting. When set, the daemon seals a checkpoint over the local
//! artifacts and publishes it to the attached hub every interval, and logs
//! each publish. The checkpoint is signed by this ship's key, as every
//! checkpoint is; the hub stores and verifies it and signs nothing (it is
//! not a witness). The public hub's latest checkpoint had gone stale for
//! seven weeks because no ship published one (0.31.9 full test, WEB-4).

use std::path::Path;
use std::time::Duration;

/// The smallest interval honoured, so a typo like `every: 1s` cannot turn
/// the daemon into a checkpoint firehose.
pub const MIN_EVERY: Duration = Duration::from_secs(5 * 60);

/// `checkpoint.every` from config.yaml, or `None` when unset or unusable.
pub fn checkpoint_every(config_yaml: &Path) -> Option<Duration> {
    let text = std::fs::read_to_string(config_yaml).ok()?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).ok()?;
    let raw = doc.get("checkpoint")?.get("every")?;
    let every = match raw {
        serde_yaml::Value::String(s) => parse_every(s)?,
        serde_yaml::Value::Number(n) => Duration::from_secs(n.as_u64()?),
        _ => return None,
    };
    Some(every.max(MIN_EVERY))
}

/// `30d`, `12h`, `45m`, `600s`.
pub fn parse_every(raw: &str) -> Option<Duration> {
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
    let n: u64 = digits.trim().parse().ok()?;
    (n > 0).then(|| Duration::from_secs(n.saturating_mul(mult)))
}

/// Is a publish due? `latest_signed_at` is the newest local checkpoint's
/// RFC 3339 time (none means never), `now` is unix seconds.
pub fn due(latest_signed_at: Option<&str>, every: Duration, now: u64) -> bool {
    match latest_signed_at.and_then(treeship_core::statements::parse_rfc3339_to_unix) {
        Some(last) => now.saturating_sub(last) >= every.as_secs(),
        None => true,
    }
}

/// A human label for the interval: `6h`, `2d`, `45m`.
pub fn label(every: Duration) -> String {
    let s = every.as_secs();
    if s.is_multiple_of(86_400) {
        format!("{}d", s / 86_400)
    } else if s.is_multiple_of(3_600) {
        format!("{}h", s / 3_600)
    } else if s.is_multiple_of(60) {
        format!("{}m", s / 60)
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intervals_parse_and_floor() {
        assert_eq!(parse_every("6h"), Some(Duration::from_secs(21_600)));
        assert_eq!(parse_every("2d"), Some(Duration::from_secs(172_800)));
        assert_eq!(parse_every("45m"), Some(Duration::from_secs(2_700)));
        assert_eq!(parse_every("0h"), None);
        assert_eq!(parse_every("soon"), None);
        let dir = tempfile::tempdir().unwrap();
        let yaml = dir.path().join("config.yaml");
        std::fs::write(&yaml, "treeship:\n  version: 1\ncheckpoint:\n  every: 1s\n").unwrap();
        assert_eq!(checkpoint_every(&yaml), Some(MIN_EVERY));
        std::fs::write(&yaml, "treeship:\n  version: 1\n").unwrap();
        assert_eq!(checkpoint_every(&yaml), None);
        std::fs::write(&yaml, "checkpoint:\n  every: 12h\n").unwrap();
        assert_eq!(checkpoint_every(&yaml), Some(Duration::from_secs(43_200)));
    }

    #[test]
    fn due_when_never_or_old() {
        let every = Duration::from_secs(3_600);
        assert!(due(None, every, 1_000_000));
        assert!(due(Some("1970-01-01T00:00:00Z"), every, 10_000));
        assert!(!due(Some("1970-01-01T02:00:00Z"), every, 7_200 + 60));
        assert!(due(Some("1970-01-01T02:00:00Z"), every, 7_200 + 3_600));
        assert_eq!(label(every), "1h");
        assert_eq!(label(Duration::from_secs(172_800)), "2d");
    }
}
