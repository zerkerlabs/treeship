//! OTLP/HTTP JSON exporter for Treeship artifacts.
//!
//! Each artifact becomes a single OTel span sent via HTTP POST to
//! `{endpoint}/v1/traces` using the OTLP/HTTP JSON protocol.
//! No opentelemetry crate needed -- just ureq + serde_json.

use treeship_core::storage::Record;

use super::config::OtelConfig;

/// Export a single artifact as an OTLP span over HTTP.
/// Best-effort: errors are returned but should never fail the caller's operation.
pub fn export_artifact(config: &OtelConfig, record: &Record) -> Result<(), String> {
    if !config.enabled {
        return Ok(());
    }

    let span_json = build_otlp_payload(config, record)?;

    let url = format!("{}/v1/traces", config.endpoint.trim_end_matches('/'));
    let mut req = ureq::post(&url)
        .set("Content-Type", "application/json");

    if let Some(ref auth) = config.auth_header {
        req = req.set("Authorization", auth);
    }

    req.send_string(&span_json)
        .map_err(|e| format!("otel export failed: {}", e))?;

    Ok(())
}

/// Send a lightweight test span to verify connectivity.
pub fn send_test_span(config: &OtelConfig) -> Result<(), String> {
    let trace_id = random_hex(16);
    let span_id = random_hex(8);
    let now_ns = now_unix_nano();

    let payload = serde_json::json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    attr_string("service.name", &config.service_name)
                ]
            },
            "scopeSpans": [{
                "scope": { "name": "treeship" },
                "spans": [{
                    "traceId": trace_id,
                    "spanId": span_id,
                    "name": "treeship.otel.test",
                    "kind": 1,
                    "startTimeUnixNano": format!("{}", now_ns),
                    "endTimeUnixNano": format!("{}", now_ns + 1_000_000),
                    "attributes": [
                        attr_string("treeship.test", "true")
                    ],
                    "status": { "code": 1 }
                }]
            }]
        }]
    });

    let url = format!("{}/v1/traces", config.endpoint.trim_end_matches('/'));
    let mut req = ureq::post(&url)
        .set("Content-Type", "application/json");

    if let Some(ref auth) = config.auth_header {
        req = req.set("Authorization", auth);
    }

    let body = serde_json::to_string(&payload)
        .map_err(|e| format!("json serialization failed: {}", e))?;

    req.send_string(&body)
        .map_err(|e| format!("otel test failed: {}", e))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn build_otlp_payload(config: &OtelConfig, record: &Record) -> Result<String, String> {
    let trace_id = artifact_id_to_trace_id(&record.artifact_id);
    let span_id = random_hex(8);

    // Decode the statement from the envelope payload
    let statement = decode_statement(record)?;

    let span_name = statement["action"]
        .as_str()
        .or_else(|| statement["type"].as_str())
        .unwrap_or("unknown")
        .to_string();

    // Timestamps
    let start_ns = rfc3339_to_unix_nano(&record.signed_at)
        .unwrap_or_else(|| now_unix_nano());

    let elapsed_ns = statement
        .get("meta")
        .and_then(|m| m.get("elapsedMs"))
        .and_then(|v| v.as_u64())
        .map(|ms| ms * 1_000_000)
        .unwrap_or(0);

    let end_ns = start_ns + elapsed_ns;

    // Build attributes
    let mut attrs = vec![
        attr_string("treeship.artifact_id", &record.artifact_id),
        attr_string("treeship.type", &record.payload_type),
        attr_string("treeship.signed", "true"),
        attr_string("treeship.key_id", &record.key_id),
    ];

    // Actor
    if let Some(actor) = statement["actor"].as_str() {
        attrs.push(attr_string("treeship.actor", actor));
    }

    // Parent ID
    if let Some(ref pid) = record.parent_id {
        attrs.push(attr_string("treeship.parent_id", pid));
    }

    // Hub / verify URL
    if let Some(ref url) = record.hub_url {
        attrs.push(attr_string("treeship.verify_url", url));
    }

    // Meta-derived attributes
    if let Some(meta) = statement.get("meta") {
        if let Some(exit_code) = meta.get("exitCode").and_then(|v| v.as_i64()) {
            attrs.push(attr_int("treeship.exit_code", exit_code));
        }
        if let Some(digest) = meta.get("output_digest").and_then(|v| v.as_str()) {
            attrs.push(attr_string("treeship.output_digest", digest));
        }
        if let Some(files) = meta.get("files_changed").and_then(|v| v.as_i64()) {
            attrs.push(attr_int("treeship.files_modified", files));
        }
        if let Some(gb) = meta.get("git_before").and_then(|v| v.as_str()) {
            attrs.push(attr_string("treeship.git_before", gb));
        }
        if let Some(ga) = meta.get("git_after").and_then(|v| v.as_str()) {
            attrs.push(attr_string("treeship.git_after", ga));
        }
        // Session info
        if let Some(sid) = meta.get("session_id").and_then(|v| v.as_str()) {
            attrs.push(attr_string("treeship.session_id", sid));
        }
    }

    // Approval nonce
    if let Some(nonce) = statement.get("approvalNonce").and_then(|v| v.as_str()) {
        attrs.push(attr_string("treeship.approval_nonce", nonce));
    }

    // Status: OK (1) or ERROR (2)
    let status_code = statement
        .get("meta")
        .and_then(|m| m.get("exitCode"))
        .and_then(|v| v.as_i64())
        .map(|c| if c == 0 { 1 } else { 2 })
        .unwrap_or(1);

    let payload = serde_json::json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    attr_string("service.name", &config.service_name)
                ]
            },
            "scopeSpans": [{
                "scope": { "name": "treeship" },
                "spans": [{
                    "traceId": trace_id,
                    "spanId": span_id,
                    "name": span_name,
                    "kind": 1,
                    "startTimeUnixNano": format!("{}", start_ns),
                    "endTimeUnixNano": format!("{}", end_ns),
                    "attributes": attrs,
                    "status": { "code": status_code }
                }]
            }]
        }]
    });

    serde_json::to_string(&payload)
        .map_err(|e| format!("json serialization failed: {}", e))
}

/// Decode the base64url-encoded statement payload from the DSSE envelope.
fn decode_statement(record: &Record) -> Result<serde_json::Value, String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let bytes = URL_SAFE_NO_PAD
        .decode(&record.envelope.payload)
        .map_err(|e| format!("base64 decode failed: {}", e))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("json parse failed: {}", e))
}

/// Derive a 32-hex-char trace ID from an artifact_id.
/// Takes the hex portion after "art_" and pads/truncates to 32 chars.
fn artifact_id_to_trace_id(artifact_id: &str) -> String {
    let hex_part = artifact_id.strip_prefix("art_").unwrap_or(artifact_id);
    if hex_part.len() >= 32 {
        hex_part[..32].to_string()
    } else {
        format!("{:0<32}", hex_part)
    }
}

fn random_hex(bytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

fn now_unix_nano() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Parse an RFC 3339 timestamp to Unix nanoseconds.
/// Handles basic ISO 8601 / RFC 3339 strings like "2026-03-26T10:00:00Z".
fn rfc3339_to_unix_nano(ts: &str) -> Option<u64> {
    // Minimal parser for "YYYY-MM-DDTHH:MM:SSZ" or with fractional seconds
    let s = ts.trim().trim_end_matches('Z');
    let (date_part, time_part) = s.split_once('T')?;
    let parts: Vec<&str> = date_part.split('-').collect();
    if parts.len() != 3 { return None; }

    let year: i64 = parts[0].parse().ok()?;
    let month: i64 = parts[1].parse().ok()?;
    let day: i64 = parts[2].parse().ok()?;

    let time_parts: Vec<&str> = time_part.split(':').collect();
    if time_parts.len() < 3 { return None; }

    let hour: i64 = time_parts[0].parse().ok()?;
    let min: i64 = time_parts[1].parse().ok()?;

    // Handle fractional seconds
    let sec_str = time_parts[2];
    let (sec_whole, frac_ns) = if let Some((whole, frac)) = sec_str.split_once('.') {
        let w: i64 = whole.parse().ok()?;
        // Pad/truncate fraction to 9 digits (nanoseconds)
        let mut f = frac.to_string();
        f.truncate(9);
        while f.len() < 9 { f.push('0'); }
        let ns: u64 = f.parse().ok()?;
        (w, ns)
    } else {
        (sec_str.parse::<i64>().ok()?, 0u64)
    };

    // Days from epoch (simplified -- good enough for 2000-2100 range)
    let days = days_from_civil(year, month, day)?;
    let secs = days * 86400 + hour * 3600 + min * 60 + sec_whole;
    if secs < 0 { return None; }
    Some(secs as u64 * 1_000_000_000 + frac_ns)
}

/// Convert a civil date to days since Unix epoch.
fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    // Adjust for months before March
    let (y, m) = if month <= 2 { (year - 1, month + 9) } else { (year, month - 3) };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days)
}

fn attr_string(key: &str, value: &str) -> serde_json::Value {
    serde_json::json!({
        "key": key,
        "value": { "stringValue": value }
    })
}

fn attr_int(key: &str, value: i64) -> serde_json::Value {
    serde_json::json!({
        "key": key,
        "value": { "intValue": format!("{}", value) }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc3339_to_unix_nano() {
        // 2026-03-26T10:00:00Z = 1774515600 seconds
        let ns = rfc3339_to_unix_nano("2026-03-26T10:00:00Z");
        assert!(ns.is_some());
        let ns = ns.unwrap();
        // Should be in the right ballpark (2026 epoch seconds ~ 1.77e9)
        assert!(ns > 1_774_000_000_000_000_000);
        assert!(ns < 1_775_000_000_000_000_000);
    }

    #[test]
    fn test_artifact_id_to_trace_id() {
        let id = "art_aabbccdd11223344aabbccdd11223344";
        let trace = artifact_id_to_trace_id(id);
        assert_eq!(trace.len(), 32);
        assert_eq!(trace, "aabbccdd11223344aabbccdd11223344");
    }

    #[test]
    fn test_artifact_id_short_padded() {
        let id = "art_aabb";
        let trace = artifact_id_to_trace_id(id);
        assert_eq!(trace.len(), 32);
        assert!(trace.starts_with("aabb"));
    }

    #[test]
    fn test_attr_string() {
        let a = attr_string("foo", "bar");
        assert_eq!(a["key"], "foo");
        assert_eq!(a["value"]["stringValue"], "bar");
    }
}
