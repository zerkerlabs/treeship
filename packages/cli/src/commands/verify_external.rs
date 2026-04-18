//! `treeship verify <url-or-path>` external mode.
//!
//! Handles three target shapes that the artifact-ID verify path does not:
//!
//! - HTTP/HTTPS URL pointing at a Hub-served receipt JSON document
//! - Filesystem path to a `.treeship` package directory
//! - Filesystem path to a `.agent` package directory (certificate-only verify)
//!
//! Plus the cross-verification path: receipt + `--certificate <path-or-url>`
//! validates that every tool the session called was authorized by the
//! certificate and that the two documents reference the same ship.
//!
//! Exit codes (set by the caller via process::exit):
//!   0 success
//!   1 verification failed (signature / Merkle / inclusion / determinism)
//!   2 cross-verification failed (cert mismatch / unauthorized tool / expired cert)
//!   3 network or filesystem error (could not fetch / could not read)

use std::path::{Path, PathBuf};

use treeship_core::agent::{verify_certificate, AgentCertificate};
use treeship_core::session::{read_package, verify_package, SessionReceipt, VerifyStatus};
use treeship_core::verify::{
    cross_verify_receipt_and_certificate, verify_receipt_json_checks, CertificateStatus,
    CrossVerifyResult, ShipIdStatus,
};

use crate::printer::{Format, Printer};

/// Outcome buckets used to pick an exit code without coupling to process::exit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalExit {
    Ok,
    VerifyFailed,
    CrossVerifyFailed,
    IoError,
}

impl ExternalExit {
    pub fn code(self) -> i32 {
        match self {
            Self::Ok => 0,
            Self::VerifyFailed => 1,
            Self::CrossVerifyFailed => 2,
            Self::IoError => 3,
        }
    }
}

/// Heuristic: does this look like a URL we should fetch?
pub fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

/// Heuristic: is this a path to something on disk (file or directory)?
pub fn is_local_path(s: &str) -> bool {
    Path::new(s).exists()
}

/// Run external verification. The dispatcher (commands::verify::run) decides
/// which mode to call based on the target shape.
pub fn run(
    target: &str,
    certificate: Option<&str>,
    printer: &Printer,
) -> ExternalExit {
    // Resolve the target into a parsed receipt or certificate.
    let target_kind = classify_target(target);
    let (receipt, package_checks, source_label, exit_for_load) = match target_kind {
        TargetKind::Url => match fetch_receipt_url(target) {
            Ok(receipt) => (Some(receipt), Vec::new(), format!("URL {target}"), None),
            Err(LoadError::Io(msg)) => {
                printer.failure("could not fetch receipt", &[("target", target), ("reason", &msg)]);
                return ExternalExit::IoError;
            }
            Err(LoadError::Parse(msg)) => {
                emit_step(printer, false, "Downloaded receipt", Some(&msg));
                return ExternalExit::VerifyFailed;
            }
        },
        TargetKind::TreeshipPackage(ref path) => {
            // verify_package does the full bag of checks (determinism + Merkle
            // + inclusion proofs + timeline order); we then surface them as
            // structured steps.
            let checks = match verify_package(path) {
                Ok(c) => c,
                Err(e) => {
                    printer.failure("could not read package", &[
                        ("path", &path.display().to_string()),
                        ("reason", &e.to_string()),
                    ]);
                    return ExternalExit::IoError;
                }
            };
            let receipt = read_package(path).ok();
            (receipt, checks, format!("package {}", path.display()), None)
        }
        TargetKind::AgentPackage(ref path) => {
            // Certificate-only verification path. Skip receipt entirely.
            return verify_agent_package_only(path, printer);
        }
        TargetKind::Unknown => {
            printer.failure("could not interpret target", &[
                ("target", target),
                ("hint", "expected URL, .treeship/.agent path, or use the artifact-ID form for local artifacts"),
            ]);
            return ExternalExit::IoError;
        }
    };

    if exit_for_load.is_some() {
        // unreachable today; reserved for future early-exit branches
        return exit_for_load.unwrap();
    }

    // Run JSON-level checks for URL mode (no on-disk package).
    let json_checks = receipt
        .as_ref()
        .map(verify_receipt_json_checks)
        .unwrap_or_default();

    // Combine. URL mode uses json_checks; package mode uses package_checks
    // (which is a superset). Pick the bigger one.
    let checks = if package_checks.is_empty() { json_checks } else { package_checks };

    let receipt = match receipt {
        Some(r) => r,
        None => {
            printer.failure("could not parse receipt", &[("target", target)]);
            return ExternalExit::VerifyFailed;
        }
    };

    // JSON output mode short-circuits the rest.
    if printer.format == Format::Json {
        return emit_json(printer, target, &source_label, &receipt, &checks, certificate);
    }

    // Header + per-step output.
    let receipt_ok = checks.iter().all(|c| c.status != VerifyStatus::Fail);
    let load_label = source_label_to_step(target_kind_label(&target_kind));
    emit_step(printer, true, &load_label, None);
    emit_checks_as_steps(printer, &checks);

    let mut overall = if receipt_ok { ExternalExit::Ok } else { ExternalExit::VerifyFailed };

    if receipt_ok {
        printer.blank();
        printer.info(&printer.green("Verified. This receipt is authentic."));
        printer.blank();
        emit_summary(printer, &receipt);
    } else {
        printer.blank();
        printer.failure("verification failed", &[("target", target)]);
    }

    // Cross-verify path.
    if let Some(cert_target) = certificate {
        if !receipt_ok {
            // Don't try to cross-verify against an unverified receipt.
            printer.blank();
            printer.warn("skipping cross-verification because receipt did not verify", &[]);
            return overall;
        }

        let cert = match load_certificate(cert_target) {
            Ok(c) => c,
            Err(LoadError::Io(msg)) => {
                printer.failure("could not load certificate", &[("certificate", cert_target), ("reason", &msg)]);
                return ExternalExit::IoError;
            }
            Err(LoadError::Parse(msg)) => {
                printer.failure("could not parse certificate", &[("certificate", cert_target), ("reason", &msg)]);
                return ExternalExit::VerifyFailed;
            }
        };

        match verify_certificate(&cert) {
            Ok(()) => emit_step(printer, true, "Certificate verified", None),
            Err(e) => {
                emit_step(printer, false, "Certificate verified", Some(&e.to_string()));
                return ExternalExit::CrossVerifyFailed;
            }
        }

        let now = now_rfc3339_utc();
        let result = cross_verify_receipt_and_certificate(&receipt, &cert, &now);

        let ship_ok = matches!(result.ship_id_status, ShipIdStatus::Match);
        let ship_msg = match &result.ship_id_status {
            ShipIdStatus::Match => "Ship IDs match".to_string(),
            ShipIdStatus::Mismatch { receipt, certificate } => {
                format!("Ship IDs mismatch (receipt={receipt}, certificate={certificate})")
            }
            ShipIdStatus::Unknown => "Receipt has no ship_id (legacy receipt; cannot cross-verify)".to_string(),
        };
        emit_step(printer, ship_ok, &ship_msg, None);

        let cert_valid = matches!(result.certificate_status, CertificateStatus::Valid);
        if !cert_valid {
            let detail = match &result.certificate_status {
                CertificateStatus::Expired { valid_until, now } => {
                    format!("Certificate expired at {valid_until} (now: {now})")
                }
                CertificateStatus::NotYetValid { issued_at, now } => {
                    format!("Certificate not yet valid (issued_at={issued_at}, now={now})")
                }
                CertificateStatus::Valid => unreachable!(),
            };
            emit_step(printer, false, "Certificate validity", Some(&detail));
        }

        let total_calls = result.authorized_tool_calls.len() + result.unauthorized_tool_calls.len();
        let calls_ok = result.unauthorized_tool_calls.is_empty();
        let calls_msg = if calls_ok {
            format!(
                "All {} tool call{} authorized by certificate",
                total_calls,
                if total_calls == 1 { "" } else { "s" }
            )
        } else {
            format!(
                "{} unauthorized tool call{}: {}",
                result.unauthorized_tool_calls.len(),
                if result.unauthorized_tool_calls.len() == 1 { "" } else { "s" },
                result.unauthorized_tool_calls.join(", ")
            )
        };
        emit_step(printer, calls_ok, &calls_msg, None);

        if result.ok() {
            printer.blank();
            printer.info(&printer.green("Complete trust loop verified."));
            printer.blank();
            emit_cross_verify_extras(printer, &result);
        } else {
            printer.blank();
            printer.failure("cross-verification failed", &[]);
            overall = ExternalExit::CrossVerifyFailed;
        }
    }

    overall
}

// ============================================================================
// Target classification + loaders
// ============================================================================

#[derive(Debug)]
enum TargetKind {
    Url,
    TreeshipPackage(PathBuf),
    AgentPackage(PathBuf),
    Unknown,
}

fn target_kind_label(k: &TargetKind) -> &'static str {
    match k {
        TargetKind::Url => "Downloaded receipt",
        TargetKind::TreeshipPackage(_) => "Loaded receipt package",
        TargetKind::AgentPackage(_) => "Loaded certificate",
        TargetKind::Unknown => "Loaded target",
    }
}

fn source_label_to_step(label: &str) -> String {
    label.to_string()
}

fn classify_target(target: &str) -> TargetKind {
    if is_url(target) {
        return TargetKind::Url;
    }
    let path = Path::new(target);
    if !path.exists() {
        return TargetKind::Unknown;
    }
    if path.is_dir() {
        if path.join("receipt.json").exists() {
            return TargetKind::TreeshipPackage(path.to_path_buf());
        }
        if path.join("certificate.json").exists() {
            return TargetKind::AgentPackage(path.to_path_buf());
        }
    }
    if path.is_file() {
        // A user might pass a path directly to a receipt.json or
        // certificate.json file rather than the package directory.
        if path.file_name().and_then(|n| n.to_str()) == Some("receipt.json") {
            if let Some(parent) = path.parent() {
                return TargetKind::TreeshipPackage(parent.to_path_buf());
            }
        }
        if path.file_name().and_then(|n| n.to_str()) == Some("certificate.json") {
            if let Some(parent) = path.parent() {
                return TargetKind::AgentPackage(parent.to_path_buf());
            }
        }
    }
    TargetKind::Unknown
}

#[derive(Debug)]
enum LoadError {
    Io(String),
    Parse(String),
}

/// Fetch a receipt JSON from a URL. Maps `/receipt/` to `/v1/receipt/` so the
/// human-readable mirror works alongside the JSON API path.
fn fetch_receipt_url(url: &str) -> Result<SessionReceipt, LoadError> {
    let api_url = url.replacen("/receipt/", "/v1/receipt/", 1);
    let resp = ureq::get(&api_url)
        .set("Accept", "application/json")
        .timeout(std::time::Duration::from_secs(15))
        .call()
        .map_err(|e| LoadError::Io(format!("HTTP request failed: {e}")))?;

    if resp.status() != 200 {
        return Err(LoadError::Io(format!(
            "HTTP {} from {}",
            resp.status(),
            api_url
        )));
    }

    let body = resp
        .into_string()
        .map_err(|e| LoadError::Io(format!("read response body: {e}")))?;

    let receipt: SessionReceipt = serde_json::from_str(&body)
        .map_err(|e| LoadError::Parse(format!("invalid receipt JSON: {e}")))?;
    Ok(receipt)
}

/// Load and parse a certificate from a path (file or directory) or URL.
fn load_certificate(target: &str) -> Result<AgentCertificate, LoadError> {
    if is_url(target) {
        let resp = ureq::get(target)
            .set("Accept", "application/json")
            .timeout(std::time::Duration::from_secs(15))
            .call()
            .map_err(|e| LoadError::Io(format!("HTTP request failed: {e}")))?;
        if resp.status() != 200 {
            return Err(LoadError::Io(format!("HTTP {} from {target}", resp.status())));
        }
        let body = resp
            .into_string()
            .map_err(|e| LoadError::Io(format!("read response body: {e}")))?;
        return serde_json::from_str(&body)
            .map_err(|e| LoadError::Parse(format!("invalid certificate JSON: {e}")));
    }

    let path = Path::new(target);
    let cert_path = if path.is_dir() {
        path.join("certificate.json")
    } else {
        path.to_path_buf()
    };
    let bytes = std::fs::read(&cert_path)
        .map_err(|e| LoadError::Io(format!("read {}: {e}", cert_path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| LoadError::Parse(format!("invalid certificate JSON: {e}")))
}

// ============================================================================
// Output helpers
// ============================================================================

fn emit_step(printer: &Printer, ok: bool, label: &str, detail: Option<&str>) {
    if printer.quiet || printer.format == Format::Json {
        return;
    }
    let icon = if ok {
        printer.green("✓")
    } else {
        printer.red("✗")
    };
    match detail {
        Some(d) => println!("  {icon}  {label}\n       {}", printer.dim(d)),
        None => println!("  {icon}  {label}"),
    }
}

fn emit_checks_as_steps(printer: &Printer, checks: &[treeship_core::session::VerifyCheck]) {
    for c in checks {
        let ok = c.status != VerifyStatus::Fail;
        let label = format_check_label(c);
        let detail = if ok { None } else { Some(c.detail.as_str()) };
        emit_step(printer, ok, &label, detail);
    }
}

fn format_check_label(c: &treeship_core::session::VerifyCheck) -> String {
    // Map internal check names to the spec'd checkmark labels where possible.
    match c.name.as_str() {
        "receipt.json" => "Receipt JSON parses".into(),
        "type" => "Receipt type recognized".into(),
        "determinism" => "Receipt round-trips deterministically".into(),
        "merkle_root" => "Merkle root verified".into(),
        "inclusion_proofs" => c.detail.clone(),
        "leaf_count" => "Leaf count matches artifact count".into(),
        "timeline_order" => "Timeline ordering verified".into(),
        "chain_linkage" => "Chain linkage intact".into(),
        n if n.starts_with("inclusion:") => format!("Inclusion proof {}", &n[10..]),
        other => other.to_string(),
    }
}

fn emit_summary(printer: &Printer, receipt: &SessionReceipt) {
    let mut fields: Vec<(&str, String)> = Vec::new();
    fields.push(("Session", receipt.session.id.clone()));
    if let Some(name) = &receipt.session.name {
        fields.push(("Name", name.clone()));
    }
    if let Some(ship) = &receipt.session.ship_id {
        fields.push(("Ship", ship.clone()));
    }
    // Pick a representative agent name from the graph.
    if let Some(node) = receipt.agent_graph.nodes.first() {
        fields.push(("Agent", node.agent_name.clone()));
    }
    if let Some(ms) = receipt.session.duration_ms {
        fields.push(("Duration", human_duration(ms)));
    }
    fields.push(("Actions", receipt.artifacts.len().to_string()));

    let max = fields.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (k, v) in &fields {
        let pad = " ".repeat(max - k.len());
        println!("  {k}:{pad}  {v}");
    }
}

fn emit_cross_verify_extras(printer: &Printer, r: &CrossVerifyResult) {
    if !r.authorized_tools_never_called.is_empty() {
        printer.dim_info(&format!(
            "  authorized but never called: {}",
            r.authorized_tools_never_called.join(", ")
        ));
    }
}

fn emit_json(
    printer: &Printer,
    target: &str,
    source_label: &str,
    receipt: &SessionReceipt,
    checks: &[treeship_core::session::VerifyCheck],
    certificate: Option<&str>,
) -> ExternalExit {
    let receipt_failed = checks.iter().any(|c| c.status == VerifyStatus::Fail);

    let cross = certificate.and_then(|cert_target| match load_certificate(cert_target) {
        Ok(cert) => {
            let cert_sig_ok = verify_certificate(&cert).is_ok();
            let now = now_rfc3339_utc();
            let result = cross_verify_receipt_and_certificate(receipt, &cert, &now);
            Some((cert_sig_ok, result))
        }
        Err(_) => None,
    });

    let mut out = serde_json::json!({
        "target": target,
        "source": source_label,
        "outcome": if receipt_failed { "fail" } else { "pass" },
        "receipt": {
            "session_id": receipt.session.id,
            "ship_id": receipt.session.ship_id,
            "schema_version": receipt.schema_version,
            "artifact_count": receipt.artifacts.len(),
        },
        "checks": checks.iter().map(|c| serde_json::json!({
            "name": c.name,
            "status": match c.status { VerifyStatus::Pass => "pass", VerifyStatus::Fail => "fail", VerifyStatus::Warn => "warn" },
            "detail": c.detail,
        })).collect::<Vec<_>>(),
    });

    if let Some((cert_ok, ref result)) = cross {
        out["cross_verify"] = serde_json::json!({
            "certificate_signature_valid": cert_ok,
            "ship_id_status": match &result.ship_id_status {
                ShipIdStatus::Match => "match",
                ShipIdStatus::Mismatch { .. } => "mismatch",
                ShipIdStatus::Unknown => "unknown",
            },
            "certificate_status": match &result.certificate_status {
                CertificateStatus::Valid => "valid",
                CertificateStatus::Expired { .. } => "expired",
                CertificateStatus::NotYetValid { .. } => "not_yet_valid",
            },
            "authorized_tool_calls": result.authorized_tool_calls.clone(),
            "unauthorized_tool_calls": result.unauthorized_tool_calls.clone(),
            "authorized_tools_never_called": result.authorized_tools_never_called.clone(),
            "ok": result.ok() && cert_ok,
        });
    }

    printer.json(&out);

    if receipt_failed {
        ExternalExit::VerifyFailed
    } else if let Some((cert_ok, ref result)) = cross {
        if !cert_ok || !result.ok() {
            ExternalExit::CrossVerifyFailed
        } else {
            ExternalExit::Ok
        }
    } else {
        ExternalExit::Ok
    }
}

fn verify_agent_package_only(path: &Path, printer: &Printer) -> ExternalExit {
    let cert_path = path.join("certificate.json");
    let bytes = match std::fs::read(&cert_path) {
        Ok(b) => b,
        Err(e) => {
            printer.failure("could not read certificate.json", &[
                ("path", &cert_path.display().to_string()),
                ("reason", &e.to_string()),
            ]);
            return ExternalExit::IoError;
        }
    };
    let cert: AgentCertificate = match serde_json::from_slice(&bytes) {
        Ok(c) => c,
        Err(e) => {
            printer.failure("could not parse certificate", &[("reason", &e.to_string())]);
            return ExternalExit::VerifyFailed;
        }
    };

    if printer.format == Format::Json {
        let sig_ok = verify_certificate(&cert).is_ok();
        printer.json(&serde_json::json!({
            "target": path.display().to_string(),
            "outcome": if sig_ok { "pass" } else { "fail" },
            "certificate": {
                "ship_id": cert.identity.ship_id,
                "agent_name": cert.identity.agent_name,
                "issued_at": cert.identity.issued_at,
                "valid_until": cert.identity.valid_until,
                "schema_version": cert.schema_version,
                "signature_valid": sig_ok,
            },
        }));
        return if sig_ok { ExternalExit::Ok } else { ExternalExit::VerifyFailed };
    }

    emit_step(printer, true, &format!("Loaded certificate from {}", path.display()), None);
    match verify_certificate(&cert) {
        Ok(()) => emit_step(printer, true, "Certificate signature valid (Ed25519)", None),
        Err(e) => {
            emit_step(printer, false, "Certificate signature valid (Ed25519)", Some(&e.to_string()));
            return ExternalExit::VerifyFailed;
        }
    }
    let sv = cert.schema_version.as_deref().unwrap_or("0");
    emit_step(printer, true, &format!("Schema version: {sv}"), None);

    printer.blank();
    printer.info(&printer.green("Certificate verified."));
    printer.blank();

    let fields: Vec<(&str, String)> = vec![
        ("Agent", cert.identity.agent_name.clone()),
        ("Ship", cert.identity.ship_id.clone()),
        ("Issued", cert.identity.issued_at.clone()),
        ("Valid until", cert.identity.valid_until.clone()),
        ("Tools", cert.capabilities.tools.len().to_string()),
    ];
    let max = fields.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
    for (k, v) in &fields {
        let pad = " ".repeat(max - k.len());
        println!("  {k}:{pad}  {v}");
    }

    ExternalExit::Ok
}

// ============================================================================
// Time + duration helpers
// ============================================================================

fn human_duration(ms: u64) -> String {
    let total_secs = ms / 1000;
    let mins = total_secs / 60;
    let secs = total_secs % 60;
    if mins > 0 {
        format!("{mins}m {secs:02}s")
    } else if total_secs > 0 {
        format!("{total_secs}s")
    } else {
        format!("{ms}ms")
    }
}

fn now_rfc3339_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    treeship_core::statements::unix_to_rfc3339(secs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_url() {
        assert!(matches!(classify_target("https://api.treeship.dev/v1/receipt/x"), TargetKind::Url));
        assert!(matches!(classify_target("http://localhost:8080/v1/receipt/x"), TargetKind::Url));
    }

    #[test]
    fn classify_unknown_for_nonexistent_path() {
        assert!(matches!(classify_target("/no/such/path/here"), TargetKind::Unknown));
        assert!(matches!(classify_target("art_abc123"), TargetKind::Unknown));
    }

    #[test]
    fn human_duration_formats() {
        assert_eq!(human_duration(500), "500ms");
        assert_eq!(human_duration(2_000), "2s");
        assert_eq!(human_duration(62_000), "1m 02s");
        assert_eq!(human_duration(3_661_000), "61m 01s");
    }

    #[test]
    fn exit_code_mapping() {
        assert_eq!(ExternalExit::Ok.code(), 0);
        assert_eq!(ExternalExit::VerifyFailed.code(), 1);
        assert_eq!(ExternalExit::CrossVerifyFailed.code(), 2);
        assert_eq!(ExternalExit::IoError.code(), 3);
    }
}
