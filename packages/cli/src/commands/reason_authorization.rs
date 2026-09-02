//! Atomic Zerker Reason verification and Treeship receipt signing.
//!
//! The command reads one bounded authorization bundle into memory, sends those
//! exact bytes to `reason verify-authorization-bundle`, and only after a strict
//! verified+authorized result commits their SHA-256 digest into a signed
//! Treeship receipt. No key or artifact store is opened before Reason succeeds.

use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use treeship_core::{
    attestation::sign,
    statements::{payload_type, ReceiptStatement},
    storage::Record,
};

use crate::{ctx, printer::Printer};

const BUNDLE_SCHEMA: &str = "zerker.reason.authorization-bundle.v1";
const CERTIFICATE_SCHEMA: &str = "zerker.reason.authorization.v1";
const VERIFICATION_SCHEMA: &str = "zerker.reason.authorization-verification.v1";
const RECEIPT_KIND: &str = "reason.authorization.v1";
const REASON_SYSTEM: &str = "system://zerker-reason";
const MAX_INPUT_BYTES: usize = 1 << 20;
const MAX_OUTPUT_BYTES: usize = 64 << 10;
const POLL_INTERVAL: Duration = Duration::from_millis(10);

pub struct Args {
    pub bundle_file: String,
    pub reason_bin: String,
    pub timeout_ms: u64,
    pub config: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleForReceipt {
    schema: String,
    #[serde(rename = "request")]
    _request: Value,
    certificate: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct VerificationOutput {
    schema: String,
    status: String,
    authorization_status: String,
    request_digest: String,
    reasoning_result_digest: String,
}

struct CapturedOutput {
    bytes: Vec<u8>,
    overflow: bool,
}

/// Verify one Reason bundle and sign a receipt that commits to its exact bytes.
pub fn run(args: Args, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    if args.timeout_ms == 0 {
        return Err("--timeout-ms must be greater than zero; no receipt was signed".into());
    }

    // One read, before either verifier or signer use. A path cannot be swapped
    // between verification and commitment because neither stage reopens it.
    let bundle_bytes = read_bundle(&args.bundle_file)?;
    let bundle_digest = sha256_digest(&bundle_bytes);
    let verification = verify_with_reason(
        &args.reason_bin,
        &bundle_bytes,
        Duration::from_millis(args.timeout_ms),
    )?;
    let bundle: BundleForReceipt = serde_json::from_slice(&bundle_bytes).map_err(|e| {
        format!(
            "verified Reason bundle could not be decoded for signing: {e}; no receipt was signed"
        )
    })?;

    if bundle.schema != BUNDLE_SCHEMA {
        return Err(format!(
            "verified Reason bundle has schema {:?}, expected {BUNDLE_SCHEMA:?}; no receipt was signed",
            bundle.schema
        )
        .into());
    }
    let certificate = bundle.certificate.as_object().ok_or_else(|| {
        "verified Reason bundle certificate is not an object; no receipt was signed".to_string()
    })?;
    if certificate.get("schema").and_then(Value::as_str) != Some(CERTIFICATE_SCHEMA)
        || certificate.get("status").and_then(Value::as_str) != Some("authorized")
        || certificate.get("request_digest").and_then(Value::as_str)
            != Some(verification.request_digest.as_str())
    {
        return Err(
            "Reason output does not match an authorized v1 certificate in the verified bundle; no receipt was signed"
                .into(),
        );
    }

    // Reason owns semantic validation. Treeship also applies the registered
    // structural predicate before signing so the dedicated and generic schema
    // surfaces cannot disagree about the receipt payload shape.
    treeship_core::predicates::validate(RECEIPT_KIND, Some(&bundle.certificate))
        .map_err(|e| format!("verified Reason certificate failed Treeship predicate validation: {e}; no receipt was signed"))?;

    // Opening the key and artifact stores happens only after every verifier
    // gate above has passed. Failures cannot create a signed side effect.
    let ctx = ctx::open(args.config.as_deref())?;
    let mut statement = ReceiptStatement::new(REASON_SYSTEM, RECEIPT_KIND);
    statement.payload = Some(bundle.certificate);
    statement.payload_digest = Some(bundle_digest.clone());
    statement.meta = Some(serde_json::json!({
        "authorization_bundle": {
            "schema": BUNDLE_SCHEMA,
            "digest": bundle_digest,
        },
        "reason_verification": verification,
    }));

    let signer = ctx.keys.default_signer()?;
    let receipt_payload_type = payload_type("receipt");
    let signed = sign(&receipt_payload_type, &statement, signer.as_ref())?;
    ctx.storage.write(&Record {
        artifact_id: signed.artifact_id.clone(),
        digest: signed.digest.clone(),
        payload_type: receipt_payload_type,
        key_id: signer.key_id().to_string(),
        signed_at: statement.timestamp.clone(),
        parent_id: None,
        envelope: signed.envelope,
        hub_url: None,
        anchors: Vec::new(),
    })?;
    super::attest::write_last(&ctx.config.storage_dir, &signed.artifact_id);

    printer.success(
        "Reason authorization verified and attested",
        &[
            ("id", &signed.artifact_id),
            ("request", &verification.request_digest),
            ("bundle", &bundle_digest),
            ("signed", &statement.timestamp),
        ],
    );
    printer.hint(&format!("treeship verify {}", signed.artifact_id));
    printer.blank();
    Ok(())
}

fn read_bundle(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = if path == "-" {
        read_bounded(io::stdin().lock(), MAX_INPUT_BYTES)?
    } else {
        // Security-sensitive single-open read: the same descriptor is bounded
        // and consumed, and the path is never resolved again.
        read_bounded(File::open(path)?, MAX_INPUT_BYTES)?
    };
    Ok(bytes)
}

fn read_bounded(reader: impl Read, limit: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Reason authorization bundle exceeds the {limit}-byte limit"),
        ));
    }
    Ok(bytes)
}

fn verify_with_reason(
    binary: &str,
    bundle: &[u8],
    timeout: Duration,
) -> Result<VerificationOutput, Box<dyn std::error::Error>> {
    let resolved = resolve_binary(binary)?;
    let mut command = Command::new(&resolved);
    command
        .args([
            "--format",
            "json",
            "verify-authorization-bundle",
            "-",
            "--require-authorized",
        ])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command);

    let mut child = command.spawn().map_err(|e| {
        format!(
            "could not start Reason verifier {}: {e}; no receipt was signed",
            resolved.display()
        )
    })?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or("Reason verifier stdin was unavailable; no receipt was signed")?;
    let stdout = child
        .stdout
        .take()
        .ok_or("Reason verifier stdout was unavailable; no receipt was signed")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("Reason verifier stderr was unavailable; no receipt was signed")?;

    let input = bundle.to_vec();
    let writer = thread::spawn(move || -> io::Result<()> {
        stdin.write_all(&input)?;
        stdin.flush()
    });
    let stdout_reader = thread::spawn(move || capture_output(stdout, MAX_OUTPUT_BYTES));
    let stderr_reader = thread::spawn(move || capture_output(stderr, MAX_OUTPUT_BYTES));

    let status = wait_bounded(&mut child, timeout)?;
    // The verifier contract is one bounded process. Kill any descendants that
    // outlived their parent before joining pipe readers; otherwise an inherited
    // descriptor could keep this command blocked after a forged success exit.
    kill_process_group(&mut child);
    let write_result = writer
        .join()
        .map_err(|_| "Reason verifier stdin writer panicked; no receipt was signed")?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| "Reason verifier stdout reader panicked; no receipt was signed")??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| "Reason verifier stderr reader panicked; no receipt was signed")??;

    if let Err(error) = write_result {
        return Err(format!(
            "Reason verifier did not consume the complete authorization bundle: {error}; no receipt was signed"
        )
        .into());
    }
    if stdout.overflow || stderr.overflow {
        return Err(
            "Reason verifier output exceeded the 65536-byte limit; no receipt was signed".into(),
        );
    }
    if !status.success() {
        return Err(format!(
            "Reason verifier rejected or did not authorize the bundle (exit {}); no receipt was signed",
            exit_label(status)
        )
        .into());
    }

    let verification: VerificationOutput = serde_json::from_slice(&stdout.bytes).map_err(|e| {
        format!("Reason verifier returned malformed JSON: {e}; no receipt was signed")
    })?;
    if verification.schema != VERIFICATION_SCHEMA
        || verification.status != "verified"
        || verification.authorization_status != "authorized"
        || !valid_digest(&verification.request_digest)
        || !valid_digest(&verification.reasoning_result_digest)
    {
        return Err("Reason verifier did not return the exact v1 verified+authorized contract; no receipt was signed".into());
    }
    Ok(verification)
}

fn wait_bounded(
    child: &mut Child,
    timeout: Duration,
) -> Result<ExitStatus, Box<dyn std::error::Error>> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or("Reason verifier timeout is too large; no receipt was signed")?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                kill_process_group(child);
                let _ = child.wait();
                return Err(format!(
                    "could not wait for Reason verifier: {error}; no receipt was signed"
                )
                .into());
            }
        }
        let now = Instant::now();
        if now >= deadline {
            kill_process_group(child);
            let _ = child.wait();
            return Err(format!(
                "Reason verifier timed out after {} ms; no receipt was signed",
                timeout.as_millis()
            )
            .into());
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
}

fn capture_output(mut reader: impl Read, limit: usize) -> io::Result<CapturedOutput> {
    let mut bytes = Vec::with_capacity(limit);
    let mut overflow = false;
    let mut chunk = [0_u8; 8192];
    loop {
        let count = reader.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        let remaining = limit.saturating_sub(bytes.len());
        let retained = remaining.min(count);
        bytes.extend_from_slice(&chunk[..retained]);
        overflow |= retained != count;
        // Continue draining after overflow so a malicious verifier cannot fill
        // its pipe and prevent the timeout/exit path from making progress.
    }
    Ok(CapturedOutput { bytes, overflow })
}

fn resolve_binary(binary: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if binary.trim().is_empty() {
        return Err("--reason-bin must not be empty; no receipt was signed".into());
    }
    let candidate = Path::new(binary);
    if candidate.components().count() > 1 {
        return Ok(candidate.to_path_buf());
    }
    let path = env::var_os("PATH")
        .ok_or("PATH is not set and --reason-bin is not a path; no receipt was signed")?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(binary);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(format!("could not find Reason verifier {binary:?} on PATH; no receipt was signed").into())
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn exit_label(status: ExitStatus) -> String {
    status
        .code()
        .map_or_else(|| "by signal".to_string(), |code| code.to_string())
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn kill_process_group(child: &mut Child) {
    // SAFETY: `child.id()` is the process-group id established immediately
    // before spawn. killpg receives no pointers and SIGKILL cannot invoke code
    // in this process. Falling back to Child::kill handles a setup race.
    let killed = unsafe { libc::killpg(child.id() as libc::pid_t, libc::SIGKILL) } == 0;
    if !killed {
        let _ = child.kill();
    }
}

#[cfg(not(unix))]
fn kill_process_group(child: &mut Child) {
    let _ = child.kill();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reader_rejects_the_sentinel_byte() {
        let error = read_bounded("12345".as_bytes(), 4).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn digest_validation_rejects_uppercase_and_wrong_length() {
        assert!(valid_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!valid_digest(&format!("sha256:{}", "A".repeat(64))));
        assert!(!valid_digest(&format!("sha256:{}", "a".repeat(63))));
    }
}
