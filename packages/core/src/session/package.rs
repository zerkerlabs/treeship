//! `.treeship` package builder and reader.
//!
//! A `.treeship` package is a directory (or tar archive) containing:
//!
//! - `receipt.json`   -- the canonical Session Receipt
//! - `merkle.json`    -- standalone Merkle tree data
//! - `render.json`    -- Explorer render hints
//! - `artifacts/`     -- referenced artifact payloads
//! - `proofs/`        -- inclusion proofs and zk proofs
//! - `preview.html`   -- static preview (optional)

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::receipt::{SessionReceipt, RECEIPT_TYPE};

/// Errors from package operations.
#[derive(Debug)]
pub enum PackageError {
    Io(std::io::Error),
    Json(serde_json::Error),
    InvalidPackage(String),
}

impl std::fmt::Display for PackageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "package io: {e}"),
            Self::Json(e) => write!(f, "package json: {e}"),
            Self::InvalidPackage(msg) => write!(f, "invalid package: {msg}"),
        }
    }
}

impl std::error::Error for PackageError {}
impl From<std::io::Error> for PackageError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}
impl From<serde_json::Error> for PackageError {
    fn from(e: serde_json::Error) -> Self { Self::Json(e) }
}

/// Manifest file inside the package root.
const RECEIPT_FILE: &str = "receipt.json";
const MERKLE_FILE: &str = "merkle.json";
const RENDER_FILE: &str = "render.json";
const ARTIFACTS_DIR: &str = "artifacts";
const PROOFS_DIR: &str = "proofs";
const PREVIEW_FILE: &str = "preview.html";

/// Result of building a package.
pub struct PackageOutput {
    /// Path to the package directory.
    pub path: PathBuf,
    /// SHA-256 digest of the canonical receipt.json.
    pub receipt_digest: String,
    /// Merkle root hex (if present).
    pub merkle_root: Option<String>,
    /// Number of files in the package.
    pub file_count: usize,
}

/// Build a `.treeship` package directory from a composed receipt.
///
/// Writes all package files into `output_dir/<session_id>.treeship/`.
/// Returns metadata about the written package.
pub fn build_package(
    receipt: &SessionReceipt,
    output_dir: &Path,
) -> Result<PackageOutput, PackageError> {
    let session_id = &receipt.session.id;
    let pkg_dir = output_dir.join(format!("{session_id}.treeship"));

    std::fs::create_dir_all(&pkg_dir)?;
    std::fs::create_dir_all(pkg_dir.join(ARTIFACTS_DIR))?;
    std::fs::create_dir_all(pkg_dir.join(PROOFS_DIR))?;

    let mut file_count = 0usize;

    // 1. receipt.json -- canonical serialization
    let receipt_bytes = serde_json::to_vec_pretty(receipt)?;
    std::fs::write(pkg_dir.join(RECEIPT_FILE), &receipt_bytes)?;
    file_count += 1;

    let receipt_hash = Sha256::digest(&receipt_bytes);
    let receipt_digest = format!("sha256:{}", hex::encode(receipt_hash));

    // 2. merkle.json -- standalone copy of the Merkle section
    let merkle_bytes = serde_json::to_vec_pretty(&receipt.merkle)?;
    std::fs::write(pkg_dir.join(MERKLE_FILE), &merkle_bytes)?;
    file_count += 1;

    // 3. render.json
    let render_bytes = serde_json::to_vec_pretty(&receipt.render)?;
    std::fs::write(pkg_dir.join(RENDER_FILE), &render_bytes)?;
    file_count += 1;

    // 4. Write inclusion proofs as individual files
    for proof_entry in &receipt.merkle.inclusion_proofs {
        let proof_bytes = serde_json::to_vec_pretty(proof_entry)?;
        let filename = format!("{}.proof.json", proof_entry.artifact_id);
        std::fs::write(pkg_dir.join(PROOFS_DIR).join(filename), &proof_bytes)?;
        file_count += 1;
    }

    // 5. preview.html stub
    if receipt.render.generate_preview {
        let preview = generate_preview_html(receipt);
        std::fs::write(pkg_dir.join(PREVIEW_FILE), preview.as_bytes())?;
        file_count += 1;
    }

    Ok(PackageOutput {
        path: pkg_dir,
        receipt_digest,
        merkle_root: receipt.merkle.root.clone(),
        file_count,
    })
}

/// Read and parse a `.treeship` package from disk.
pub fn read_package(pkg_dir: &Path) -> Result<SessionReceipt, PackageError> {
    let receipt_path = pkg_dir.join(RECEIPT_FILE);
    if !receipt_path.exists() {
        return Err(PackageError::InvalidPackage(
            format!("missing {RECEIPT_FILE} in {}", pkg_dir.display()),
        ));
    }
    let bytes = std::fs::read(&receipt_path)?;
    let receipt: SessionReceipt = serde_json::from_slice(&bytes)?;

    if receipt.type_ != RECEIPT_TYPE {
        return Err(PackageError::InvalidPackage(
            format!("unexpected type: {} (expected {RECEIPT_TYPE})", receipt.type_),
        ));
    }

    Ok(receipt)
}

/// Verify a `.treeship` package locally.
///
/// Returns a list of check results. All must pass for the package to be valid.
pub fn verify_package(pkg_dir: &Path) -> Result<Vec<VerifyCheck>, PackageError> {
    let mut checks = Vec::new();

    // 1. receipt.json exists and parses
    let receipt = match read_package(pkg_dir) {
        Ok(r) => {
            checks.push(VerifyCheck::pass("receipt.json", "Parses as valid Session Receipt"));
            r
        }
        Err(e) => {
            checks.push(VerifyCheck::fail("receipt.json", &format!("Failed to parse: {e}")));
            return Ok(checks);
        }
    };

    // 2. Type field
    if receipt.type_ == RECEIPT_TYPE {
        checks.push(VerifyCheck::pass("type", "Correct receipt type"));
    } else {
        checks.push(VerifyCheck::fail("type", &format!("Expected {RECEIPT_TYPE}, got {}", receipt.type_)));
    }

    // 3. Determinism: re-serialize and check digest matches
    let receipt_path = pkg_dir.join(RECEIPT_FILE);
    let on_disk = std::fs::read(&receipt_path)?;
    let re_serialized = serde_json::to_vec_pretty(&receipt)?;
    if on_disk == re_serialized {
        checks.push(VerifyCheck::pass("determinism", "receipt.json round-trips identically"));
    } else {
        // Not a hard failure -- pretty-print whitespace may differ
        checks.push(VerifyCheck::warn("determinism", "receipt.json does not byte-match after re-serialization"));
    }

    // 4. Merkle root re-computation
    if !receipt.artifacts.is_empty() {
        let mut tree = crate::merkle::MerkleTree::new();
        for art in &receipt.artifacts {
            tree.append(&art.artifact_id);
        }
        let root_bytes = tree.root();
        let recomputed_root = root_bytes
            .map(|r| format!("mroot_{}", hex::encode(r)));
        let root_hex = root_bytes
            .map(|r| hex::encode(r))
            .unwrap_or_default();

        if recomputed_root == receipt.merkle.root {
            checks.push(VerifyCheck::pass("merkle_root", "Merkle root matches recomputed value"));
        } else {
            checks.push(VerifyCheck::fail(
                "merkle_root",
                &format!(
                    "Mismatch: on-disk {:?} vs recomputed {:?}",
                    receipt.merkle.root, recomputed_root
                ),
            ));
        }

        // 5. Verify each inclusion proof
        for proof_entry in &receipt.merkle.inclusion_proofs {
            let verified = crate::merkle::MerkleTree::verify_proof(
                &root_hex,
                &proof_entry.artifact_id,
                &proof_entry.proof,
            );
            if verified {
                checks.push(VerifyCheck::pass(
                    &format!("inclusion:{}", proof_entry.artifact_id),
                    "Inclusion proof valid",
                ));
            } else {
                checks.push(VerifyCheck::fail(
                    &format!("inclusion:{}", proof_entry.artifact_id),
                    "Inclusion proof failed verification",
                ));
            }
        }
    } else {
        checks.push(VerifyCheck::warn("merkle_root", "No artifacts to verify"));
    }

    // 6. Leaf count matches artifacts
    if receipt.merkle.leaf_count == receipt.artifacts.len() {
        checks.push(VerifyCheck::pass("leaf_count", "Leaf count matches artifact count"));
    } else {
        checks.push(VerifyCheck::fail(
            "leaf_count",
            &format!("leaf_count {} != artifact count {}", receipt.merkle.leaf_count, receipt.artifacts.len()),
        ));
    }

    // 7. Timeline ordering (determinism rule: timestamp, sequence_no, event_id)
    let ordered = receipt.timeline.windows(2).all(|w| {
        (&w[0].timestamp, w[0].sequence_no, &w[0].event_id)
            <= (&w[1].timestamp, w[1].sequence_no, &w[1].event_id)
    });
    if ordered {
        checks.push(VerifyCheck::pass("timeline_order", "Timeline is correctly ordered"));
    } else {
        checks.push(VerifyCheck::fail("timeline_order", "Timeline entries are not in deterministic order"));
    }

    Ok(checks)
}

/// A single verification check result.
#[derive(Debug, Clone)]
pub struct VerifyCheck {
    pub name: String,
    pub status: VerifyStatus,
    pub detail: String,
}

/// Status of a verification check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyStatus {
    Pass,
    Fail,
    Warn,
}

impl VerifyCheck {
    fn pass(name: &str, detail: &str) -> Self {
        Self { name: name.into(), status: VerifyStatus::Pass, detail: detail.into() }
    }
    fn fail(name: &str, detail: &str) -> Self {
        Self { name: name.into(), status: VerifyStatus::Fail, detail: detail.into() }
    }
    fn warn(name: &str, detail: &str) -> Self {
        Self { name: name.into(), status: VerifyStatus::Warn, detail: detail.into() }
    }
}

impl VerifyCheck {
    pub fn passed(&self) -> bool {
        self.status == VerifyStatus::Pass
    }
}

/// Generate a minimal static preview HTML for the session.
fn generate_preview_html(receipt: &SessionReceipt) -> String {
    let session = &receipt.session;
    let p = &receipt.participants;
    let se_files = receipt.side_effects.files_written.len();
    let se_tools = receipt.side_effects.tool_invocations.len();
    let merkle_root = receipt.merkle.root.as_deref().unwrap_or("none");
    let duration = session.duration_ms
        .map(|ms| format_duration(ms))
        .unwrap_or_else(|| "unknown".into());

    let agents_html: String = receipt.agent_graph.nodes.iter()
        .map(|n| format!(
            "<li><strong>{}</strong> ({}){}</li>",
            n.agent_name,
            n.host_id,
            n.agent_role.as_ref().map(|r| format!(" -- {r}")).unwrap_or_default(),
        ))
        .collect::<Vec<_>>()
        .join("\n        ");

    let timeline_html: String = receipt.timeline.iter()
        .map(|t| format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            t.timestamp, t.event_type, t.agent_name,
            t.summary.as_deref().unwrap_or(""),
        ))
        .collect::<Vec<_>>()
        .join("\n          ");

    format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Session Report: {session_id}</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
           background: #0a0a0a; color: #e0e0e0; padding: 2rem; max-width: 960px; margin: 0 auto; }}
    h1 {{ color: #fff; margin-bottom: 0.25rem; font-size: 1.5rem; }}
    .subtitle {{ color: #888; margin-bottom: 2rem; font-size: 0.875rem; }}
    .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
              font-size: 0.75rem; font-weight: 600; }}
    .badge-pass {{ background: #1a3a1a; color: #4ade80; }}
    .badge-status {{ background: #1a2a3a; color: #60a5fa; }}
    .card {{ background: #141414; border: 1px solid #252525; border-radius: 8px;
             padding: 1.25rem; margin-bottom: 1rem; }}
    .card h2 {{ font-size: 1rem; color: #aaa; margin-bottom: 0.75rem; text-transform: uppercase;
                letter-spacing: 0.05em; font-weight: 500; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem; }}
    .stat {{ text-align: center; }}
    .stat .value {{ font-size: 1.5rem; font-weight: 700; color: #fff; }}
    .stat .label {{ font-size: 0.75rem; color: #888; margin-top: 0.15rem; }}
    ul {{ list-style: none; }}
    ul li {{ padding: 0.3rem 0; border-bottom: 1px solid #1a1a1a; font-size: 0.875rem; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.8rem; }}
    th, td {{ text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #1a1a1a; }}
    th {{ color: #888; font-weight: 500; }}
    .mono {{ font-family: 'SF Mono', 'Fira Code', monospace; font-size: 0.8rem; color: #60a5fa; }}
    .footer {{ margin-top: 2rem; text-align: center; color: #555; font-size: 0.75rem; }}
  </style>
</head>
<body>
  <h1>{name}</h1>
  <p class="subtitle">
    <span class="badge badge-status">{status:?}</span>
    <span class="mono">{session_id}</span>
  </p>

  <div class="card">
    <h2>Session Summary</h2>
    <div class="grid">
      <div class="stat"><div class="value">{total_agents}</div><div class="label">Agents</div></div>
      <div class="stat"><div class="value">{spawned}</div><div class="label">Spawned</div></div>
      <div class="stat"><div class="value">{handoffs}</div><div class="label">Handoffs</div></div>
      <div class="stat"><div class="value">{max_depth}</div><div class="label">Max Depth</div></div>
      <div class="stat"><div class="value">{hosts}</div><div class="label">Hosts</div></div>
      <div class="stat"><div class="value">{duration}</div><div class="label">Duration</div></div>
    </div>
  </div>

  <div class="card">
    <h2>Participants</h2>
    <ul>
        {agents_html}
    </ul>
  </div>

  <div class="card">
    <h2>Timeline</h2>
    <table>
      <thead><tr><th>Time</th><th>Event</th><th>Agent</th><th>Detail</th></tr></thead>
      <tbody>
          {timeline_html}
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Side Effects</h2>
    <div class="grid">
      <div class="stat"><div class="value">{se_files}</div><div class="label">Files Written</div></div>
      <div class="stat"><div class="value">{se_tools}</div><div class="label">Tool Calls</div></div>
    </div>
  </div>

  <div class="card">
    <h2>Verification</h2>
    <p><span class="badge badge-pass">Merkle Root</span> <span class="mono">{merkle_root}</span></p>
    <p style="margin-top: 0.5rem; font-size: 0.8rem; color: #888;">
      {leaf_count} leaves &middot; {proof_count} inclusion proofs
    </p>
  </div>

  <div class="footer">
    Generated by Treeship Session Receipt v1 &middot; <a href="https://treeship.dev" style="color:#60a5fa;">treeship.dev</a>
  </div>
</body>
</html>"#,
        session_id = session.id,
        name = session.name.as_deref().unwrap_or(&session.id),
        status = session.status,
        total_agents = p.total_agents,
        spawned = p.spawned_subagents,
        handoffs = p.handoffs,
        max_depth = p.max_depth,
        hosts = p.hosts,
        duration = duration,
        agents_html = agents_html,
        timeline_html = timeline_html,
        se_files = se_files,
        se_tools = se_tools,
        merkle_root = merkle_root,
        leaf_count = receipt.merkle.leaf_count,
        proof_count = receipt.merkle.inclusion_proofs.len(),
    )
}

fn format_duration(ms: u64) -> String {
    let secs = ms / 1000;
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        format!("{h}h {m}m")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::event::*;
    use crate::session::manifest::SessionManifest;
    use crate::session::receipt::{ArtifactEntry, ReceiptComposer};

    fn make_receipt() -> SessionReceipt {
        let manifest = SessionManifest::new(
            "ssn_pkg_test".into(),
            "agent://test".into(),
            "2026-04-05T08:00:00Z".into(),
            1743843600000,
        );

        let mk = |seq: u64, inst: &str, et: EventType| -> SessionEvent {
            SessionEvent {
                session_id: "ssn_pkg_test".into(),
                event_id: format!("evt_{:016x}", seq),
                timestamp: format!("2026-04-05T08:{:02}:00Z", seq),
                sequence_no: seq,
                trace_id: "trace_1".into(),
                span_id: format!("span_{seq}"),
                parent_span_id: None,
                agent_id: format!("agent://{inst}"),
                agent_instance_id: inst.into(),
                agent_name: inst.into(),
                agent_role: None,
                host_id: "host_1".into(),
                tool_runtime_id: None,
                event_type: et,
                artifact_ref: None,
                meta: None,
            }
        };

        let events = vec![
            mk(0, "root", EventType::SessionStarted),
            mk(1, "root", EventType::AgentStarted { parent_agent_instance_id: None }),
            mk(2, "root", EventType::AgentCalledTool {
                tool_name: "read_file".into(),
                tool_input_digest: None,
                tool_output_digest: None,
                duration_ms: Some(10),
            }),
            mk(3, "root", EventType::AgentCompleted { termination_reason: None }),
            mk(4, "root", EventType::SessionClosed { summary: Some("Done".into()), duration_ms: Some(60000) }),
        ];

        let artifacts = vec![
            ArtifactEntry { artifact_id: "art_001".into(), payload_type: "action".into(), digest: None, signed_at: None },
        ];

        ReceiptComposer::compose(&manifest, &events, artifacts)
    }

    #[test]
    fn build_and_read_package() {
        let receipt = make_receipt();
        let tmp = std::env::temp_dir().join(format!("treeship-pkg-test-{}", rand::random::<u32>()));

        let output = build_package(&receipt, &tmp).unwrap();
        assert!(output.path.exists());
        assert!(output.path.join("receipt.json").exists());
        assert!(output.path.join("merkle.json").exists());
        assert!(output.path.join("render.json").exists());
        assert!(output.path.join("preview.html").exists());
        assert!(output.receipt_digest.starts_with("sha256:"));
        assert!(output.file_count >= 4);

        // Read back
        let read_back = read_package(&output.path).unwrap();
        assert_eq!(read_back.session.id, "ssn_pkg_test");
        assert_eq!(read_back.type_, RECEIPT_TYPE);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn verify_valid_package() {
        let receipt = make_receipt();
        let tmp = std::env::temp_dir().join(format!("treeship-pkg-verify-{}", rand::random::<u32>()));

        let output = build_package(&receipt, &tmp).unwrap();
        let checks = verify_package(&output.path).unwrap();

        let fails: Vec<_> = checks.iter().filter(|c| c.status == VerifyStatus::Fail).collect();
        assert!(fails.is_empty(), "unexpected failures: {fails:?}");

        let passes: Vec<_> = checks.iter().filter(|c| c.status == VerifyStatus::Pass).collect();
        assert!(passes.len() >= 5, "expected at least 5 pass checks, got {}", passes.len());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn verify_detects_missing_receipt() {
        let tmp = std::env::temp_dir().join(format!("treeship-pkg-empty-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmp).unwrap();

        let err = read_package(&tmp);
        assert!(err.is_err());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn preview_html_contains_session_info() {
        let receipt = make_receipt();
        let html = generate_preview_html(&receipt);
        assert!(html.contains("ssn_pkg_test"));
        assert!(html.contains("treeship.dev"));
        assert!(html.contains("Timeline"));
    }
}
