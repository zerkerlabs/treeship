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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::receipt::{SessionReceipt, RECEIPT_TYPE};
use crate::statements::{
    ApprovalRevocation, ApprovalUse, JournalCheckpoint,
    ReplayCheck, ReplayCheckLevel,
    approval_revocation_record_digest, approval_use_record_digest,
    journal_checkpoint_record_digest,
};

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

// Approval Authority package layout (v0.9.9 PR 4).
// approvals/index.json -- top-level index of every approval evidence
//                          file in this package
// approvals/grants/<grant_id>.json    -- copy of the signed
//                          ApprovalStatement envelope (already in
//                          artifacts/ via the chain; mirrored here for
//                          single-directory access during verify)
// approvals/uses/<use_id>.json        -- ApprovalUse record from the
//                          local journal at session-close time
// approvals/checkpoints/<id>.json     -- JournalCheckpoint records that
//                          cover the included uses (PR 6 Hub
//                          checkpoint signing extends this)
const APPROVALS_DIR:        &str = "approvals";
const APPROVALS_GRANTS:     &str = "approvals/grants";
const APPROVALS_USES:       &str = "approvals/uses";
const APPROVALS_CHECKPOINTS:&str = "approvals/checkpoints";
const APPROVALS_INDEX_FILE: &str = "approvals/index.json";

/// Optional approval evidence to embed in the package alongside the
/// receipt + artifacts. None means "no approvals consumed during this
/// session, or none worth exporting." Empty vectors mean "we looked and
/// found nothing"; the resulting package omits the `approvals/` dir
/// entirely so absence is unambiguous.
///
/// Ownership of the evidence stays with the caller: `session::close`
/// gathers the grant envelopes from the chain, the uses from the local
/// journal, and any covering checkpoints, then hands them off here.
#[derive(Debug, Clone, Default)]
pub struct ApprovalsBundle {
    /// Bytes of the signed ApprovalStatement envelopes that authorized
    /// any consumed uses. Each entry is `(grant_id, raw_envelope_json)`.
    /// Stored verbatim so the package's verifier can re-check the
    /// signature without re-serializing.
    pub grants:      Vec<(String, Vec<u8>)>,
    /// ApprovalUse records pulled from the local journal at close time.
    /// `action_artifact_id` should be backfilled before passing to
    /// build_package (see `commands/session.rs`).
    pub uses:        Vec<ApprovalUse>,
    /// JournalCheckpoints that cover the included uses. Optional; may
    /// be empty even when uses are present (PR 6 fills these in).
    pub checkpoints: Vec<JournalCheckpoint>,
    /// Explicit revocations we wanted to surface (e.g. a use whose
    /// grant was revoked after consumption -- the package should still
    /// show the consumed evidence and the revocation alongside).
    /// Empty in PR 4; reserved.
    pub revocations: Vec<ApprovalRevocation>,

    /// Bytes of each action artifact's signed envelope that consumed an
    /// approval. Each entry is `(action_artifact_id, raw_envelope_json)`.
    /// v0.9.10 PR A: shipped to close the action↔use binding gap. The
    /// verifier extracts `meta.approval_use_id` from each envelope and
    /// cross-checks it against the package's use records. Empty in
    /// pre-v0.9.10 packages; readers must treat absence as "binding
    /// not asserted by package" rather than "binding present and OK."
    pub action_envelopes: Vec<(String, Vec<u8>)>,
}

/// `approvals/index.json` -- top-level inventory of evidence in the
/// package. Lets a consumer pre-flight what's there before opening
/// every file; doubles as a stable shape for downstream tooling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalsIndex {
    /// Stable schema marker so future versions can fan out cleanly.
    #[serde(rename = "type")]
    pub type_: String,
    pub schema_version: u32,
    /// Stable kebab-case ids of grants present. Order matches
    /// `grants/` filename order.
    pub grants:      Vec<String>,
    /// Use ids present.
    pub uses:        Vec<String>,
    pub checkpoints: Vec<String>,
    pub revocations: Vec<String>,
}

impl ApprovalsIndex {
    pub fn type_string() -> &'static str { "treeship/approvals-index/v1" }
}

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
///
/// Backwards-compatible wrapper: callers that don't have approval
/// evidence to export pass through here unchanged. Callers that do
/// (`session::close` with consumed approvals) call
/// `build_package_with_approvals` directly.
pub fn build_package(
    receipt: &SessionReceipt,
    output_dir: &Path,
) -> Result<PackageOutput, PackageError> {
    build_package_with_approvals(receipt, output_dir, None)
}

/// Like `build_package` but also embeds approval evidence (PR 4 of v0.9.9).
/// `bundle = None` is identical to `build_package`; the `approvals/`
/// directory is omitted entirely so absence stays unambiguous.
pub fn build_package_with_approvals(
    receipt: &SessionReceipt,
    output_dir: &Path,
    bundle: Option<&ApprovalsBundle>,
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

    // 6. Approval evidence (v0.9.9 PR 4). Only writes when the caller
    // supplied a bundle AND that bundle has at least one entry; an empty
    // bundle behaves the same as None so a session with no consumed
    // approvals doesn't leave behind an empty `approvals/` directory.
    if let Some(b) = bundle {
        if !b.grants.is_empty() || !b.uses.is_empty() || !b.checkpoints.is_empty() || !b.revocations.is_empty() || !b.action_envelopes.is_empty() {
            std::fs::create_dir_all(pkg_dir.join(APPROVALS_GRANTS))?;
            std::fs::create_dir_all(pkg_dir.join(APPROVALS_USES))?;
            std::fs::create_dir_all(pkg_dir.join(APPROVALS_CHECKPOINTS))?;
            // v0.9.10 PR A: write action envelopes that consumed an
            // approval. The artifacts/ directory was created earlier
            // for the package layout but never populated; closing the
            // action↔use binding gap requires the verifier to be able
            // to read each consuming action's `meta.approval_use_id`.
            std::fs::create_dir_all(pkg_dir.join(ARTIFACTS_DIR))?;
            for (artifact_id, envelope_bytes) in &b.action_envelopes {
                let safe = sanitize_filename(artifact_id);
                std::fs::write(
                    pkg_dir.join(ARTIFACTS_DIR).join(format!("{safe}.json")),
                    envelope_bytes,
                )?;
                file_count += 1;
            }

            let mut grant_ids = Vec::with_capacity(b.grants.len());
            for (grant_id, envelope_bytes) in &b.grants {
                let safe = sanitize_filename(grant_id);
                std::fs::write(
                    pkg_dir.join(APPROVALS_GRANTS).join(format!("{safe}.json")),
                    envelope_bytes,
                )?;
                grant_ids.push(grant_id.clone());
                file_count += 1;
            }

            let mut use_ids = Vec::with_capacity(b.uses.len());
            for u in &b.uses {
                let safe = sanitize_filename(&u.use_id);
                let bytes = serde_json::to_vec_pretty(u)?;
                std::fs::write(
                    pkg_dir.join(APPROVALS_USES).join(format!("{safe}.json")),
                    &bytes,
                )?;
                use_ids.push(u.use_id.clone());
                file_count += 1;
            }

            let mut checkpoint_ids = Vec::with_capacity(b.checkpoints.len());
            for cp in &b.checkpoints {
                let safe = sanitize_filename(&cp.checkpoint_id);
                let bytes = serde_json::to_vec_pretty(cp)?;
                std::fs::write(
                    pkg_dir.join(APPROVALS_CHECKPOINTS).join(format!("{safe}.json")),
                    &bytes,
                )?;
                checkpoint_ids.push(cp.checkpoint_id.clone());
                file_count += 1;
            }

            let mut revocation_ids = Vec::with_capacity(b.revocations.len());
            for rev in &b.revocations {
                let safe = sanitize_filename(&rev.revocation_id);
                let bytes = serde_json::to_vec_pretty(rev)?;
                std::fs::write(
                    pkg_dir.join(APPROVALS_DIR).join(format!("revocations-{safe}.json")),
                    &bytes,
                )?;
                revocation_ids.push(rev.revocation_id.clone());
                file_count += 1;
            }

            let index = ApprovalsIndex {
                type_:          ApprovalsIndex::type_string().into(),
                schema_version: 1,
                grants:         grant_ids,
                uses:           use_ids,
                checkpoints:    checkpoint_ids,
                revocations:    revocation_ids,
            };
            let index_bytes = serde_json::to_vec_pretty(&index)?;
            std::fs::write(pkg_dir.join(APPROVALS_INDEX_FILE), &index_bytes)?;
            file_count += 1;
        }
    }

    Ok(PackageOutput {
        path: pkg_dir,
        receipt_digest,
        merkle_root: receipt.merkle.root.clone(),
        file_count,
    })
}

/// Sanitize an id (artifact_id, use_id, checkpoint_id) into a filesystem-safe
/// filename. Underscores everything that isn't alphanumeric, dash, or dot.
/// Not a security boundary; the digest chain is the integrity check.
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' { c } else { '_' })
        .collect()
}

/// Read approval evidence embedded in a package, if any. Returns
/// `Ok(ApprovalsBundle::default())` when the package has no `approvals/`
/// directory (the typical case for sessions that didn't consume any
/// scoped approvals). Errors only on malformed JSON inside files that
/// the index claims exist.
///
/// Quiet on missing-directory by design: PR 4 packages and pre-PR-4
/// packages should both round-trip through verify without spurious
/// failures.
pub fn read_approvals_bundle(pkg_dir: &Path) -> Result<ApprovalsBundle, PackageError> {
    let approvals_dir = pkg_dir.join(APPROVALS_DIR);
    if !approvals_dir.is_dir() {
        return Ok(ApprovalsBundle::default());
    }

    let mut bundle = ApprovalsBundle::default();

    // Grants are raw envelopes by file; we don't parse here, the
    // verify layer can re-check the signature.
    let grants_dir = pkg_dir.join(APPROVALS_GRANTS);
    if grants_dir.is_dir() {
        for entry in std::fs::read_dir(&grants_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") { continue; }
            let id = path.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
            let bytes = std::fs::read(&path)?;
            bundle.grants.push((id, bytes));
        }
    }

    let uses_dir = pkg_dir.join(APPROVALS_USES);
    if uses_dir.is_dir() {
        for entry in std::fs::read_dir(&uses_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") { continue; }
            let bytes = std::fs::read(&path)?;
            let u: ApprovalUse = serde_json::from_slice(&bytes)?;
            bundle.uses.push(u);
        }
    }

    let cps_dir = pkg_dir.join(APPROVALS_CHECKPOINTS);
    if cps_dir.is_dir() {
        for entry in std::fs::read_dir(&cps_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") { continue; }
            let bytes = std::fs::read(&path)?;
            let cp: JournalCheckpoint = serde_json::from_slice(&bytes)?;
            bundle.checkpoints.push(cp);
        }
    }

    // v0.9.10 PR A: read action envelopes shipped to support the
    // action↔use binding check. Pre-v0.9.10 packages have an empty
    // artifacts/ dir (the dir was created but never populated); the
    // bundle's `action_envelopes` stays empty in that case, and the
    // verifier reports the binding row honestly as "not asserted by
    // package" rather than silently passing.
    let arts_dir = pkg_dir.join(ARTIFACTS_DIR);
    if arts_dir.is_dir() {
        for entry in std::fs::read_dir(&arts_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") { continue; }
            let id = path.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
            let bytes = std::fs::read(&path)?;
            bundle.action_envelopes.push((id, bytes));
        }
    }

    Ok(bundle)
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

    // event_log completeness: when session::close skipped malformed
    // event log lines, the count is recorded on receipt.proofs.event_log_skipped.
    // Surface as WARN (not FAIL) because the receipt is still
    // cryptographically valid -- we just want a downstream verifier to
    // know that some evidence was dropped before the receipt was sealed.
    // A future --strict flag can promote this to FAIL.
    // Codex adversarial review finding #8.
    if receipt.proofs.event_log_skipped > 0 {
        checks.push(VerifyCheck::warn(
            "event_log_completeness",
            &format!(
                "{} event(s) skipped during close (malformed lines in events.jsonl). \
                 Receipt is cryptographically valid but does not represent the full event stream. \
                 Inspect close-time stderr or the events.jsonl directly to investigate.",
                receipt.proofs.event_log_skipped,
            ),
        ));
    }

    // 8. Approval evidence -- v0.9.9 PR 4. Three independent replay
    // checks, each emitted as its own VerifyCheck row so the printer
    // (and downstream tooling) can render them separately.
    //
    //   replay-package-local      duplicate uses INSIDE this package
    //   replay-included-checkpoint  embedded JournalCheckpoints verify standalone
    //
    // The local-journal level requires access to the workspace journal,
    // which the package alone doesn't carry; that check runs in the CLI
    // verify_package wrapper that has Ctx access. The hub-org level is
    // reserved for PR 6 -- not claimed without a real Hub checkpoint.
    let bundle = read_approvals_bundle(pkg_dir).unwrap_or_default();
    add_approval_evidence_checks(&mut checks, &bundle);

    Ok(checks)
}

/// Emit the package-local + included-checkpoint replay checks. Both are
/// fully offline: package-local scans the embedded uses for duplicates;
/// included-checkpoint walks the embedded checkpoint records and
/// re-derives each `record_digest` against its stored value.
///
/// The local-journal check is NOT here -- it requires workspace access
/// and is added by the CLI wrapper in `commands/package.rs` that has the
/// resolved config_path. Keeping these two pure means an offline tool
/// (Hub-side validator, third-party verifier) can run the same checks
/// without needing a Treeship workspace.
pub(crate) fn add_approval_evidence_checks(
    checks: &mut Vec<VerifyCheck>,
    bundle: &ApprovalsBundle,
) {
    if bundle.uses.is_empty() && bundle.checkpoints.is_empty() {
        // Nothing to assert. Stay quiet rather than emit a "skipped"
        // row -- session packages without approvals shouldn't drag in
        // approval rows by accident.
        return;
    }

    // -- replay-package-local --
    // Two distinct violation cases inside the package:
    //   (a) uses sharing (grant_id, nonce_digest) EXCEED max_uses on
    //       that grant. Two uses of a max_uses=2 grant is fine; three
    //       is the violation. max_uses is read from the use record's
    //       own `max_uses` field (a snapshot from consume time).
    //   (b) two ApprovalUse records with the same use_id -- a copy
    //       artifact from a corrupt build, never legitimate.
    use std::collections::HashMap;
    let mut by_nonce: HashMap<(String, String), Vec<&ApprovalUse>> = HashMap::new();
    let mut by_use_id: HashMap<&str, Vec<&ApprovalUse>> = HashMap::new();
    for u in &bundle.uses {
        by_nonce
            .entry((u.grant_id.clone(), u.nonce_digest.clone()))
            .or_default()
            .push(u);
        by_use_id.entry(&u.use_id).or_default().push(u);
    }
    let over_max: Vec<((String, String), Vec<&ApprovalUse>, u32)> = by_nonce
        .iter()
        .filter_map(|(key, uses)| {
            let max = uses.iter().filter_map(|u| u.max_uses).next()?;
            if (uses.len() as u32) > max {
                Some((key.clone(), uses.iter().map(|u| *u).collect(), max))
            } else {
                None
            }
        })
        .collect();
    let dup_use_ids: Vec<(&&str, &Vec<&ApprovalUse>)> =
        by_use_id.iter().filter(|(_, v)| v.len() > 1).collect();

    if over_max.is_empty() && dup_use_ids.is_empty() {
        checks.push(VerifyCheck::pass(
            "replay-package-local",
            &format!("no duplicate approval use inside package ({} uses scanned)", bundle.uses.len()),
        ));
    } else {
        let mut detail = String::from("package-local replay violation:");
        for ((grant_id, _nd), uses, max) in &over_max {
            detail.push_str(&format!(
                " grant {grant_id} consumed {} times in this package (max_uses={max});",
                uses.len(),
            ));
        }
        for (uid, uses) in &dup_use_ids {
            detail.push_str(&format!(" use_id {uid} appears {} times;", uses.len()));
        }
        checks.push(VerifyCheck::fail("replay-package-local", &detail));
    }

    // -- replay-included-checkpoint --
    // For each checkpoint, recompute its record_digest from canonical
    // form. If the stored digest doesn't match, the checkpoint was
    // tampered after sealing.
    if !bundle.checkpoints.is_empty() {
        let mut tampered = Vec::new();
        for cp in &bundle.checkpoints {
            let recomputed = journal_checkpoint_record_digest(cp);
            if recomputed != cp.record_digest {
                tampered.push((cp.checkpoint_id.clone(), cp.record_digest.clone(), recomputed));
            }
        }
        if tampered.is_empty() {
            checks.push(VerifyCheck::pass(
                "replay-included-checkpoint",
                &format!("{} included journal checkpoint(s) verify offline", bundle.checkpoints.len()),
            ));
        } else {
            let detail = tampered.iter()
                .map(|(id, expected, actual)| {
                    format!("checkpoint {id} tampered (stored {expected}, recomputed {actual})")
                })
                .collect::<Vec<_>>()
                .join("; ");
            checks.push(VerifyCheck::fail("replay-included-checkpoint", &detail));
        }
    }

    // -- approval-use-record-digest --
    // Each ApprovalUse carries its own record_digest computed over the
    // canonical form of the record (minus the digest itself). Tampering
    // any field changes the digest. v0.9.10 PR A renames this from the
    // older `approval-use-integrity` because the prior label suggested
    // it covered nonce/action binding -- it didn't, and Codex's v0.9.9
    // adversarial review flagged the over-claim. The honest scope of
    // this row is "each use's stored digest matches its canonical
    // recompute"; the binding checks are now separate rows below.
    let mut tampered_uses = Vec::new();
    for u in &bundle.uses {
        let recomputed = approval_use_record_digest(u);
        if recomputed != u.record_digest {
            tampered_uses.push((u.use_id.clone(), u.record_digest.clone(), recomputed));
        }
    }
    if !bundle.uses.is_empty() {
        if tampered_uses.is_empty() {
            checks.push(VerifyCheck::pass(
                "approval-use-record-digest",
                &format!("{} use record(s) recompute identically", bundle.uses.len()),
            ));
        } else {
            let detail = tampered_uses.iter()
                .map(|(id, expected, actual)| {
                    format!("use {id} tampered (stored {expected}, recomputed {actual})")
                })
                .collect::<Vec<_>>()
                .join("; ");
            checks.push(VerifyCheck::fail("approval-use-record-digest", &detail));
        }
    }

    // -- approval-use-nonce-binding --
    // Cross-check each use's `nonce_digest` against the corresponding
    // grant's *signed* nonce. v0.9.9 trusted the use's nonce_digest
    // verbatim, which let an attacker who controls the package mutate
    // it (and recompute record_digest) to claim consumption of a grant
    // whose nonce was never actually used. This row closes that gap.
    //
    // Discipline: the grant envelope is the source of truth. We pull
    // the raw `nonce` from the grant's payload, hash it via the same
    // `nonce_digest` helper that attest used, and compare to each
    // use's stored `nonce_digest`. Mismatch -> fail.
    if !bundle.uses.is_empty() {
        use crate::attestation::envelope::Envelope;
        use crate::statements::{nonce_digest, ApprovalStatement};
        // Build a grant_id -> expected_nonce_digest map from the bundle's
        // grant envelopes. Skip grants we can't parse (the receipt's
        // signature checks would catch those upstream; here we just
        // can't speak to their binding).
        let mut grant_nonce_digest: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for (grant_id, env_bytes) in &bundle.grants {
            let env = match Envelope::from_json(env_bytes) {
                Ok(e)  => e,
                Err(_) => continue,
            };
            let approval: ApprovalStatement = match env.unmarshal_statement() {
                Ok(a)  => a,
                Err(_) => continue,
            };
            grant_nonce_digest.insert(grant_id.clone(), nonce_digest(&approval.nonce));
        }
        let mut mismatches: Vec<String> = Vec::new();
        let mut missing_grants: Vec<String> = Vec::new();
        for u in &bundle.uses {
            match grant_nonce_digest.get(&u.grant_id) {
                Some(expected) => {
                    if expected != &u.nonce_digest {
                        mismatches.push(format!(
                            "use {} claims nonce_digest {} but grant {} signed nonce hashes to {}",
                            u.use_id, u.nonce_digest, u.grant_id, expected,
                        ));
                    }
                }
                None => {
                    missing_grants.push(format!(
                        "use {} references grant {} but the grant envelope is not in the package",
                        u.use_id, u.grant_id,
                    ));
                }
            }
        }
        if mismatches.is_empty() && missing_grants.is_empty() {
            checks.push(VerifyCheck::pass(
                "approval-use-nonce-binding",
                &format!("{} use record(s) bind to grant signed nonces", bundle.uses.len()),
            ));
        } else {
            let mut detail = String::new();
            if !mismatches.is_empty()    { detail.push_str(&mismatches.join("; ")); }
            if !missing_grants.is_empty() {
                if !detail.is_empty() { detail.push_str("; "); }
                detail.push_str(&missing_grants.join("; "));
            }
            checks.push(VerifyCheck::fail("approval-use-nonce-binding", &detail));
        }
    }

    // -- approval-use-action-binding --
    // Cross-check each consuming action's `meta.approval_use_id`
    // against the package's use records. v0.9.9 ignored this pointer
    // entirely; the package didn't even ship action envelopes, so the
    // verifier could not see the field. v0.9.10 PR A: action envelopes
    // ride along in `artifacts/`, and this row pins that every action
    // declaring it consumed an approval has a use record for that
    // exact use_id, with matching grant_id and matching
    // `nonce_digest(approval_nonce)`.
    //
    // Honesty rule: when bundle.action_envelopes is empty (pre-v0.9.10
    // packages, or a v0.9.10 package with no consuming actions
    // recorded), this row reports `not asserted by package` rather
    // than silent PASS.
    if !bundle.uses.is_empty() {
        use crate::attestation::envelope::Envelope;
        use crate::statements::{nonce_digest, ActionStatement};
        if bundle.action_envelopes.is_empty() {
            checks.push(VerifyCheck::warn(
                "approval-use-action-binding",
                "no action envelopes embedded -- action↔use binding not asserted by package (pre-v0.9.10)",
            ));
        } else {
            let use_ids: std::collections::HashSet<&str> = bundle.uses.iter().map(|u| u.use_id.as_str()).collect();
            let mut violations: Vec<String> = Vec::new();
            let mut bound_count = 0usize;
            for (artifact_id, env_bytes) in &bundle.action_envelopes {
                let env = match Envelope::from_json(env_bytes) {
                    Ok(e)  => e,
                    Err(_) => {
                        violations.push(format!("action {artifact_id} envelope unparseable"));
                        continue;
                    }
                };
                let action: ActionStatement = match env.unmarshal_statement() {
                    Ok(a)  => a,
                    Err(_) => {
                        violations.push(format!("action {artifact_id} not an ActionStatement"));
                        continue;
                    }
                };
                // Action envelopes shipped only when they consumed an
                // approval, but be defensive: if there's no
                // approval_nonce, skip silently.
                let raw_nonce = match action.approval_nonce.as_deref() {
                    Some(n) => n,
                    None    => continue,
                };
                let claimed_use_id = action
                    .meta
                    .as_ref()
                    .and_then(|m| m.get("approval_use_id"))
                    .and_then(|v| v.as_str());
                let Some(claimed_use_id) = claimed_use_id else {
                    violations.push(format!(
                        "action {artifact_id} consumed an approval but its meta has no approval_use_id"
                    ));
                    continue;
                };
                if !use_ids.contains(claimed_use_id) {
                    violations.push(format!(
                        "action {artifact_id} claims approval_use_id={} but no such use is embedded",
                        claimed_use_id,
                    ));
                    continue;
                }
                // The use exists; cross-check that its nonce_digest
                // matches the action's approval_nonce hash.
                let expected = nonce_digest(raw_nonce);
                let matched_use = bundle.uses.iter().find(|u| u.use_id == claimed_use_id);
                if let Some(u) = matched_use {
                    if u.nonce_digest != expected {
                        violations.push(format!(
                            "action {artifact_id} approval_nonce hashes to {} but use {} stores nonce_digest {}",
                            expected, claimed_use_id, u.nonce_digest,
                        ));
                        continue;
                    }
                }
                bound_count += 1;
            }
            if violations.is_empty() {
                checks.push(VerifyCheck::pass(
                    "approval-use-action-binding",
                    &format!("{bound_count} consuming action(s) bind cleanly to embedded use records"),
                ));
            } else {
                checks.push(VerifyCheck::fail(
                    "approval-use-action-binding",
                    &violations.join("; "),
                ));
            }
        }
    }

    // -- approval-use-chain-continuity --
    // v0.9.9 verified each use's individual record_digest but never
    // walked the `previous_record_digest` chain across the embedded
    // records. An attacker could rewrite an entire chain consistently
    // (recomputing each digest along the way) and the per-record
    // checks all passed.
    //
    // We can only do a *partial* chain walk in offline package replay:
    // the package ships only records the session touched, not the
    // workspace journal's full history, so the chain we see may have
    // gaps. What we CAN check: every embedded record's
    // previous_record_digest must point at SOME record_digest that
    // either (a) belongs to another embedded record, or (b) is
    // explicitly the empty string (genesis). A dangling
    // previous_record_digest pointing at nothing is a bypass attempt.
    //
    // Anchoring against a Hub-signed checkpoint is handled separately
    // by replay-hub-org (the signature covers previous_record_digest);
    // here we report internal consistency only.
    if !bundle.uses.is_empty() || !bundle.checkpoints.is_empty() {
        // Collect every digest the package "owns" as a chain link.
        let mut owned: std::collections::HashSet<String> = std::collections::HashSet::new();
        owned.insert(String::new()); // genesis is a valid prev pointer
        for u in &bundle.uses          { owned.insert(u.record_digest.clone()); }
        for cp in &bundle.checkpoints  { owned.insert(cp.record_digest.clone()); }
        let mut dangling: Vec<String> = Vec::new();
        for u in &bundle.uses {
            if !owned.contains(&u.previous_record_digest) {
                dangling.push(format!(
                    "use {} previous_record_digest {} not anchored in package",
                    u.use_id, u.previous_record_digest,
                ));
            }
        }
        for cp in &bundle.checkpoints {
            if !owned.contains(&cp.previous_record_digest) {
                dangling.push(format!(
                    "checkpoint {} previous_record_digest {} not anchored in package",
                    cp.checkpoint_id, cp.previous_record_digest,
                ));
            }
        }
        if dangling.is_empty() {
            checks.push(VerifyCheck::pass(
                "approval-use-chain-continuity",
                &format!(
                    "{} record(s) form a self-consistent chain (every previous_record_digest anchors in-package or genesis)",
                    bundle.uses.len() + bundle.checkpoints.len(),
                ),
            ));
        } else {
            checks.push(VerifyCheck::fail(
                "approval-use-chain-continuity",
                &dangling.join("; "),
            ));
        }
    }

    // -- replay-hub-org -- v0.9.9 PR 6.
    // The strongest level Treeship can speak to today. The release
    // rule is non-negotiable: PASS only when (1) at least one embedded
    // checkpoint declares kind=HubOrg, (2) every required Hub field is
    // populated, (3) the signature verifies against the embedded
    // public key, AND (4) the checkpoint covers every embedded
    // ApprovalUse via covered_use_ids. Anything short of that means
    // "no row" or "fail" -- never silent pass.
    //
    // No row at all when the package has no Hub-kind checkpoint:
    // matches the v0.9.9 PR 4-5 behavior where the panel renders
    // "- hub-org   not checked (no Hub checkpoint in package)" so a
    // reader doesn't misread an absent row as a failure.
    let hub_checkpoints: Vec<&JournalCheckpoint> = bundle
        .checkpoints
        .iter()
        .filter(|cp| cp.checkpoint_kind == crate::statements::CheckpointKind::HubOrg)
        .collect();
    if !hub_checkpoints.is_empty() {
        let mut all_ok = true;
        let mut details: Vec<String> = Vec::new();
        let mut have_valid_signature = false;

        for cp in &hub_checkpoints {
            match crate::statements::verify_hub_checkpoint_signature(cp) {
                crate::statements::HubCheckpointVerification::Valid => {
                    have_valid_signature = true;
                    // Coverage: every embedded use_id MUST appear in
                    // this checkpoint's covered_use_ids. A checkpoint
                    // that doesn't cover the package's uses cannot
                    // promote replay-hub-org for those uses.
                    let covered: std::collections::HashSet<&String> =
                        cp.covered_use_ids.iter().collect();
                    let missing: Vec<String> = bundle
                        .uses
                        .iter()
                        .filter(|u| !covered.contains(&u.use_id))
                        .map(|u| u.use_id.clone())
                        .collect();
                    if missing.is_empty() {
                        details.push(format!(
                            "{} signed by {} verifies; covers {} use(s)",
                            cp.checkpoint_id,
                            cp.hub_id,
                            cp.covered_use_ids.len(),
                        ));
                    } else {
                        all_ok = false;
                        details.push(format!(
                            "{} verifies but does not cover {} use(s): {}",
                            cp.checkpoint_id,
                            missing.len(),
                            missing.join(", "),
                        ));
                    }
                }
                crate::statements::HubCheckpointVerification::MissingFields(field) => {
                    all_ok = false;
                    details.push(format!(
                        "{} declares kind=hub-org but field `{}` is missing",
                        cp.checkpoint_id, field,
                    ));
                }
                crate::statements::HubCheckpointVerification::Tampered => {
                    all_ok = false;
                    details.push(format!(
                        "{} hub signature failed verification (tampered or wrong key)",
                        cp.checkpoint_id,
                    ));
                }
                crate::statements::HubCheckpointVerification::NotHubKind => {
                    // Filter ensures this is unreachable; keep the
                    // arm so a future filter relaxation doesn't go
                    // silent.
                    all_ok = false;
                    details.push(format!(
                        "{} kind toggled out of hub-org during verify",
                        cp.checkpoint_id,
                    ));
                }
            }
        }
        if all_ok && have_valid_signature {
            checks.push(VerifyCheck::pass(
                "replay-hub-org",
                &details.join("; "),
            ));
        } else {
            // Hub checkpoint is present but does not satisfy every
            // gate. Default mode warns; the CLI verify wrapper's
            // --strict promotes to fail.
            checks.push(VerifyCheck::warn(
                "replay-hub-org",
                &details.join("; "),
            ));
        }
    }
    // No hub-org checkpoints embedded -> no row. The Approval
    // Authority panel still renders "- hub-org   not checked".

    let _ = ReplayCheckLevel::HubOrg;
    let _ = approval_revocation_record_digest as fn(&ApprovalRevocation) -> String;
    let _ = ReplayCheck::not_performed;
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
    pub fn pass(name: &str, detail: &str) -> Self {
        Self { name: name.into(), status: VerifyStatus::Pass, detail: detail.into() }
    }
    pub fn fail(name: &str, detail: &str) -> Self {
        Self { name: name.into(), status: VerifyStatus::Fail, detail: detail.into() }
    }
    pub fn warn(name: &str, detail: &str) -> Self {
        Self { name: name.into(), status: VerifyStatus::Warn, detail: detail.into() }
    }
}

impl VerifyCheck {
    pub fn passed(&self) -> bool {
        self.status == VerifyStatus::Pass
    }
}

/// HTML template for the self-contained verifier preview.
/// Loaded at compile time so the binary carries no runtime file dependencies.
const PREVIEW_TEMPLATE: &str = include_str!("preview_template.html");

/// Generate a self-contained preview.html that embeds the receipt JSON
/// and runs Merkle verification client-side using Web Crypto API.
///
/// The HTML works fully air-gapped: no network calls, no CDN, no server.
/// Open it in any modern browser and it automatically verifies the receipt
/// and shows pass/fail for each check.
fn generate_preview_html(receipt: &SessionReceipt) -> String {
    let receipt_json = serde_json::to_string_pretty(receipt)
        .unwrap_or_else(|_| "{}".to_string());
    // Defense-in-depth: escape </script sequences so a malicious receipt
    // field cannot break out of the JSON data block. The primary defense
    // is type="application/json" which the HTML parser does not execute,
    // but this escaping adds a second layer.
    // Escape ALL '<' as '\u003c' in the JSON string to prevent any
    // case-variant of </script> from breaking out of the data block.
    // This is bulletproof: no HTML parser can see a tag open inside the JSON.
    let safe_json = receipt_json.replace('<', r"\u003c");

    // Only one placeholder: __RECEIPT_JSON__ inside the data block.
    // The page title is set at runtime from the parsed JSON to avoid
    // a second replacement pass that could re-inject content.
    PREVIEW_TEMPLATE
        .replace("__RECEIPT_JSON__", &safe_json)
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
