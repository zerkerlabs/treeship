use std::{
    fs,
    path::PathBuf,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{SigningKey, Signer};
use rand::RngCore;
use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use treeship_core::merkle::{
    ArtifactSummary, Checkpoint, MerkleTree, ProofFile,
};

use crate::{ctx, printer::Printer};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the merkle directory: ~/.treeship/merkle/
fn merkle_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = home::home_dir().ok_or("cannot determine home directory")?;
    let dir = home.join(".treeship").join("merkle");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Returns the checkpoints directory: ~/.treeship/merkle/checkpoints/
fn checkpoints_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = merkle_dir()?.join("checkpoints");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Build a MerkleTree from all artifacts in the store, sorted by signed_at.
pub(crate) fn build_tree(
    ctx: &ctx::Ctx,
) -> Result<(MerkleTree, Vec<String>), Box<dyn std::error::Error>> {
    let mut entries = ctx.storage.list();
    // list() returns most-recent-first; reverse to get chronological order
    entries.reverse();
    // Sort by signed_at for deterministic ordering
    entries.sort_by(|a, b| a.signed_at.cmp(&b.signed_at));

    let mut tree = MerkleTree::new();
    let mut artifact_ids: Vec<String> = Vec::new();
    for entry in &entries {
        tree.append(&entry.id);
        artifact_ids.push(entry.id.clone());
    }
    Ok((tree, artifact_ids))
}

/// Find the next checkpoint index by scanning existing checkpoints.
fn next_checkpoint_index() -> Result<u64, Box<dyn std::error::Error>> {
    let dir = checkpoints_dir()?;
    let mut max_index: u64 = 0;
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == "latest.json" {
                continue;
            }
            if let Some(stem) = name.strip_suffix(".json") {
                if let Ok(idx) = stem.parse::<u64>() {
                    if idx > max_index {
                        max_index = idx;
                    }
                }
            }
        }
    }
    Ok(max_index + 1)
}

/// Load the latest checkpoint from disk.
pub(crate) fn load_latest_checkpoint() -> Result<Option<Checkpoint>, Box<dyn std::error::Error>> {
    let path = checkpoints_dir()?.join("latest.json");
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&path)?;
    let cp: Checkpoint = serde_json::from_slice(&bytes)?;
    Ok(Some(cp))
}

/// Count existing checkpoints.
fn count_checkpoints() -> Result<usize, Box<dyn std::error::Error>> {
    let dir = checkpoints_dir()?;
    let mut count = 0;
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name != "latest.json" && name.ends_with(".json") {
                count += 1;
            }
        }
    }
    Ok(count)
}

/// Shorten a hash for display: first 16 hex chars + "..."
fn short_hash(h: &str) -> String {
    let raw = h.strip_prefix("sha256:").unwrap_or(h);
    if raw.len() > 16 {
        format!("{}...", &raw[..16])
    } else {
        raw.to_string()
    }
}

// ---------------------------------------------------------------------------
// treeship checkpoint
// ---------------------------------------------------------------------------

pub fn checkpoint(
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let (tree, _artifact_ids) = build_tree(&ctx)?;

    if tree.is_empty() {
        return Err("no artifacts to checkpoint -- create some artifacts first".into());
    }

    let index = next_checkpoint_index()?;
    let signer = ctx.keys.default_signer()?;
    let cp = Checkpoint::create(index, &tree, signer.as_ref())
        .map_err(|e| format!("checkpoint creation failed: {}", e))?;

    // Save checkpoint file: NNNN.json
    let cp_dir = checkpoints_dir()?;
    let filename = format!("{:04}.json", index);
    let cp_json = serde_json::to_vec_pretty(&cp)?;
    fs::write(cp_dir.join(&filename), &cp_json)?;

    // Save latest.json (copy, not symlink, for portability)
    fs::write(cp_dir.join("latest.json"), &cp_json)?;

    let root_short = short_hash(&cp.root);

    printer.success("checkpoint sealed", &[
        ("index",     &format!("#{:04}", cp.index)),
        ("root",      &format!("sha256:{}", root_short)),
        ("artifacts", &cp.tree_size.to_string()),
        ("height",    &cp.height.to_string()),
        ("signed",    &format!("{}  (ed25519)", cp.signer)),
        ("time",      &cp.signed_at),
    ]);
    printer.blank();
    printer.hint("treeship merkle proof <artifact_id>");
    printer.hint(&format!("treeship merkle verify sha256:{}... <proof.json>", root_short));

    Ok(())
}

// ---------------------------------------------------------------------------
// treeship merkle proof <artifact_id>
// ---------------------------------------------------------------------------

/// Rebuild the Merkle tree EXACTLY as it was at `checkpoint` — its first
/// `tree_size` leaves — and cross-check the rebuilt root against the
/// checkpoint's own root before returning it. Inclusion proofs must be
/// generated from THIS tree, never the full current one: an authentication
/// path is a function of the total leaf count, so a proof computed over a
/// tree that grew after the checkpoint reconstructs the wrong root and
/// reports a legitimate, in-log artifact as inclusion INVALID. (The same
/// correctness rule publish_consistency and `present` already apply.)
pub(crate) fn checkpoint_tree(
    artifact_ids: &[String],
    checkpoint: &Checkpoint,
) -> Result<MerkleTree, Box<dyn std::error::Error>> {
    if artifact_ids.len() < checkpoint.tree_size {
        return Err(format!(
            "local store has {} artifacts but checkpoint #{} covers {} — the store no longer matches the checkpoint",
            artifact_ids.len(), checkpoint.index, checkpoint.tree_size
        )
        .into());
    }
    let mut tree = MerkleTree::new();
    for id in &artifact_ids[..checkpoint.tree_size] {
        tree.append(id);
    }
    let computed = tree
        .root()
        .map(hex::encode)
        .ok_or("checkpoint-sized tree has no root")?;
    let cp_root = checkpoint
        .root
        .strip_prefix("sha256:")
        .unwrap_or(&checkpoint.root);
    if computed != cp_root {
        return Err(format!(
            "local artifacts no longer reproduce checkpoint #{}'s root (artifacts changed since checkpointing)\n\n  Fix: treeship checkpoint  (then re-run this command)",
            checkpoint.index
        )
        .into());
    }
    Ok(tree)
}

pub fn proof(
    artifact_id: &str,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let (_, artifact_ids) = build_tree(&ctx)?;

    // Load the checkpoint FIRST: a proof is a statement about membership in
    // a signed checkpoint, so both the membership guard and the tree the
    // authentication path is computed from must be the checkpoint's.
    let checkpoint = load_latest_checkpoint()?
        .ok_or("no checkpoints found -- run 'treeship checkpoint' first")?;

    // Find the artifact's leaf index
    let leaf_index = artifact_ids.iter()
        .position(|id| id == artifact_id)
        .ok_or_else(|| format!("artifact {} not found in store", artifact_id))?;

    // Membership guard: an artifact appended after the checkpoint is not in
    // the checkpoint's tree — a "proof" against that checkpoint would be one
    // that verifiably fails.
    if leaf_index >= checkpoint.tree_size {
        return Err(format!(
            "artifact {} is newer than checkpoint #{} (tree_size {})\n\n  Fix: treeship checkpoint  (then re-run this command)",
            artifact_id, checkpoint.index, checkpoint.tree_size
        )
        .into());
    }

    // Generate the inclusion proof from the checkpoint's tree.
    let cp_tree = checkpoint_tree(&artifact_ids, &checkpoint)?;
    let inclusion_proof = cp_tree.inclusion_proof(leaf_index)
        .ok_or("failed to generate inclusion proof")?;

    // Load artifact record for summary
    let record = ctx.storage.read(artifact_id)?;
    let short_type = record.payload_type
        .strip_prefix("application/vnd.treeship.")
        .and_then(|s| s.strip_suffix(".v1+json"))
        .unwrap_or(&record.payload_type);

    let proof_file = ProofFile {
        artifact_id: artifact_id.to_string(),
        artifact_summary: ArtifactSummary {
            actor: short_type.to_string(),
            action: short_type.to_string(),
            timestamp: record.signed_at.clone(),
            key_id: record.key_id.clone(),
        },
        inclusion_proof: inclusion_proof.clone(),
        checkpoint: checkpoint.clone(),
    };

    // Save proof file
    let proof_json = serde_json::to_vec_pretty(&proof_file)?;
    let out_path = format!("{}.proof.json", artifact_id);
    fs::write(&out_path, &proof_json)?;

    let root_short = short_hash(&checkpoint.root);

    printer.success(&format!("inclusion proof  {}", artifact_id), &[
        ("leaf",       &format!("sha256:{}  (position {} of {})",
            short_hash(&inclusion_proof.leaf_hash),
            leaf_index,
            checkpoint.tree_size)),
        ("root",       &format!("sha256:{}", root_short)),
        ("path",       &format!("{} steps", inclusion_proof.path.len())),
    ]);
    printer.blank();

    for (i, step) in inclusion_proof.path.iter().enumerate() {
        let dir_str = match step.direction {
            treeship_core::merkle::Direction::Left => "left ",
            treeship_core::merkle::Direction::Right => "right",
        };
        printer.info(&format!("  Step {}:  {}  sha256:{}",
            i + 1, dir_str, short_hash(&step.hash)));
    }
    printer.blank();

    printer.info(&format!("checkpoint:  #{:04}  .  local  .  {}", checkpoint.index, checkpoint.signed_at));
    printer.info(&format!("exported:    {}", out_path));
    printer.blank();
    printer.hint(&format!("treeship merkle verify sha256:{}... {}", root_short, out_path));

    Ok(())
}

// ---------------------------------------------------------------------------
// treeship merkle verify [root] <proof.json>
// ---------------------------------------------------------------------------

pub fn verify(
    expected_root: Option<&str>,
    proof_path: &str,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = fs::read(proof_path)
        .map_err(|e| format!("cannot read {}: {}", proof_path, e))?;
    let proof_file: ProofFile = serde_json::from_slice(&bytes)
        .map_err(|e| format!("invalid proof JSON: {}", e))?;

    // 1. Verify checkpoint signature against pinned trust roots.
    //    The signature now also binds merkle_version (see
    //    Checkpoint::canonical_for_signing), so any tampered version
    //    on the checkpoint reaches us as an invalid signature.
    //
    //    Missing trust file = empty store, which makes verification
    //    fail closed (audit lane J: a checkpoint signed by an unpinned
    //    issuer is no longer accepted just because the signature math
    //    is internally consistent). Audit lane J fix-up: propagate
    //    Malformed / PermissionsTooOpen instead of silently degrading
    //    to an empty store.
    let trust = treeship_core::trust::TrustRootStore::open_default_or_empty()
        .map_err(|e| -> Box<dyn std::error::Error> {
            printer.failure("trust store unreadable", &[
                ("path",   &treeship_core::trust::TrustRootStore::default_path().display().to_string()),
                ("reason", &e.to_string()),
            ]);
            format!("trust-root: {e}").into()
        })?;
    let sig_valid = proof_file.checkpoint.verify(&trust);

    // 2. Verify inclusion proof. The trusted merkle_version is the one
    // bound into the checkpoint signature, NOT the one in the proof
    // blob. verify_proof additionally rejects on per-proof drift.
    let root_hex = proof_file.checkpoint.root
        .strip_prefix("sha256:")
        .unwrap_or(&proof_file.checkpoint.root);

    let proof_valid = MerkleTree::verify_proof(
        proof_file.checkpoint.merkle_version,
        root_hex,
        &proof_file.artifact_id,
        &proof_file.inclusion_proof,
    );

    // 3. If expected root provided, check it matches
    let root_matches = match expected_root {
        Some(expected) => {
            let expected_hex = expected.strip_prefix("sha256:")
                .unwrap_or(expected);
            expected_hex == root_hex
        }
        None => true,
    };

    let all_valid = sig_valid && proof_valid && root_matches;

    if all_valid {
        let root_short = short_hash(&proof_file.checkpoint.root);
        printer.success("inclusion verified  (offline)", &[
            ("artifact", &proof_file.artifact_id),
            ("position", &format!("{} of {}",
                proof_file.inclusion_proof.leaf_index,
                proof_file.checkpoint.tree_size)),
            ("root",     &format!("sha256:{}  matches", root_short)),
            ("path",     &format!("{} steps, all valid", proof_file.inclusion_proof.path.len())),
        ]);
        printer.blank();

        // Print step-by-step verification, dispatching on the proof's
        // declared merkle version so v2 uses 0x01-prefixed internal
        // hashing (RFC 9162). v1 (legacy) skips the prefix to remain
        // byte-identical to v0.10.2-and-earlier output.
        let version = proof_file.inclusion_proof.merkle_version;
        let mut current_hex = proof_file.inclusion_proof.leaf_hash.clone();
        for (i, step) in proof_file.inclusion_proof.path.iter().enumerate() {
            let sibling_short = short_hash(&step.hash);
            let current_short = short_hash(&current_hex);

            // Recompute next hash
            let current_bytes = hex::decode(&current_hex).unwrap_or_default();
            let sibling_bytes = hex::decode(&step.hash).unwrap_or_default();
            let mut hasher = Sha256::new();
            if version == treeship_core::merkle::MERKLE_VERSION_V2 {
                hasher.update([0x01u8]);
            }
            match step.direction {
                treeship_core::merkle::Direction::Right => {
                    hasher.update(&current_bytes);
                    hasher.update(&sibling_bytes);
                }
                treeship_core::merkle::Direction::Left => {
                    hasher.update(&sibling_bytes);
                    hasher.update(&current_bytes);
                }
            }
            let result: [u8; 32] = hasher.finalize().into();
            let result_hex = hex::encode(result);
            let result_short = short_hash(&result_hex);

            let dir_str = match step.direction {
                treeship_core::merkle::Direction::Right => {
                    format!("sha256:{} + sha256:{}", current_short, sibling_short)
                }
                treeship_core::merkle::Direction::Left => {
                    format!("sha256:{} + sha256:{}", sibling_short, current_short)
                }
            };

            let check = printer.green("ok");
            printer.info(&format!("  Step {}:  {} -> sha256:{}  {}",
                i + 1, dir_str, result_short, check));

            current_hex = result_hex;
        }
        printer.blank();

        printer.info(&format!("  checkpoint: #{:04}  .  {}",
            proof_file.checkpoint.index, proof_file.checkpoint.signed_at));
        printer.info(&format!("  signed by:  {}  {}",
            proof_file.checkpoint.signer, printer.green("ok")));
        printer.blank();
        printer.info(&format!("  This artifact was in the log before {}.",
            proof_file.checkpoint.signed_at));
        printer.info("  It cannot have been inserted or backdated after this time.");
    } else {
        let mut reasons = Vec::new();
        if !sig_valid { reasons.push("checkpoint signature invalid"); }
        if !proof_valid { reasons.push("inclusion proof invalid"); }
        if !root_matches { reasons.push("root hash does not match expected"); }
        printer.failure("verification failed", &[
            ("artifact", &proof_file.artifact_id),
            ("reason",   &reasons.join(", ")),
        ]);
        return Err("verification failed".into());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// treeship merkle status
// ---------------------------------------------------------------------------

pub fn status(
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let (tree, _artifact_ids) = build_tree(&ctx)?;
    let total_artifacts = tree.len();
    let num_checkpoints = count_checkpoints()?;
    let latest_cp = load_latest_checkpoint()?;

    printer.blank();
    printer.section("Local Merkle tree");

    printer.info(&format!("  total artifacts:   {}", total_artifacts));
    printer.info(&format!("  checkpoints:       {}", num_checkpoints));

    if let Some(ref cp) = latest_cp {
        printer.info(&format!("  latest:            #{:04}  .  {}",
            cp.index, cp.signed_at));
        printer.info(&format!("  latest root:       sha256:{}",
            short_hash(&cp.root)));

        let uncheckpointed = if total_artifacts > cp.tree_size {
            total_artifacts - cp.tree_size
        } else {
            0
        };
        printer.info(&format!("  uncheckpointed:    {} artifacts",
            uncheckpointed));
    } else {
        printer.dim_info("  no checkpoints yet");
    }
    printer.blank();

    if latest_cp.is_none() && total_artifacts > 0 {
        printer.hint("treeship checkpoint");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// treeship merkle publish
// ---------------------------------------------------------------------------

pub fn publish(
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    let (_hub_name, hub_entry) = ctx.config.resolve_hub(None)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let endpoint = &hub_entry.endpoint;
    let hub_id = &hub_entry.hub_id;
    let hub_secret_hex = super::hub::resolve_dpop_secret_hex(hub_entry, &ctx.keys)?;

    // 1. Load latest checkpoint
    let checkpoint = load_latest_checkpoint()?
        .ok_or("no checkpoints found -- run: treeship checkpoint")?;

    let cp_index = format!("{:04}", checkpoint.index);
    printer.blank();
    printer.info(&format!("Publishing checkpoint #{} to Hub...", cp_index));

    // 2. POST checkpoint to Hub
    let checkpoint_url = format!("{}/v1/merkle/checkpoint", endpoint);
    let dpop_jwt = build_dpop_jwt(&hub_secret_hex, "POST", &checkpoint_url)?;

    let cp_body = serde_json::json!({
        "root":       checkpoint.root,
        "tree_size":  checkpoint.tree_size,
        "height":     checkpoint.height,
        "signed_at":  checkpoint.signed_at,
        "signer":     checkpoint.signer,
        "signature":  checkpoint.signature,
        "public_key": checkpoint.public_key,
        "index":      checkpoint.index,
        // AUD-18: the exact bytes the signature is over, so the hub can
        // ed25519-verify the checkpoint without re-implementing the versioned
        // canonical in Go. The hub cross-checks the structured fields above
        // against the values embedded in this string.
        "canonical":  checkpoint.canonical_signing_string(),
    });

    let cp_resp: serde_json::Value = ureq::post(&checkpoint_url)
        .set("Authorization", &format!("DPoP {}", hub_id))
        .set("DPoP", &dpop_jwt)
        .send_json(&cp_body)?
        .into_json()?;

    let hub_checkpoint_id = cp_resp["id"].as_i64()
        .ok_or("Hub did not return checkpoint id")?;

    printer.info(&format!("  {} checkpoint received (hub id: {})", printer.green("ok"), hub_checkpoint_id));

    // 3. Find and publish all proofs for this checkpoint. Proofs are
    // generated from the tree AS IT WAS at the checkpoint (truncated +
    // root-cross-checked by checkpoint_tree) — the full current tree would
    // yield authentication paths that reconstruct the wrong root whenever
    // artifacts were appended after checkpointing, making the hub serve
    // proofs that verifiably fail for legitimate, in-log artifacts.
    let (_, artifact_ids) = build_tree(&ctx)?;
    let cp_tree = checkpoint_tree(&artifact_ids, &checkpoint)?;
    let proof_url = format!("{}/v1/merkle/proof", endpoint);
    let mut published_count = 0u64;

    for (leaf_index, artifact_id) in artifact_ids.iter().enumerate() {
        // Only publish proofs for artifacts within this checkpoint's tree_size
        if leaf_index >= checkpoint.tree_size {
            break;
        }

        let inclusion_proof = match cp_tree.inclusion_proof(leaf_index) {
            Some(p) => p,
            None => continue,
        };

        // Load artifact record for summary
        let record = match ctx.storage.read(artifact_id) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let short_type = record.payload_type
            .strip_prefix("application/vnd.treeship.")
            .and_then(|s| s.strip_suffix(".v1+json"))
            .unwrap_or(&record.payload_type);

        let proof_file = ProofFile {
            artifact_id: artifact_id.clone(),
            artifact_summary: ArtifactSummary {
                actor: short_type.to_string(),
                action: short_type.to_string(),
                timestamp: record.signed_at.clone(),
                key_id: record.key_id.clone(),
            },
            inclusion_proof: inclusion_proof.clone(),
            checkpoint: checkpoint.clone(),
        };

        let proof_json_str = serde_json::to_string(&proof_file)?;

        let dpop_jwt = build_dpop_jwt(&hub_secret_hex, "POST", &proof_url)?;

        let proof_body = serde_json::json!({
            "artifact_id":   artifact_id,
            "checkpoint_id": hub_checkpoint_id,
            "leaf_index":    leaf_index,
            "leaf_hash":     inclusion_proof.leaf_hash,
            "proof_json":    proof_json_str,
        });

        ureq::post(&proof_url)
            .set("Authorization", &format!("DPoP {}", hub_id))
            .set("DPoP", &dpop_jwt)
            .send_json(&proof_body)?;

        published_count += 1;
    }

    printer.info(&format!("  {} {} proofs published", printer.green("ok"), published_count));

    // 4. Publish a consistency proof from the previous checkpoint (3b): proves
    //    this checkpoint's tree EXTENDS the previous one (append-only, no
    //    rewrite). Best-effort: a failure here never blocks proof publishing.
    if let Err(e) = publish_consistency(
        &checkpoint,
        &artifact_ids,
        endpoint,
        hub_id,
        &hub_secret_hex,
        printer,
    ) {
        printer.hint(&format!("consistency proof not published: {e}"));
    }
    printer.blank();

    if let Some(first_id) = artifact_ids.first() {
        printer.hint(&format!("treeship.dev/merkle?id={}  (any artifact is now verifiable via Hub)", first_id));
    }
    printer.blank();

    Ok(())
}

/// Load the checkpoint immediately before `index` (i.e. `index - 1`), if it
/// exists on disk. Used to compute the consistency proof from the previous
/// published tree to the current one.
fn load_prev_checkpoint(index: u64) -> Result<Option<Checkpoint>, Box<dyn std::error::Error>> {
    if index == 0 {
        return Ok(None);
    }
    let path = checkpoints_dir()?.join(format!("{:04}.json", index - 1));
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_slice(&fs::read(&path)?)?))
}

/// Compute and push the Merkle consistency proof from the previous checkpoint
/// (size `from`) to this one (size `to`), proving the log only appended.
///
/// Correctness is load-bearing here, so the proof is computed over the tree
/// **truncated to exactly `to_size` leaves** (the tree as it was at this
/// checkpoint), and its root is **cross-checked against the checkpoint's own
/// root** before anything is pushed. On any mismatch or degenerate range we
/// skip rather than publish a proof that would not verify. The Hub stores it
/// verbatim; the auditing client re-verifies offline with `verify_consistency`.
fn publish_consistency(
    checkpoint: &Checkpoint,
    artifact_ids: &[String],
    endpoint: &str,
    hub_id: &str,
    hub_secret_hex: &str,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(prev) = load_prev_checkpoint(checkpoint.index)? else {
        return Ok(()); // first checkpoint: nothing to extend from
    };
    let from_size = prev.tree_size;
    let to_size = checkpoint.tree_size;
    // A consistency proof only makes sense for a forward, non-empty extension
    // whose leaves we actually hold.
    if from_size == 0 || from_size > to_size || to_size > artifact_ids.len() {
        return Ok(());
    }

    // Rebuild the tree EXACTLY as it was at this checkpoint (first `to_size`
    // leaves), so the proof's upper tree matches the published checkpoint.
    let mut cp_tree = MerkleTree::new();
    for id in &artifact_ids[..to_size] {
        cp_tree.append(id);
    }
    // Cross-check: the truncated tree's root MUST equal the checkpoint's root.
    // If it does not (e.g. artifacts changed since checkpointing), skip rather
    // than push a proof that cannot verify.
    let computed_root = match cp_tree.root() {
        Some(r) => hex::encode(r),
        None => return Ok(()),
    };
    let cp_root = checkpoint.root.strip_prefix("sha256:").unwrap_or(&checkpoint.root);
    if computed_root != cp_root {
        printer.hint("consistency proof skipped: tree does not match checkpoint root (re-checkpoint before publishing)");
        return Ok(());
    }

    let Some(proof) = cp_tree.consistency_proof(from_size) else {
        return Ok(());
    };

    let from_root = prev.root.strip_prefix("sha256:").unwrap_or(&prev.root);
    let url = format!("{}/v1/merkle/consistency", endpoint);
    let dpop_jwt = build_dpop_jwt(hub_secret_hex, "POST", &url)?;
    let body = serde_json::json!({
        "signer":     checkpoint.signer,
        "from_size":  from_size,
        "from_root":  from_root,
        "to_size":    to_size,
        "to_root":    cp_root,
        "version":    checkpoint.merkle_version,
        "proof_json": serde_json::to_string(&proof)?,
        "signed_at":  checkpoint.signed_at,
    });
    ureq::post(&url)
        .set("Authorization", &format!("DPoP {}", hub_id))
        .set("DPoP", &dpop_jwt)
        .send_json(&body)?;

    printer.info(&format!(
        "  {} consistency proof published (#{:04} → #{:04}, tree_size {} → {})",
        printer.green("ok"),
        prev.index,
        checkpoint.index,
        from_size,
        to_size
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// DPoP JWT builder (mirrors hub.rs)
// ---------------------------------------------------------------------------

fn build_dpop_jwt(
    hub_secret_hex: &str,
    method: &str,
    url: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let secret_bytes = hex::decode(hub_secret_hex)?;
    let secret_arr: [u8; 32] = secret_bytes.try_into()
        .map_err(|_| "hub secret key must be 32 bytes")?;
    let signing_key = SigningKey::from_bytes(&secret_arr);

    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "dpop+jwt",
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();

    let mut jti_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut jti_bytes);
    let jti = hex::encode(jti_bytes);

    let payload = serde_json::json!({
        "iat": now,
        "jti": jti,
        "htm": method,
        "htu": url,
    });
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);

    let message = format!("{}.{}", header_b64, payload_b64);
    let signature = signing_key.sign(message.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{}.{}.{}", header_b64, payload_b64, sig_b64))
}
