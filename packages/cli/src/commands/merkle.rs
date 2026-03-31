use std::{
    fs,
    path::PathBuf,
};

use sha2::{Sha256, Digest};
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
fn build_tree(
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
fn load_latest_checkpoint() -> Result<Option<Checkpoint>, Box<dyn std::error::Error>> {
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

pub fn proof(
    artifact_id: &str,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let (tree, artifact_ids) = build_tree(&ctx)?;

    // Find the artifact's leaf index
    let leaf_index = artifact_ids.iter()
        .position(|id| id == artifact_id)
        .ok_or_else(|| format!("artifact {} not found in store", artifact_id))?;

    // Generate inclusion proof
    let inclusion_proof = tree.inclusion_proof(leaf_index)
        .ok_or("failed to generate inclusion proof")?;

    // Load latest checkpoint
    let checkpoint = load_latest_checkpoint()?
        .ok_or("no checkpoints found -- run 'treeship checkpoint' first")?;

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

    // 1. Verify checkpoint signature
    let sig_valid = proof_file.checkpoint.verify();

    // 2. Verify inclusion proof
    let root_hex = proof_file.checkpoint.root
        .strip_prefix("sha256:")
        .unwrap_or(&proof_file.checkpoint.root);

    let proof_valid = MerkleTree::verify_proof(
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

        // Print step-by-step verification
        let mut current_hex = proof_file.inclusion_proof.leaf_hash.clone();
        for (i, step) in proof_file.inclusion_proof.path.iter().enumerate() {
            let sibling_short = short_hash(&step.hash);
            let current_short = short_hash(&current_hex);

            // Recompute next hash
            let current_bytes = hex::decode(&current_hex).unwrap_or_default();
            let sibling_bytes = hex::decode(&step.hash).unwrap_or_default();
            let mut hasher = Sha256::new();
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
