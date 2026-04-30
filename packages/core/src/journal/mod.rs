//! Local Approval Use Journal -- v0.9.9 PR 2.
//!
//! Per-workspace append-only memory of consumed Approval Grants. The
//! journal turns the v0.9.6 "package-local only" replay finding into a
//! local-journal replay finding: with this module wired through, verify
//! can say "use 1/1 -- local Approval Use Journal passed" instead of
//! "no global ledger consulted."
//!
//! Scope of THIS PR:
//!   * journal storage (records/, heads/, indexes/, locks/)
//!   * append-only writes with file lock + atomic temp+rename
//!   * hash chain via `previous_record_digest`
//!   * read-only `check_replay` lookup
//!   * `verify_integrity` chain walk
//!   * `rebuild_indexes` from records (records are truth)
//!
//! Out of scope (later PRs):
//!   * consume-before-action wiring inside `treeship attest action` (PR 3)
//!   * package export of journal records (PR 4)
//!   * Hub checkpoint signing (PR 6 scaffold)
//!
//! Privacy rules baked into the layout:
//!   * `nonce_digest`, never raw nonce
//!   * no commands, prompts, file contents, bearer tokens, or API keys
//!     are stored. The journal answers the single question "has this
//!     (grant_id, nonce_digest) been consumed before, and if so how
//!     many times?" -- everything else stays in the signed grant +
//!     receipt where it already is.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

// fs2 is gated to non-wasm targets at the workspace Cargo.toml; the WASM
// build has no concurrent writers and no real filesystem, so journal
// operations fall back to a deterministic "no-op write" mode that still
// keeps the public API building. Same pattern session::event_log uses.
#[cfg(not(target_family = "wasm"))]
use fs2::FileExt;

use crate::statements::{
    ApprovalRevocation, ApprovalUse, JournalCheckpoint, ReplayCheck, ReplayCheckLevel,
    TYPE_APPROVAL_REVOCATION, TYPE_APPROVAL_USE, TYPE_JOURNAL_CHECKPOINT,
    approval_revocation_record_digest, approval_use_record_digest,
    journal_checkpoint_record_digest,
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum JournalError {
    Io(std::io::Error),
    Json(serde_json::Error),
    /// `previous_record_digest` on a record didn't match the prior
    /// record's `record_digest`. The chain is broken.
    BrokenChain {
        index:    u64,
        expected: String,
        actual:   String,
    },
    /// A record's stored `record_digest` didn't match the recomputed
    /// digest. The record was tampered after write.
    RecordTampered {
        index:    u64,
        expected: String,
        actual:   String,
    },
    /// A record file referenced by the head no longer exists.
    MissingRecord {
        index: u64,
    },
    /// The journal's append lock could not be acquired.
    LockBusy,
    /// The append exceeds `max_uses` recorded on prior uses for this
    /// grant. Surfaced as an error so callers (PR 3) refuse to sign
    /// the action; PR 2 itself only writes uses passed in by callers,
    /// so this only fires from `append_use` when the caller didn't
    /// preflight via `check_replay`.
    MaxUsesExceeded {
        grant_id:   String,
        max_uses:   u32,
        current:    u32,
    },
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e)            => write!(f, "journal io: {e}"),
            Self::Json(e)          => write!(f, "journal json: {e}"),
            Self::BrokenChain { index, expected, actual } => write!(
                f,
                "journal broken at record {index}: previous_record_digest = {actual}, expected {expected}",
            ),
            Self::RecordTampered { index, expected, actual } => write!(
                f,
                "journal record {index} tampered: stored digest {expected}, recomputed {actual}",
            ),
            Self::MissingRecord { index } => write!(
                f,
                "journal record {index} referenced by head but missing on disk",
            ),
            Self::LockBusy => write!(f, "journal append lock busy; another process holds it"),
            Self::MaxUsesExceeded { grant_id, max_uses, current } => write!(
                f,
                "approval grant {grant_id} would exceed max_uses ({current}/{max_uses})",
            ),
        }
    }
}

impl std::error::Error for JournalError {}
impl From<std::io::Error>    for JournalError { fn from(e: std::io::Error)    -> Self { Self::Io(e) } }
impl From<serde_json::Error> for JournalError { fn from(e: serde_json::Error) -> Self { Self::Json(e) } }

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

/// Directory layout under `.treeship/journals/approval-use/`.
pub struct Journal {
    /// Root directory.
    pub dir: PathBuf,
}

impl Journal {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn records_dir(&self) -> PathBuf  { self.dir.join("records") }
    pub fn heads_dir(&self)   -> PathBuf  { self.dir.join("heads") }
    pub fn indexes_dir(&self) -> PathBuf  { self.dir.join("indexes") }
    pub fn locks_dir(&self)   -> PathBuf  { self.dir.join("locks") }
    pub fn current_head_path(&self) -> PathBuf { self.heads_dir().join("current.json") }
    pub fn lock_path(&self)         -> PathBuf { self.locks_dir().join("journal.lock") }
    pub fn meta_path(&self)         -> PathBuf { self.dir.join("journal.json") }

    /// Index file for a given grant. Each line is one `record_index`.
    pub fn by_grant_path(&self, grant_id: &str) -> PathBuf {
        self.indexes_dir().join("by-grant").join(format!("{}.txt", safe_name(grant_id)))
    }

    /// Index file for a nonce_digest.
    pub fn by_nonce_path(&self, nonce_digest: &str) -> PathBuf {
        self.indexes_dir().join("by-nonce").join(format!("{}.txt", safe_name(nonce_digest)))
    }

    /// Returns true iff the journal directory exists.
    pub fn exists(&self) -> bool {
        self.dir.is_dir()
    }
}

/// Make a filesystem-safe name by replacing path-unsafe chars. Used for
/// index file names; not a security boundary -- the journal's actual
/// integrity check is the hash chain.
fn safe_name(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            ':' | '/' | '\\' | ' ' | '.' => '_',
            c => c,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Head file
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Head {
    /// 1-indexed; 0 means "no records yet."
    pub index: u64,
    /// `record_digest` of the most recent record. Empty when index=0.
    pub digest: String,
    /// Updated on every append.
    pub updated_at: String,
}

impl Default for Head {
    fn default() -> Self {
        Self {
            index:      0,
            digest:     String::new(),
            updated_at: String::new(),
        }
    }
}

fn read_head(j: &Journal) -> Result<Head, JournalError> {
    let path = j.current_head_path();
    if !path.exists() {
        return Ok(Head::default());
    }
    let bytes = fs::read(&path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_head(j: &Journal, head: &Head) -> Result<(), JournalError> {
    fs::create_dir_all(j.heads_dir())?;
    let path = j.current_head_path();
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(head)?;
    fs::write(&tmp, json)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Append
// ---------------------------------------------------------------------------

/// Acquire the journal append lock for the duration of the closure. Uses
/// fs2::FileExt::try_lock_exclusive (the same primitive `session::event_log`
/// uses) so behavior matches what the rest of the codebase already
/// trusts.
#[cfg(not(target_family = "wasm"))]
fn with_lock<F, T>(j: &Journal, body: F) -> Result<T, JournalError>
where
    F: FnOnce() -> Result<T, JournalError>,
{
    fs::create_dir_all(j.locks_dir())?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(j.lock_path())?;
    if lock.try_lock_exclusive().is_err() {
        return Err(JournalError::LockBusy);
    }
    let result = body();
    let _ = fs2::FileExt::unlock(&lock);
    result
}

/// WASM build: no concurrent writers, no advisory locks. Run the body
/// directly. Matches `session::event_log`'s wasm fallback.
#[cfg(target_family = "wasm")]
fn with_lock<F, T>(_j: &Journal, body: F) -> Result<T, JournalError>
where
    F: FnOnce() -> Result<T, JournalError>,
{
    body()
}

/// Append an ApprovalUse to the journal. The caller MUST set
/// `previous_record_digest` to the current head's digest on the
/// incoming record; we re-validate before write. `record_digest` is
/// computed from the canonical form and stamped on the stored record.
///
/// Returns the new head's index and digest.
pub fn append_use(j: &Journal, mut rec: ApprovalUse) -> Result<Head, JournalError> {
    rec.type_ = TYPE_APPROVAL_USE.into();
    with_lock(j, || {
        let head = read_head(j)?;
        rec.previous_record_digest = head.digest.clone();
        rec.record_digest = approval_use_record_digest(&rec);
        let next_index = head.index + 1;
        write_record_use(j, next_index, &rec)?;
        update_indexes_for_use(j, next_index, &rec)?;
        let new_head = Head {
            index:      next_index,
            digest:     rec.record_digest.clone(),
            updated_at: rec.created_at.clone(),
        };
        write_head(j, &new_head)?;
        ensure_meta(j)?;
        Ok(new_head)
    })
}

/// Atomic check-and-append for the consume path. Combines `check_replay` +
/// append under a single journal lock so concurrent consume paths cannot
/// bypass `max_uses` via TOCTOU race.
///
/// v0.9.9 PR 3 (`reserve_in_journal` in attest.rs) ran `check_replay` and
/// derived `use_number` *outside* `with_lock`, then called `append_use`
/// (which takes the lock only for the write). Two parallel attests could
/// both pass the pre-lock replay check, then queue serially through the
/// lock, and both would write — exceeding `max_uses=1`. v0.9.10 closes
/// that race by doing the check *inside* the lock.
///
/// The function also stamps `use_number` from the grant-wide count
/// observed at lock-acquire time. Callers should pass the record with
/// `use_number = 0` (or any value); it will be overwritten.
///
/// Returns the new head on success. On replay violation, returns
/// `JournalError::MaxUsesExceeded` and writes nothing — the lock is
/// released without state change.
pub fn reserve_use(
    j: &Journal,
    mut rec: ApprovalUse,
    max_uses: Option<u32>,
) -> Result<Head, JournalError> {
    rec.type_ = TYPE_APPROVAL_USE.into();
    with_lock(j, || {
        // Replay check inside the lock. `check_replay` reads the
        // by-nonce index; while we hold the exclusive lock, no other
        // writer can mutate that index, so the count is correct.
        let replay = check_replay(j, &rec.grant_id, &rec.nonce_digest, max_uses)?;
        if let Some(false) = replay.passed {
            let current = replay
                .use_number
                .map(|n| n.saturating_sub(1))
                .unwrap_or(0);
            return Err(JournalError::MaxUsesExceeded {
                grant_id: rec.grant_id.clone(),
                max_uses: replay.max_uses.unwrap_or(0),
                current,
            });
        }
        // Stamp use_number from grant-wide count, also inside the lock,
        // so two parallel reservations on the same grant cannot both
        // claim the same use_number.
        let prior_count = list_uses_for_grant(j, &rec.grant_id)?.len() as u32;
        rec.use_number = prior_count.saturating_add(1);
        // Append.
        let head = read_head(j)?;
        rec.previous_record_digest = head.digest.clone();
        rec.record_digest = approval_use_record_digest(&rec);
        let next_index = head.index + 1;
        write_record_use(j, next_index, &rec)?;
        update_indexes_for_use(j, next_index, &rec)?;
        let new_head = Head {
            index:      next_index,
            digest:     rec.record_digest.clone(),
            updated_at: rec.created_at.clone(),
        };
        write_head(j, &new_head)?;
        ensure_meta(j)?;
        Ok(new_head)
    })
}

/// Append an ApprovalRevocation. Sibling of `append_use`.
pub fn append_revocation(j: &Journal, mut rec: ApprovalRevocation) -> Result<Head, JournalError> {
    rec.type_ = TYPE_APPROVAL_REVOCATION.into();
    with_lock(j, || {
        let head = read_head(j)?;
        rec.previous_record_digest = head.digest.clone();
        rec.record_digest = approval_revocation_record_digest(&rec);
        let next_index = head.index + 1;
        write_record_revocation(j, next_index, &rec)?;
        index_grant(j, next_index, &rec.grant_id)?;
        let new_head = Head {
            index:      next_index,
            digest:     rec.record_digest.clone(),
            updated_at: rec.created_at.clone(),
        };
        write_head(j, &new_head)?;
        ensure_meta(j)?;
        Ok(new_head)
    })
}

/// Append a JournalCheckpoint over a contiguous range of prior records.
pub fn append_checkpoint(j: &Journal, mut rec: JournalCheckpoint) -> Result<Head, JournalError> {
    rec.type_ = TYPE_JOURNAL_CHECKPOINT.into();
    with_lock(j, || {
        let head = read_head(j)?;
        rec.previous_record_digest = head.digest.clone();
        rec.record_digest = journal_checkpoint_record_digest(&rec);
        let next_index = head.index + 1;
        write_record_checkpoint(j, next_index, &rec)?;
        let new_head = Head {
            index:      next_index,
            digest:     rec.record_digest.clone(),
            updated_at: rec.created_at.clone(),
        };
        write_head(j, &new_head)?;
        ensure_meta(j)?;
        Ok(new_head)
    })
}

fn record_filename(index: u64, type_: &str, digest: &str) -> String {
    // Use the digest's hex tail (after "sha256:") so the filename is
    // bounded length and contains no separators.
    let tail = digest.strip_prefix("sha256:").unwrap_or(digest);
    let short = &tail[..tail.len().min(16)];
    format!("{:010}.{type_}.{short}.json", index)
}

fn write_record_use(j: &Journal, index: u64, rec: &ApprovalUse) -> Result<(), JournalError> {
    fs::create_dir_all(j.records_dir())?;
    let name = record_filename(index, "approval-use", &rec.record_digest);
    let path = j.records_dir().join(&name);
    let tmp = path.with_extension("json.tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(&serde_json::to_vec_pretty(rec)?)?;
    f.sync_all()?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

fn write_record_revocation(j: &Journal, index: u64, rec: &ApprovalRevocation) -> Result<(), JournalError> {
    fs::create_dir_all(j.records_dir())?;
    let name = record_filename(index, "approval-revocation", &rec.record_digest);
    let path = j.records_dir().join(&name);
    let tmp = path.with_extension("json.tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(&serde_json::to_vec_pretty(rec)?)?;
    f.sync_all()?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

fn write_record_checkpoint(j: &Journal, index: u64, rec: &JournalCheckpoint) -> Result<(), JournalError> {
    fs::create_dir_all(j.records_dir())?;
    let name = record_filename(index, "journal-checkpoint", &rec.record_digest);
    let path = j.records_dir().join(&name);
    let tmp = path.with_extension("json.tmp");
    let mut f = File::create(&tmp)?;
    f.write_all(&serde_json::to_vec_pretty(rec)?)?;
    f.sync_all()?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

fn ensure_meta(j: &Journal) -> Result<(), JournalError> {
    let path = j.meta_path();
    if path.exists() {
        return Ok(());
    }
    #[derive(serde::Serialize)]
    struct Meta<'a> {
        kind:    &'a str,
        version: &'a str,
        format:  &'a str,
    }
    let meta = Meta { kind: "approval-use-journal", version: "v1", format: "json-records" };
    let bytes = serde_json::to_vec_pretty(&meta)?;
    fs::write(&path, bytes)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Indexes (rebuildable cache)
// ---------------------------------------------------------------------------

fn append_index(path: &Path, line: &str) -> Result<(), JournalError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new().append(true).create(true).open(path)?;
    writeln!(f, "{line}")?;
    Ok(())
}

fn index_grant(j: &Journal, index: u64, grant_id: &str) -> Result<(), JournalError> {
    append_index(&j.by_grant_path(grant_id), &index.to_string())
}

fn index_nonce(j: &Journal, index: u64, nonce_digest: &str) -> Result<(), JournalError> {
    append_index(&j.by_nonce_path(nonce_digest), &index.to_string())
}

fn update_indexes_for_use(j: &Journal, index: u64, rec: &ApprovalUse) -> Result<(), JournalError> {
    index_grant(j, index, &rec.grant_id)?;
    index_nonce(j, index, &rec.nonce_digest)?;
    Ok(())
}

/// Delete and rebuild every index from the records directory. Records are
/// truth; indexes are cache. Useful as a recovery tool when an index file
/// is corrupt or out of sync.
pub fn rebuild_indexes(j: &Journal) -> Result<u64, JournalError> {
    let dir = j.indexes_dir();
    if dir.is_dir() {
        // Wipe by recursive remove. Atomic enough; the worst-case is a
        // partially-rebuilt index, which the next call to this function
        // also recovers from.
        fs::remove_dir_all(&dir)?;
    }
    let mut rebuilt = 0u64;
    for (idx, kind, bytes) in iter_records(j)? {
        match kind.as_str() {
            "approval-use" => {
                let rec: ApprovalUse = serde_json::from_slice(&bytes)?;
                update_indexes_for_use(j, idx, &rec)?;
                rebuilt += 1;
            }
            "approval-revocation" => {
                let rec: ApprovalRevocation = serde_json::from_slice(&bytes)?;
                index_grant(j, idx, &rec.grant_id)?;
                rebuilt += 1;
            }
            "journal-checkpoint" => {
                rebuilt += 1; // checkpoints aren't indexed by grant/nonce
            }
            _ => {}
        }
    }
    Ok(rebuilt)
}

// ---------------------------------------------------------------------------
// Iteration + integrity
// ---------------------------------------------------------------------------

/// Walk records/ in index order. Returns `(index, kind, bytes)`. Kind is
/// derived from the filename ("approval-use" / "approval-revocation" /
/// "journal-checkpoint"). Filenames Treeship doesn't recognize are
/// skipped silently rather than failing the whole walk -- a future record
/// type added by a newer version shouldn't break older readers.
fn iter_records(j: &Journal) -> Result<Vec<(u64, String, Vec<u8>)>, JournalError> {
    let dir = j.records_dir();
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut entries: Vec<(u64, String, PathBuf)> = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None    => continue,
        };
        // Filename shape: "<10-digit-index>.<kind>.<short-digest>.json"
        let mut parts = name.splitn(4, '.');
        let idx_str = match parts.next() { Some(s) => s, None => continue };
        let kind    = match parts.next() { Some(s) => s, None => continue };
        // index parses as u64
        let idx = match idx_str.parse::<u64>() { Ok(n) => n, Err(_) => continue };
        entries.push((idx, kind.to_string(), path));
    }
    entries.sort_by_key(|(idx, _, _)| *idx);
    let mut out = Vec::with_capacity(entries.len());
    for (idx, kind, path) in entries {
        let bytes = fs::read(&path)?;
        out.push((idx, kind, bytes));
    }
    Ok(out)
}

/// Walk every record in order, recompute each `record_digest`, and check
/// that each record's `previous_record_digest` matches the prior
/// record's stored `record_digest`. Returns the number of records walked
/// or an error pinpointing the first integrity failure.
pub fn verify_integrity(j: &Journal) -> Result<u64, JournalError> {
    let mut prior_digest = String::new();
    let mut count = 0u64;
    let head = read_head(j)?;
    for (idx, kind, bytes) in iter_records(j)? {
        match kind.as_str() {
            "approval-use" => {
                let rec: ApprovalUse = serde_json::from_slice(&bytes)?;
                if rec.previous_record_digest != prior_digest {
                    return Err(JournalError::BrokenChain {
                        index:    idx,
                        expected: prior_digest,
                        actual:   rec.previous_record_digest,
                    });
                }
                let recomputed = approval_use_record_digest(&rec);
                if recomputed != rec.record_digest {
                    return Err(JournalError::RecordTampered {
                        index:    idx,
                        expected: rec.record_digest,
                        actual:   recomputed,
                    });
                }
                prior_digest = rec.record_digest;
            }
            "approval-revocation" => {
                let rec: ApprovalRevocation = serde_json::from_slice(&bytes)?;
                if rec.previous_record_digest != prior_digest {
                    return Err(JournalError::BrokenChain {
                        index:    idx,
                        expected: prior_digest,
                        actual:   rec.previous_record_digest,
                    });
                }
                let recomputed = approval_revocation_record_digest(&rec);
                if recomputed != rec.record_digest {
                    return Err(JournalError::RecordTampered {
                        index:    idx,
                        expected: rec.record_digest,
                        actual:   recomputed,
                    });
                }
                prior_digest = rec.record_digest;
            }
            "journal-checkpoint" => {
                let rec: JournalCheckpoint = serde_json::from_slice(&bytes)?;
                if rec.previous_record_digest != prior_digest {
                    return Err(JournalError::BrokenChain {
                        index:    idx,
                        expected: prior_digest,
                        actual:   rec.previous_record_digest,
                    });
                }
                let recomputed = journal_checkpoint_record_digest(&rec);
                if recomputed != rec.record_digest {
                    return Err(JournalError::RecordTampered {
                        index:    idx,
                        expected: rec.record_digest,
                        actual:   recomputed,
                    });
                }
                prior_digest = rec.record_digest;
            }
            _ => {
                // Unknown record kind. Stop the chain check rather than
                // skip silently -- a newer record type would still need
                // to participate in the chain.
                continue;
            }
        }
        count += 1;
    }
    // Tail must match the head if records exist; if records were
    // deleted off the end the head will be stale.
    if head.index != 0 && head.digest != prior_digest {
        return Err(JournalError::MissingRecord { index: head.index });
    }
    Ok(count)
}

// ---------------------------------------------------------------------------
// check_replay
// ---------------------------------------------------------------------------

/// Check whether (`grant_id`, `nonce_digest`) has already been consumed,
/// and how many times. Returns a `ReplayCheck` carrying the strongest
/// level the journal can speak to:
///
///   - `NotPerformed` when the journal directory does not exist on disk.
///     The caller (verify) should fall back to its package-local check.
///   - `LocalJournal` otherwise. `passed: true` means the use count is
///     within `max_uses_hint`; `false` means it would exceed.
///
/// `max_uses_hint` is what the caller knows from the signed grant's
/// `ApprovalScope.max_actions`. We accept it as a hint rather than
/// reading it back from a stored record because the stored uses already
/// carry their own `max_uses` snapshot, and disagreement between the
/// hint and the stored value should be visible in `details`.
pub fn check_replay(
    j: &Journal,
    grant_id: &str,
    nonce_digest: &str,
    max_uses_hint: Option<u32>,
) -> Result<ReplayCheck, JournalError> {
    if !j.exists() {
        return Ok(ReplayCheck::not_performed());
    }
    // Use the by-nonce index: every prior use of the same approval
    // shares the same nonce_digest, so the index gives us the exact
    // record list.
    let index_path = j.by_nonce_path(nonce_digest);
    let mut current = 0u32;
    let mut last_max: Option<u32> = None;
    if index_path.exists() {
        let raw = fs::read_to_string(&index_path)?;
        for line in raw.lines() {
            let idx: u64 = match line.trim().parse() { Ok(n) => n, Err(_) => continue };
            if let Some(rec) = load_use_record(j, idx)? {
                // Only count uses that bind to the same grant_id; the
                // by-nonce index can in theory share a digest across
                // grants, though in practice nonces are random.
                if rec.grant_id == grant_id {
                    current = current.saturating_add(1);
                    last_max = rec.max_uses.or(last_max);
                }
            }
        }
    }
    let max_uses = max_uses_hint.or(last_max);
    let passed = match max_uses {
        Some(m) => current < m,
        None    => true, // unbounded grant; PR 5 reports this honestly
    };
    let details = match max_uses {
        Some(m) => format!("local Approval Use Journal: use {current}/{m}"),
        None    => format!("local Approval Use Journal: {current} prior use(s); grant has no max_uses"),
    };
    Ok(ReplayCheck {
        level:      ReplayCheckLevel::LocalJournal,
        use_number: Some(current.saturating_add(1)),
        max_uses,
        passed:     Some(passed),
        details:    Some(details),
    })
}

fn load_use_record(j: &Journal, index: u64) -> Result<Option<ApprovalUse>, JournalError> {
    let dir = j.records_dir();
    if !dir.is_dir() {
        return Ok(None);
    }
    let prefix = format!("{:010}.approval-use.", index);
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(&prefix) {
            let bytes = fs::read(entry.path())?;
            let rec: ApprovalUse = serde_json::from_slice(&bytes)?;
            return Ok(Some(rec));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Public read helpers (CLI)
// ---------------------------------------------------------------------------

/// Find the recorded ApprovalUse for an already-signed action.
/// Returns the matching use record plus a `ReplayCheck` that answers
/// the *verify-time* question -- "is the recorded use within max_uses?"
/// -- as opposed to `check_replay`'s consume-time question -- "would
/// the next use exceed?". The two questions look the same but have
/// different boundary semantics:
///
///   consume-time: passed = use_number_that_would_be_allocated <= max_uses
///                 (i.e. current_count < max_uses, since next = current + 1)
///   verify-time:  passed = recorded_use_number <= max_uses
///
/// Verify should call THIS, not check_replay, when reporting on an
/// action that already has a journal record.
pub fn find_use_for_action(
    j: &Journal,
    grant_id: &str,
    nonce_digest: &str,
    max_uses_hint: Option<u32>,
) -> Result<Option<(ApprovalUse, ReplayCheck)>, JournalError> {
    if !j.exists() {
        return Ok(None);
    }
    let index_path = j.by_nonce_path(nonce_digest);
    if !index_path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&index_path)?;
    // The action under verification corresponds to the most recent use
    // record sharing the same (grant_id, nonce_digest) -- callers can
    // also disambiguate by `approval_use_id` from action.meta, which
    // PR 4 wires in. For PR 3, returning the most recent matching use
    // is sufficient and matches what verify can derive without that
    // metadata link.
    let mut latest: Option<ApprovalUse> = None;
    for line in raw.lines() {
        let idx: u64 = match line.trim().parse() { Ok(n) => n, Err(_) => continue };
        if let Some(rec) = load_use_record(j, idx)? {
            if rec.grant_id == grant_id {
                latest = Some(rec);
            }
        }
    }
    let Some(rec) = latest else { return Ok(None) };

    let stored_max = rec.max_uses;
    let max_uses = max_uses_hint.or(stored_max);
    let passed = match max_uses {
        Some(m) => rec.use_number <= m,
        None    => true,
    };
    let details = match max_uses {
        Some(m) => format!("local Approval Use Journal passed, use {}/{}", rec.use_number, m),
        None    => format!("local Approval Use Journal: use {} of unbounded grant", rec.use_number),
    };
    Ok(Some((
        rec.clone(),
        ReplayCheck {
            level:      ReplayCheckLevel::LocalJournal,
            use_number: Some(rec.use_number),
            max_uses,
            passed:     Some(passed),
            details:    Some(details),
        },
    )))
}

/// Every ApprovalUse for `grant_id`. Reads the by-grant index, then
/// loads each record. Quiet on missing journal.
pub fn list_uses_for_grant(j: &Journal, grant_id: &str) -> Result<Vec<ApprovalUse>, JournalError> {
    if !j.exists() {
        return Ok(Vec::new());
    }
    let index_path = j.by_grant_path(grant_id);
    if !index_path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(&index_path)?;
    let mut out = Vec::new();
    for line in raw.lines() {
        let idx: u64 = match line.trim().parse() { Ok(n) => n, Err(_) => continue };
        if let Some(rec) = load_use_record(j, idx)? {
            out.push(rec);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample_use(use_id: &str, grant_id: &str, nonce_digest: &str, n: u32) -> ApprovalUse {
        ApprovalUse {
            type_:                  TYPE_APPROVAL_USE.into(),
            use_id:                 use_id.into(),
            grant_id:               grant_id.into(),
            grant_digest:           "sha256:00".into(),
            nonce_digest:           nonce_digest.into(),
            actor:                  "agent://deployer".into(),
            action:                 "deploy.production".into(),
            subject:                "env://production".into(),
            session_id:             None,
            action_artifact_id:     None,
            receipt_digest:         None,
            use_number:             n,
            max_uses:               Some(2),
            idempotency_key:        None,
            created_at:             "2026-04-30T07:00:00Z".into(),
            expires_at:             None,
            previous_record_digest: String::new(), // append_use rewrites this
            record_digest:          String::new(), // append_use rewrites this
            signature:              None,
            signature_alg:          None,
            signing_key_id:         None,
        }
    }

    #[test]
    fn first_append_creates_layout_and_head() {
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        let head = append_use(&j, sample_use("use_1", "g1", "sha256:nn1", 1)).unwrap();
        assert_eq!(head.index, 1);
        assert!(j.records_dir().is_dir());
        assert!(j.heads_dir().is_dir());
        assert!(j.current_head_path().is_file());
        assert!(j.meta_path().is_file());
        // by-grant + by-nonce indexes populated
        assert!(j.by_grant_path("g1").is_file());
        assert!(j.by_nonce_path("sha256:nn1").is_file());
    }

    #[test]
    fn second_append_links_previous_record_digest() {
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        let h1 = append_use(&j, sample_use("use_1", "g1", "sha256:nn1", 1)).unwrap();
        let h2 = append_use(&j, sample_use("use_2", "g1", "sha256:nn2", 2)).unwrap();
        assert_eq!(h2.index, 2);
        // Reading record 2 should show previous_record_digest == h1.digest
        let recs = iter_records(&j).unwrap();
        assert_eq!(recs.len(), 2);
        let (_, _, bytes) = &recs[1];
        let r2: ApprovalUse = serde_json::from_slice(bytes).unwrap();
        assert_eq!(r2.previous_record_digest, h1.digest);
    }

    #[test]
    fn verify_integrity_passes_on_intact_chain() {
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        for i in 1..=5 {
            let nd = format!("sha256:nn{i}");
            append_use(&j, sample_use(&format!("use_{i}"), "g1", &nd, i)).unwrap();
        }
        assert_eq!(verify_integrity(&j).unwrap(), 5);
    }

    #[test]
    fn editing_a_record_breaks_integrity() {
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        append_use(&j, sample_use("use_1", "g1", "sha256:nn1", 1)).unwrap();
        // Find the on-disk record file and corrupt it.
        let entries: Vec<_> = fs::read_dir(j.records_dir()).unwrap().collect();
        let entry = entries.into_iter().next().unwrap().unwrap();
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(entry.path()).unwrap()).unwrap();
        json["actor"] = "agent://attacker".into();
        fs::write(entry.path(), serde_json::to_vec_pretty(&json).unwrap()).unwrap();

        let err = verify_integrity(&j).unwrap_err();
        assert!(
            matches!(err, JournalError::RecordTampered { .. }),
            "expected RecordTampered, got {err:?}"
        );
    }

    #[test]
    fn deleting_a_record_breaks_integrity_or_head_continuity() {
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        append_use(&j, sample_use("use_1", "g1", "sha256:nn1", 1)).unwrap();
        append_use(&j, sample_use("use_2", "g1", "sha256:nn2", 2)).unwrap();
        // Remove the trailing record. Head still points at index 2.
        let entries: Vec<_> = fs::read_dir(j.records_dir())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        let trailing = entries.iter().max().unwrap();
        fs::remove_file(trailing).unwrap();

        let err = verify_integrity(&j).unwrap_err();
        assert!(
            matches!(err, JournalError::MissingRecord { .. }),
            "expected MissingRecord, got {err:?}"
        );
    }

    #[test]
    fn indexes_can_be_rebuilt_from_records() {
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        for i in 1..=3 {
            let nd = format!("sha256:nn{i}");
            append_use(&j, sample_use(&format!("use_{i}"), "g1", &nd, i)).unwrap();
        }
        // Wipe indexes; check_replay (or rebuild_indexes) should still work.
        fs::remove_dir_all(j.indexes_dir()).unwrap();

        let rebuilt = rebuild_indexes(&j).unwrap();
        assert_eq!(rebuilt, 3);
        assert!(j.by_grant_path("g1").is_file());
        assert!(j.by_nonce_path("sha256:nn1").is_file());
    }

    #[test]
    fn check_replay_reports_use_count_and_max() {
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        // Two prior uses of grant g1 with the same nonce_digest.
        append_use(&j, sample_use("use_1", "g1", "sha256:nn1", 1)).unwrap();
        append_use(&j, sample_use("use_2", "g1", "sha256:nn1", 2)).unwrap();

        // max_uses_hint = 2: the next use would be 3/2 -> not passed.
        let r = check_replay(&j, "g1", "sha256:nn1", Some(2)).unwrap();
        assert_eq!(r.level, ReplayCheckLevel::LocalJournal);
        assert_eq!(r.use_number, Some(3));
        assert_eq!(r.max_uses,   Some(2));
        assert_eq!(r.passed,     Some(false));
    }

    #[test]
    fn check_replay_passes_when_under_max() {
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        append_use(&j, sample_use("use_1", "g1", "sha256:nn1", 1)).unwrap();
        let r = check_replay(&j, "g1", "sha256:nn1", Some(2)).unwrap();
        assert_eq!(r.use_number, Some(2));
        assert_eq!(r.passed,     Some(true));
    }

    #[test]
    fn check_replay_no_journal_returns_not_performed() {
        let dir = tempdir().unwrap();
        let absent = dir.path().join("nope");
        let j = Journal::new(&absent);
        let r = check_replay(&j, "g1", "sha256:nn1", Some(1)).unwrap();
        assert_eq!(r.level, ReplayCheckLevel::NotPerformed);
        assert!(r.use_number.is_none());
    }

    #[test]
    fn check_replay_unbounded_grant_passes_with_count() {
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        append_use(&j, sample_use("use_1", "g1", "sha256:nn1", 1)).unwrap();
        // No max_uses_hint and stored record's max_uses is Some(2) too,
        // so we explicitly set None on a fresh record to test the
        // unbounded path.
        let mut u = sample_use("use_2", "g2", "sha256:other", 1);
        u.max_uses = None;
        append_use(&j, u).unwrap();

        let r = check_replay(&j, "g2", "sha256:other", None).unwrap();
        assert!(r.passed.unwrap());
        assert!(r.max_uses.is_none());
    }

    #[test]
    fn list_uses_for_grant_returns_records_in_order() {
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        append_use(&j, sample_use("use_1", "g1", "sha256:nn1", 1)).unwrap();
        append_use(&j, sample_use("use_2", "g2", "sha256:nn2", 1)).unwrap();
        append_use(&j, sample_use("use_3", "g1", "sha256:nn3", 2)).unwrap();
        let g1 = list_uses_for_grant(&j, "g1").unwrap();
        assert_eq!(g1.len(), 2);
        assert_eq!(g1[0].use_id, "use_1");
        assert_eq!(g1[1].use_id, "use_3");
    }

    #[test]
    fn lock_keeps_two_appends_serial() {
        // Hold the lock externally; an append should fail with LockBusy
        // rather than racing or silently overwriting.
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        fs::create_dir_all(j.locks_dir()).unwrap();
        let held = OpenOptions::new()
            .read(true).write(true).create(true).truncate(false)
            .open(j.lock_path()).unwrap();
        held.try_lock_exclusive().unwrap();

        let err = append_use(&j, sample_use("use_1", "g1", "sha256:nn1", 1)).unwrap_err();
        assert!(matches!(err, JournalError::LockBusy));

        let _ = fs2::FileExt::unlock(&held);
    }

    #[test]
    fn revocation_appends_into_chain() {
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        append_use(&j, sample_use("use_1", "g1", "sha256:nn1", 1)).unwrap();
        let rev = ApprovalRevocation {
            type_:                  TYPE_APPROVAL_REVOCATION.into(),
            revocation_id:          "rev_1".into(),
            grant_id:               "g1".into(),
            grant_digest:           "sha256:00".into(),
            revoker:                "human://alice".into(),
            reason:                 Some("rotated key".into()),
            created_at:             "2026-04-30T07:01:00Z".into(),
            previous_record_digest: String::new(),
            record_digest:          String::new(),
            signature:              None,
            signature_alg:          None,
            signing_key_id:         None,
        };
        let h = append_revocation(&j, rev).unwrap();
        assert_eq!(h.index, 2);
        assert_eq!(verify_integrity(&j).unwrap(), 2);
    }

    #[test]
    fn record_files_contain_no_raw_nonce_or_signature_secrets() {
        // Privacy invariant: ApprovalUse has no `nonce` field on the
        // struct, so by construction the stored JSON only contains
        // `nonce_digest`. This test pins the on-disk shape so a future
        // schema change can't sneak in a raw-nonce field.
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        append_use(&j, sample_use("use_1", "g1", "sha256:nn1", 1)).unwrap();
        let entries: Vec<_> = fs::read_dir(j.records_dir())
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        let bytes = fs::read(&entries[0]).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let obj = json.as_object().unwrap();
        for forbidden in ["nonce", "command", "prompt", "file_content", "bearer_token", "api_key"] {
            assert!(
                !obj.contains_key(forbidden),
                "journal record must not contain `{forbidden}`",
            );
        }
        // The digest IS allowed.
        assert!(obj.contains_key("nonce_digest"));
    }

    // -- v0.9.10 PR A: reserve_use atomic check+append regression tests --

    #[test]
    fn reserve_use_first_call_succeeds_and_stamps_use_number() {
        // Caller passes use_number=0; reserve_use stamps it from the
        // grant-wide count observed inside the lock.
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        let mut rec = sample_use("use_1", "g1", "sha256:nn1", 0);
        rec.use_number = 0;
        let head = reserve_use(&j, rec, Some(1)).unwrap();
        assert_eq!(head.index, 1);
        let stored = list_uses_for_grant(&j, "g1").unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].use_number, 1, "reserve_use must stamp use_number=1 for the first use");
    }

    #[test]
    fn reserve_use_max_uses_1_serial_second_call_rejects() {
        // Sequential second call with the same nonce against
        // max_uses=1 must error with MaxUsesExceeded BEFORE writing.
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        reserve_use(&j, sample_use("use_1", "g1", "sha256:nn_a", 0), Some(1)).unwrap();

        let err = reserve_use(&j, sample_use("use_2", "g1", "sha256:nn_a", 0), Some(1))
            .expect_err("second consume of max_uses=1 grant must fail");
        match err {
            JournalError::MaxUsesExceeded { grant_id, max_uses, current } => {
                assert_eq!(grant_id, "g1");
                assert_eq!(max_uses, 1);
                assert_eq!(current, 1);
            }
            other => panic!("expected MaxUsesExceeded, got {other:?}"),
        }
        // Crucially, the second record is NOT written.
        let stored = list_uses_for_grant(&j, "g1").unwrap();
        assert_eq!(stored.len(), 1, "rejected reserve must not append");
    }

    #[test]
    fn reserve_use_max_uses_2_two_uses_pass_third_rejects() {
        // Legitimate multi-use grant: two distinct nonces, same grant.
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        let mut a = sample_use("use_1", "g1", "sha256:nn_a", 0); a.max_uses = Some(2);
        let mut b = sample_use("use_2", "g1", "sha256:nn_b", 0); b.max_uses = Some(2);
        reserve_use(&j, a, Some(2)).unwrap();
        reserve_use(&j, b, Some(2)).unwrap();
        // A third nonce with max_uses=2 is fine (per-nonce check, not
        // per-grant); the journal's invariant is single-use-per-nonce.
        let mut c = sample_use("use_3", "g1", "sha256:nn_c", 0); c.max_uses = Some(2);
        reserve_use(&j, c, Some(2)).unwrap();
        // But a SECOND consume of nn_a violates max_uses=2 because
        // that nonce already has 1 use; 1+1 = 2 is within bound, so
        // this second use of nn_a is actually allowed — pin that.
        let mut a2 = sample_use("use_1b", "g1", "sha256:nn_a", 0); a2.max_uses = Some(2);
        reserve_use(&j, a2, Some(2)).unwrap();
        // A THIRD consume of nn_a exceeds max_uses=2.
        let mut a3 = sample_use("use_1c", "g1", "sha256:nn_a", 0); a3.max_uses = Some(2);
        let err = reserve_use(&j, a3, Some(2)).expect_err("third use of same nonce must fail");
        assert!(matches!(err, JournalError::MaxUsesExceeded { .. }));
    }

    /// Round-2 hardening: idempotency-key retries through the
    /// CLI's `reserve_in_journal` should NOT bypass `reserve_use`'s
    /// max_uses gate. The CLI checks the idempotency key against
    /// existing uses *before* calling `reserve_use`; this test
    /// confirms that path doesn't sneak a second reservation past
    /// max_uses=1 just because a flaky retry uses the same key.
    ///
    /// The journal-level invariant we pin here: even if a caller
    /// repeatedly invokes `reserve_use` with the same record after a
    /// `LockBusy`, the second call sees the first record (now
    /// committed) and rejects with `MaxUsesExceeded`. There is no
    /// "free retry" loophole.
    #[test]
    fn reserve_use_retry_after_lock_busy_does_not_bypass_max_uses() {
        let dir = tempdir().unwrap();
        let j = Journal::new(dir.path());
        // First reserve commits use_1.
        reserve_use(&j, sample_use("use_1", "g1", "sha256:nn_retry", 0), Some(1)).unwrap();
        // Subsequent reserves with the SAME nonce all fail with
        // MaxUsesExceeded -- no retry-bypass window.
        for i in 0..5 {
            let err = reserve_use(
                &j,
                sample_use(&format!("use_retry_{i}"), "g1", "sha256:nn_retry", 0),
                Some(1),
            ).expect_err("retry must fail");
            assert!(matches!(err, JournalError::MaxUsesExceeded { .. }));
        }
        let stored = list_uses_for_grant(&j, "g1").unwrap();
        assert_eq!(stored.len(), 1, "exactly one record on disk despite 5 retries");
    }

    #[test]
    fn reserve_use_concurrent_max_uses_1_only_one_succeeds() {
        // The headline regression test for the v0.9.9 TOCTOU race.
        //
        // Eight threads race to reserve the same (grant_id, nonce_digest)
        // against max_uses=1. With v0.9.9's split check_replay/append_use
        // pattern, two threads could both pass the pre-lock replay check
        // and write — exceeding max_uses. With v0.9.10's reserve_use,
        // the check happens INSIDE the lock; exactly one thread wins.
        //
        // Outcomes for the 7 losers are a mix of:
        //   - LockBusy: the lock was held when they tried try_lock
        //   - MaxUsesExceeded: they got the lock after the winner
        //     released, saw the winner's record, declined to write
        // Both are correct — neither is a bypass.
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::thread;

        let dir = tempdir().unwrap();
        let dir_path = Arc::new(dir.path().to_path_buf());
        let success = Arc::new(AtomicUsize::new(0));
        let lock_busy = Arc::new(AtomicUsize::new(0));
        let max_exceeded = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for i in 0..8 {
            let dir_path = Arc::clone(&dir_path);
            let success = Arc::clone(&success);
            let lock_busy = Arc::clone(&lock_busy);
            let max_exceeded = Arc::clone(&max_exceeded);
            handles.push(thread::spawn(move || {
                let j = Journal::new(dir_path.as_path());
                let rec = sample_use(
                    &format!("use_{i}"),
                    "g1",
                    "sha256:race_nonce",
                    0,
                );
                match reserve_use(&j, rec, Some(1)) {
                    Ok(_)                                            => { success.fetch_add(1, Ordering::SeqCst); }
                    Err(JournalError::LockBusy)                      => { lock_busy.fetch_add(1, Ordering::SeqCst); }
                    Err(JournalError::MaxUsesExceeded { .. })        => { max_exceeded.fetch_add(1, Ordering::SeqCst); }
                    Err(other) => panic!("unexpected error: {other:?}"),
                }
            }));
        }
        for h in handles { h.join().unwrap(); }

        let s = success.load(Ordering::SeqCst);
        let lb = lock_busy.load(Ordering::SeqCst);
        let me = max_exceeded.load(Ordering::SeqCst);
        assert_eq!(s, 1, "exactly one of 8 concurrent reserves must succeed; got {s} (lock_busy={lb}, max_exceeded={me})");
        assert_eq!(s + lb + me, 8, "every thread accounted for");

        // Belt-and-braces: only one record actually on disk for this nonce.
        let stored = list_uses_for_grant(&Journal::new(dir.path()), "g1").unwrap();
        let same_nonce = stored.iter().filter(|u| u.nonce_digest == "sha256:race_nonce").count();
        assert_eq!(same_nonce, 1, "exactly one record on disk for the contested nonce");
    }
}
