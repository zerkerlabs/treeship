//! Append-only, file-backed event log for session events.
//!
//! Events are stored as newline-delimited JSON (JSONL) in
//! `.treeship/sessions/<session_id>/events.jsonl`.
//!
//! Concurrency model: `append()` is safe to call from multiple processes
//! concurrently. Each call attempts to acquire an exclusive advisory lock
//! (via `fs2::FileExt::try_lock_exclusive` -- backed by `flock(2)` on Unix
//! and `LockFileEx` on Windows) on a sidecar `events.jsonl.lock` file in a
//! ~500ms bounded retry loop. Under the lock, a counter sidecar
//! `events.jsonl.count` is the authoritative source for the next
//! `sequence_no`. The per-process AtomicU64 is retained as a hot-path
//! optimization for non-contended use, but its value is overwritten by the
//! on-disk counter after every locked append.
//!
//! Counter sidecar format (16 bytes):
//!   - bytes 0..8:  count (u64 LE) -- number of events written to events.jsonl
//!   - bytes 8..16: byte_size (u64 LE) -- size of events.jsonl when count was recorded
//!
//! The byte_size field is the crash detector. If a peer wrote events.jsonl
//! but crashed before fsyncing the counter (or vice versa), the size on disk
//! and the size in the counter disagree. On any mismatch we fall back to an
//! O(N) line count and rewrite the counter -- one paid scan, then back to
//! O(1) on every subsequent append.
//!
//! This bounds steady-state append cost at constant: read 16 bytes, write
//! one JSONL line, write 16 bytes. The previous implementation re-streamed
//! the entire events.jsonl on every append, which made hooks O(N) in
//! session length and dominated PostToolUse latency on long sessions.
//!
//! Fail-open semantics: if a writer cannot acquire the lock within the
//! retry window (typically because a peer crashed while holding it, or a
//! filesystem doesn't honor flock at all), the append still proceeds
//! without the lock and writes a stderr warning. In that degenerate case
//! the resulting `sequence_no` is best-effort rather than guaranteed
//! monotonic, but the event itself is preserved -- the alternative
//! (blocking the agent forever on a wedged peer) is strictly worse.
//!
//! Lock file permissions are 0o600 (owner-only) on Unix, applied at file
//! creation via `OpenOptionsExt::mode` and re-tightened on every open if
//! a previous run left the file with looser perms.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(not(target_family = "wasm"))]
use fs2::FileExt;

use crate::session::event::SessionEvent;

/// Error from event log operations.
#[derive(Debug)]
pub enum EventLogError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl std::fmt::Display for EventLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "event log io: {e}"),
            Self::Json(e) => write!(f, "event log json: {e}"),
        }
    }
}

impl std::error::Error for EventLogError {}
impl From<std::io::Error> for EventLogError {
    fn from(e: std::io::Error) -> Self { Self::Io(e) }
}
impl From<serde_json::Error> for EventLogError {
    fn from(e: serde_json::Error) -> Self { Self::Json(e) }
}

/// An append-only event log backed by a JSONL file.
pub struct EventLog {
    path: PathBuf,
    sequence: AtomicU64,
}

impl EventLog {
    /// Open or create an event log for the given session directory.
    ///
    /// The session directory is typically `.treeship/sessions/<session_id>/`.
    /// If the directory does not exist, it will be created.
    ///
    /// Initialization reads the counter sidecar in O(1) when present and
    /// consistent with events.jsonl's byte size; falls back to an O(N) line
    /// count (and rewrites the sidecar) when the sidecar is missing,
    /// short-read, or stale from a crashed previous appender.
    pub fn open(session_dir: &Path) -> Result<Self, EventLogError> {
        std::fs::create_dir_all(session_dir)?;
        let path = session_dir.join("events.jsonl");
        let count = read_counter_or_recount(&path)?;
        Ok(Self { path, sequence: AtomicU64::new(count) })
    }

    /// Append a single event to the log.
    ///
    /// The event's `sequence_no` is set automatically. Under contention from
    /// multiple writer processes, the sequence number is re-derived from the
    /// on-disk line count under an exclusive flock so two parallel writers
    /// never collide.
    pub fn append(&self, event: &mut SessionEvent) -> Result<(), EventLogError> {
        self.append_locked(event)
    }

    /// Cross-process safe append: acquires an exclusive advisory lock on a
    /// sidecar `.lock` file, re-counts events.jsonl lines, assigns sequence_no,
    /// writes the new event, then releases the lock on drop.
    ///
    /// Lock acquisition is bounded: tries to acquire for up to ~500ms via
    /// `try_lock_exclusive` poll, then falls back to an unlocked append
    /// with a stderr warning. A wedged or crashed writer must NOT hang
    /// hook-driven invocations forever (PostToolUse hooks running per
    /// tool call would freeze the agent). Better to lose strict
    /// sequence_no monotonicity in the rare wedge case than to deadlock.
    ///
    /// Lock file is created mode 0o600 (owner-only) so the sidecar can
    /// never be opened by other users on a shared machine.
    ///
    /// Skipped on WASM (no fs, no concurrency).
    #[cfg(not(target_family = "wasm"))]
    fn append_locked(&self, event: &mut SessionEvent) -> Result<(), EventLogError> {
        use std::time::{Duration, Instant};

        // Sidecar lock file: contention here doesn't block readers of events.jsonl.
        let lock_path = self.path.with_extension("jsonl.lock");

        // Open or create the lock file. On Unix we set 0o600 explicitly so
        // the sidecar isn't group/world readable; the umask-derived default
        // would otherwise be permissive on some setups.
        let lock_file = open_lock_file(&lock_path)?;

        // Bounded retry. With 16 parallel writers the worst case is a
        // queue of N short-held locks; 500ms is plenty. If we fail to
        // acquire in that window something is wedged -- fall through and
        // append without ordering rather than freezing the caller.
        let mut acquired = false;
        let start = Instant::now();
        let deadline = Duration::from_millis(500);
        loop {
            match lock_file.try_lock_exclusive() {
                Ok(()) => {
                    acquired = true;
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if start.elapsed() >= deadline {
                        eprintln!(
                            "[treeship] event_log: lock contention on {} \
                             exceeded {}ms; appending without sequence ordering guarantee",
                            lock_path.display(),
                            deadline.as_millis()
                        );
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(e.into()),
            }
        }

        // Under the lock (or unlocked fallback): read sequence_no from the
        // counter sidecar in O(1) when consistent with events.jsonl size.
        // Stale or missing counters force a one-time O(N) rescan that also
        // rewrites the counter, so subsequent appends return to O(1). Only
        // the on-disk state (counter + size check) is authoritative when
        // multiple processes are appending; the per-process AtomicU64 is a
        // stale hint.
        let count = read_counter_or_recount(&self.path)?;
        event.sequence_no = count;

        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&line)?;
        file.flush()?;

        // Update the counter sidecar with the new count and the new
        // events.jsonl size, so the next append can short-circuit the line
        // scan. Failure to update the counter is non-fatal: the next reader
        // will detect the size mismatch and recount.
        let new_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        let _ = write_counter(&self.path, count + 1, new_size);

        // Keep the in-process AtomicU64 in sync so non-contended callers
        // see the right value via event_count() without re-reading.
        self.sequence.store(count + 1, Ordering::SeqCst);

        // Suppress the unused-variable warning on the unlock-fallback path.
        let _ = acquired;
        // lock_file drops here -> flock released (no-op if we never acquired).
        Ok(())
    }

    /// WASM build: no filesystem locks available, no concurrent writers.
    /// Falls back to the simple AtomicU64 path.
    #[cfg(target_family = "wasm")]
    fn append_locked(&self, event: &mut SessionEvent) -> Result<(), EventLogError> {
        event.sequence_no = self.sequence.fetch_add(1, Ordering::SeqCst);

        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&line)?;
        file.flush()?;

        Ok(())
    }

    /// Read all events from the log.
    ///
    /// Per-line tolerant: a single malformed line (unknown event type,
    /// missing required field, truncated JSON from a crashed writer) is
    /// logged to stderr and skipped, not propagated as an error. The
    /// caller -- session close, in particular -- composes a receipt
    /// from whatever events parse, instead of dropping every event when
    /// any one is bad.
    ///
    /// Why this matters: events.jsonl is append-only and written by
    /// hooks, daemons, SDKs, and bridges from multiple processes. A
    /// single bad event from one buggy emitter would otherwise nuke
    /// the entire receipt's side_effects / agent_graph / timeline.
    /// Real-world repro: a hook that emitted events with an unknown
    /// `type` field caused side_effects.files_written to come back
    /// empty even though the rest of the events in the log were valid
    /// agent.wrote_file events the aggregator would have happily
    /// processed.
    pub fn read_all(&self) -> Result<Vec<SessionEvent>, EventLogError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = std::fs::File::open(&self.path)?;
        let reader = std::io::BufReader::new(file);
        let mut events = Vec::new();
        let mut skipped = 0usize;
        for (idx, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<SessionEvent>(&line) {
                Ok(event) => events.push(event),
                Err(e) => {
                    skipped += 1;
                    eprintln!(
                        "[treeship] event_log: skipping malformed line {} in {}: {}",
                        idx + 1,
                        self.path.display(),
                        e,
                    );
                }
            }
        }
        if skipped > 0 {
            eprintln!(
                "[treeship] event_log: {} malformed line(s) skipped while reading {} (kept {} valid event(s))",
                skipped,
                self.path.display(),
                events.len(),
            );
        }
        Ok(events)
    }

    /// Return the current event count.
    pub fn event_count(&self) -> u64 {
        self.sequence.load(Ordering::SeqCst)
    }

    /// Return the path to the JSONL file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Open the sidecar lock file with owner-only permissions (0o600 on Unix).
///
/// On Unix the mode is set atomically via `OpenOptionsExt::mode` for newly
/// created files. For files that already exist (e.g. left over from a
/// prior crash or an upgrade from a pre-0.9.3 CLI that didn't tighten
/// perms), we additionally re-chmod to 0o600 after open IF the file is
/// owned by the current user. This is best-effort: if the chmod fails
/// (file owned by another user, read-only filesystem, etc.) we proceed
/// silently rather than refuse to open the lock -- the lock semantics
/// don't depend on the perms being tight, only the privacy of the
/// sidecar's existence does.
///
/// On Windows the mode concept doesn't apply; ACLs default to inheriting
/// the parent dir's permissions, which for `.treeship/sessions/<id>/`
/// should already be scoped to the owning user.
#[cfg(all(not(target_family = "wasm"), unix))]
fn open_lock_file(path: &Path) -> Result<std::fs::File, std::io::Error> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::os::unix::io::AsRawFd;

    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)?;

    // Re-tighten if a pre-existing file has loose perms. Use `fchmod` on the
    // open file descriptor rather than `set_permissions(path, ...)` to
    // eliminate the TOCTOU window -- between metadata() and a path-based
    // chmod, an attacker could swap the file. `fchmod` operates on the
    // already-opened inode, so the target is pinned.
    //
    // Only act when the file is owned by us (uid match via geteuid). If
    // fchmod fails (NFS mount with restricted metadata writes, or some
    // filesystems without full POSIX perm support), emit a one-line
    // stderr warning so an operator has visibility. The lock still works;
    // only the privacy of the sidecar's existence is affected.
    if let Ok(meta) = file.metadata() {
        let mode = meta.permissions().mode() & 0o777;
        let owned_by_us = meta.uid() == nix_uid();
        if owned_by_us && mode != 0o600 {
            let fd = file.as_raw_fd();
            // SAFETY: fd is valid (we just opened it), 0o600 is a
            // well-formed mode. fchmod is async-signal-safe per POSIX.
            let rc = unsafe { libc_fchmod(fd, 0o600) };
            if rc != 0 {
                let err = std::io::Error::last_os_error();
                eprintln!(
                    "[treeship] warning: could not tighten lock file perms on {} \
                     to 0o600 (current: 0o{:o}). Error: {}. Lock still functions; \
                     only the privacy of the sidecar is affected. Common cause: \
                     NFS mount or filesystem without full POSIX perm support.",
                    path.display(), mode, err
                );
            }
        }
    }

    Ok(file)
}

/// Thin FFI wrapper around libc::fchmod. Declared here so event_log.rs
/// doesn't need a direct libc crate dep -- the symbol is available in
/// every Unix libc binary.
#[cfg(all(not(target_family = "wasm"), unix))]
fn libc_fchmod(fd: i32, mode: u32) -> i32 {
    // SAFETY: posix-standard FFI signature; `fd` validity and `mode`
    // bounds are enforced by the caller.
    unsafe extern "C" {
        fn fchmod(fd: i32, mode: u32) -> i32;
    }
    unsafe { fchmod(fd, mode) }
}

/// Lightweight wrapper around `geteuid` so we can compare to file ownership
/// without pulling in the `nix` crate. Uses `libc` directly (already a
/// transitive dep via several upstream crates).
#[cfg(all(not(target_family = "wasm"), unix))]
fn nix_uid() -> u32 {
    // SAFETY: geteuid is async-signal-safe and never fails per POSIX.
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg(all(not(target_family = "wasm"), not(unix)))]
fn open_lock_file(path: &Path) -> Result<std::fs::File, std::io::Error> {
    std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(path)
}

/// Path of the counter sidecar for a given events.jsonl path.
fn counter_path(events_path: &Path) -> PathBuf {
    events_path.with_extension("jsonl.count")
}

/// Read the counter sidecar if it exists and is consistent with events.jsonl.
///
/// Returns `Some(count)` when the sidecar's recorded byte_size matches the
/// current events.jsonl size, and `None` otherwise (missing sidecar, short
/// read, parse failure, or size mismatch from a crashed previous appender).
#[cfg(not(target_family = "wasm"))]
fn read_counter_consistent(events_path: &Path) -> Option<u64> {
    let counter = counter_path(events_path);
    let bytes = std::fs::read(&counter).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let count = u64::from_le_bytes(bytes[0..8].try_into().ok()?);
    let recorded_size = u64::from_le_bytes(bytes[8..16].try_into().ok()?);

    // events.jsonl may not exist yet -- counter records (0, 0) for that case.
    let actual_size = match std::fs::metadata(events_path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(_) => return None,
    };
    if actual_size != recorded_size {
        return None;
    }
    Some(count)
}

/// Read the counter via the sidecar (O(1)) or fall back to an O(N) line
/// scan, rewriting the sidecar on the way out. This is the recovery path
/// after a crash that left the counter and events.jsonl out of sync.
#[cfg(not(target_family = "wasm"))]
fn read_counter_or_recount(events_path: &Path) -> Result<u64, EventLogError> {
    if let Some(count) = read_counter_consistent(events_path) {
        return Ok(count);
    }
    let count = if events_path.exists() {
        let f = std::fs::File::open(events_path)?;
        let r = std::io::BufReader::new(f);
        r.lines().filter(|l| l.is_ok()).count() as u64
    } else {
        0
    };
    let size = std::fs::metadata(events_path).map(|m| m.len()).unwrap_or(0);
    let _ = write_counter(events_path, count, size);
    Ok(count)
}

/// WASM has no fs and no concurrent writers; the in-memory AtomicU64 in the
/// EventLog is sufficient. Initialize to zero on open.
#[cfg(target_family = "wasm")]
fn read_counter_or_recount(_events_path: &Path) -> Result<u64, EventLogError> {
    Ok(0)
}

/// Atomically replace the counter sidecar with the new (count, byte_size).
///
/// Writes to a temp file in the same directory and renames into place so a
/// reader either sees the old 16 bytes or the new 16 bytes, never a partial
/// write. The 0o600 perm matches the lock file -- the counter doesn't leak
/// secrets but its existence is a session signal worth scoping to the owner.
#[cfg(not(target_family = "wasm"))]
fn write_counter(events_path: &Path, count: u64, byte_size: u64) -> Result<(), std::io::Error> {
    use std::io::Write as _;
    let counter = counter_path(events_path);
    let dir = counter.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "counter path has no parent")
    })?;
    std::fs::create_dir_all(dir)?;

    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&count.to_le_bytes());
    buf[8..16].copy_from_slice(&byte_size.to_le_bytes());

    let tmp = counter.with_extension("count.tmp");
    {
        let mut f = open_counter_tmp(&tmp)?;
        f.write_all(&buf)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &counter)?;
    Ok(())
}

#[cfg(all(not(target_family = "wasm"), unix))]
fn open_counter_tmp(path: &Path) -> Result<std::fs::File, std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
}

#[cfg(all(not(target_family = "wasm"), not(unix)))]
fn open_counter_tmp(path: &Path) -> Result<std::fs::File, std::io::Error> {
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::event::*;

    fn make_event(session_id: &str, event_type: EventType) -> SessionEvent {
        SessionEvent {
            session_id: session_id.into(),
            event_id: generate_event_id(),
            timestamp: "2026-04-05T08:00:00Z".into(),
            sequence_no: 0,
            trace_id: generate_trace_id(),
            span_id: generate_span_id(),
            parent_span_id: None,
            agent_id: "agent://test".into(),
            agent_instance_id: "ai_test_1".into(),
            agent_name: "test-agent".into(),
            agent_role: None,
            host_id: "host_test".into(),
            tool_runtime_id: None,
            event_type,
            artifact_ref: None,
            meta: None,
        }
    }

    #[test]
    fn append_and_read_back() {
        let dir = std::env::temp_dir().join(format!("treeship-evtlog-test-{}", rand::random::<u32>()));
        let log = EventLog::open(&dir).unwrap();

        let mut e1 = make_event("ssn_001", EventType::SessionStarted);
        let mut e2 = make_event("ssn_001", EventType::AgentStarted {
            parent_agent_instance_id: None,
        });

        log.append(&mut e1).unwrap();
        log.append(&mut e2).unwrap();

        assert_eq!(log.event_count(), 2);
        assert_eq!(e1.sequence_no, 0);
        assert_eq!(e2.sequence_no, 1);

        let events = log.read_all().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence_no, 0);
        assert_eq!(events[1].sequence_no, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_all_skips_malformed_lines() {
        // Regression: a single malformed line in events.jsonl used to
        // make read_all() return Err, and the caller's
        // .unwrap_or_default() would drop EVERY event in the log. Real
        // bug: hooks emitting events with an unknown `type` field made
        // side_effects.files_written come back empty even though every
        // other event in the log was a perfectly valid agent.wrote_file
        // event. Now we skip-and-log the bad line and keep the rest.
        let dir = std::env::temp_dir().join(format!("treeship-evtlog-malformed-{}", rand::random::<u32>()));
        let log = EventLog::open(&dir).unwrap();

        let mut good1 = make_event(
            "ssn_001",
            EventType::AgentWroteFile {
                file_path: "src/before.rs".into(),
                digest: None,
                operation: None,
                additions: None,
                deletions: None,
            },
        );
        let mut good2 = make_event(
            "ssn_001",
            EventType::AgentWroteFile {
                file_path: "src/after.rs".into(),
                digest: None,
                operation: None,
                additions: None,
                deletions: None,
            },
        );
        log.append(&mut good1).unwrap();
        log.append(&mut good2).unwrap();

        // Manually inject a malformed line between the two good ones by
        // truncating the file and rewriting. The malformed line has an
        // unknown event type ("custom.weird") which the closed EventType
        // enum can't deserialize.
        let path = log.path().to_path_buf();
        let original = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = original.lines().collect();
        lines.insert(1, r#"{"session_id":"ssn_001","event_id":"evt_bad","timestamp":"2026-04-26T00:00:00Z","sequence_no":1,"trace_id":"x","span_id":"y","agent_id":"a","agent_instance_id":"i","agent_name":"n","host_id":"h","type":"custom.weird","payload":42}"#);
        std::fs::write(&path, lines.join("\n") + "\n").unwrap();

        let events = log.read_all().unwrap();
        assert_eq!(events.len(), 2, "expected the two valid events to come through; got {}", events.len());
        // Confirm the valid events are the file-write events and not
        // some default fallback.
        let written_paths: Vec<&str> = events
            .iter()
            .filter_map(|e| match &e.event_type {
                EventType::AgentWroteFile { file_path, .. } => Some(file_path.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(written_paths, vec!["src/before.rs", "src/after.rs"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reopen_preserves_sequence() {
        let dir = std::env::temp_dir().join(format!("treeship-evtlog-reopen-{}", rand::random::<u32>()));

        {
            let log = EventLog::open(&dir).unwrap();
            let mut e = make_event("ssn_001", EventType::SessionStarted);
            log.append(&mut e).unwrap();
        }

        // Reopen
        let log = EventLog::open(&dir).unwrap();
        assert_eq!(log.event_count(), 1);

        let mut e2 = make_event("ssn_001", EventType::AgentStarted {
            parent_agent_instance_id: None,
        });
        log.append(&mut e2).unwrap();
        assert_eq!(e2.sequence_no, 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression test for #1 in the v0.9.3 Codex adversarial review.
    ///
    /// Multiple `EventLog` instances opened against the same directory must
    /// not collide on `sequence_no`. This simulates what happens when each
    /// `treeship session event` invocation (one per PostToolUse hook firing)
    /// creates a fresh `EventLog` on a shared events.jsonl. Without the
    /// flock-based re-derivation in `append_locked`, every instance sees
    /// the same on-disk count at open time and assigns duplicate sequence
    /// numbers.
    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn concurrent_appends_have_unique_sequence_numbers() {
        use std::sync::Arc;
        use std::thread;

        let dir = std::env::temp_dir()
            .join(format!("treeship-evtlog-race-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();

        const WRITERS: usize = 16;
        let dir = Arc::new(dir);
        let mut handles = Vec::with_capacity(WRITERS);

        for _ in 0..WRITERS {
            let dir = Arc::clone(&dir);
            handles.push(thread::spawn(move || {
                // Each thread opens its OWN EventLog -- mimics a separate
                // process invocation. Without flock, all threads would see
                // the same line count at open() time.
                let log = EventLog::open(&dir).unwrap();
                let mut e = make_event("ssn_race", EventType::SessionStarted);
                log.append(&mut e).unwrap();
                e.sequence_no
            }));
        }

        let mut seqs: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        seqs.sort();

        // All sequence numbers must be unique and contiguous 0..WRITERS.
        let expected: Vec<u64> = (0..WRITERS as u64).collect();
        assert_eq!(seqs, expected, "sequence_no collisions under contention");

        // Same invariant from the on-disk file's perspective.
        let log = EventLog::open(&dir).unwrap();
        let read = log.read_all().unwrap();
        assert_eq!(read.len(), WRITERS);
        let mut on_disk: Vec<u64> = read.iter().map(|e| e.sequence_no).collect();
        on_disk.sort();
        assert_eq!(on_disk, expected);

        let _ = std::fs::remove_dir_all(&*dir);
    }

    /// Sidecar lock file must be created mode 0o600 (owner-only) on Unix.
    /// Regression test for #5 in the second Codex adversarial review.
    #[cfg(all(not(target_family = "wasm"), unix))]
    #[test]
    fn lock_file_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir()
            .join(format!("treeship-evtlog-perms-{}", rand::random::<u32>()));
        let log = EventLog::open(&dir).unwrap();

        let mut e = make_event("ssn_perms", EventType::SessionStarted);
        log.append(&mut e).unwrap();

        let lock_path = log.path().with_extension("jsonl.lock");
        let meta = std::fs::metadata(&lock_path).expect("lock file must exist after first append");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "lock file mode is {:o}, expected 0o600 (owner-only)",
            mode
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pre-existing lock file (e.g. from a v0.9.2 era crash) with looser
    /// permissions must be tightened to 0o600 on next `EventLog::open`.
    /// Regression test for the third Codex adversarial review.
    #[cfg(all(not(target_family = "wasm"), unix))]
    #[test]
    fn existing_lock_file_is_re_tightened() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir()
            .join(format!("treeship-evtlog-retighten-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();

        // Pre-create a lock file with deliberately loose perms, simulating
        // an upgrade from a CLI version that didn't set 0o600.
        let lock_path = dir.join("events.jsonl.lock");
        std::fs::write(&lock_path, b"").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let pre_mode = std::fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(pre_mode, 0o644, "test setup: pre-existing perms should be 0o644");

        // First append after upgrade -- should re-tighten.
        let log = EventLog::open(&dir).unwrap();
        let mut e = make_event("ssn_retighten", EventType::SessionStarted);
        log.append(&mut e).unwrap();

        let post_mode = std::fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            post_mode, 0o600,
            "lock file should be re-tightened to 0o600 after open; got {:o}",
            post_mode
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Counter sidecar must exist after the first append and contain
    /// (count=1, byte_size=size of events.jsonl). This is the happy path
    /// that lets every subsequent append skip the O(N) rescan.
    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn counter_sidecar_written_after_append() {
        let dir = std::env::temp_dir()
            .join(format!("treeship-evtlog-counter-{}", rand::random::<u32>()));
        let log = EventLog::open(&dir).unwrap();

        let mut e = make_event("ssn_counter", EventType::SessionStarted);
        log.append(&mut e).unwrap();

        let counter = log.path().with_extension("jsonl.count");
        let bytes = std::fs::read(&counter).expect("counter sidecar must exist after append");
        assert_eq!(bytes.len(), 16, "counter sidecar must be 16 bytes");

        let count = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let recorded_size = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let actual_size = std::fs::metadata(log.path()).unwrap().len();
        assert_eq!(count, 1, "counter must reflect the one appended event");
        assert_eq!(
            recorded_size, actual_size,
            "counter byte_size ({}) must match events.jsonl size ({})",
            recorded_size, actual_size
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A missing counter sidecar (fresh install, deleted by user, etc.)
    /// must not break sequence_no assignment. The next append falls back
    /// to an O(N) recount and rewrites the counter.
    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn counter_sidecar_recovers_when_missing() {
        let dir = std::env::temp_dir()
            .join(format!("treeship-evtlog-missing-counter-{}", rand::random::<u32>()));

        // Append two events, then nuke the counter sidecar.
        {
            let log = EventLog::open(&dir).unwrap();
            let mut e1 = make_event("ssn_x", EventType::SessionStarted);
            let mut e2 = make_event("ssn_x", EventType::AgentStarted {
                parent_agent_instance_id: None,
            });
            log.append(&mut e1).unwrap();
            log.append(&mut e2).unwrap();
        }
        let counter = dir.join("events.jsonl.count");
        std::fs::remove_file(&counter).expect("counter must exist before deletion");

        // Reopen + append. The third event must get sequence_no=2 even
        // though the counter sidecar is gone.
        let log = EventLog::open(&dir).unwrap();
        assert_eq!(log.event_count(), 2, "open() must recount when counter is missing");

        let mut e3 = make_event("ssn_x", EventType::SessionClosed {
            summary: None,
            duration_ms: None,
        });
        log.append(&mut e3).unwrap();
        assert_eq!(e3.sequence_no, 2);
        assert!(counter.exists(), "counter must be rewritten after recount");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A short-read or garbage counter sidecar (corrupted, partial write,
    /// truncated by external tool) must not be trusted. The size mismatch
    /// path covers the "wrong content" case for a 16-byte file too.
    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn counter_sidecar_recovers_when_corrupt() {
        let dir = std::env::temp_dir()
            .join(format!("treeship-evtlog-corrupt-counter-{}", rand::random::<u32>()));

        {
            let log = EventLog::open(&dir).unwrap();
            let mut e = make_event("ssn_corrupt", EventType::SessionStarted);
            log.append(&mut e).unwrap();
        }
        // Truncate the counter to a non-16 length.
        let counter = dir.join("events.jsonl.count");
        std::fs::write(&counter, b"junk").unwrap();

        let log = EventLog::open(&dir).unwrap();
        assert_eq!(log.event_count(), 1, "short-read counter must be ignored, recount kicks in");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A counter that recorded the wrong byte_size (someone or something
    /// appended to events.jsonl behind our back) must not be trusted.
    /// This is the crash-recovery path: peer wrote events.jsonl but
    /// crashed before fsyncing the counter, so the recorded size is stale.
    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn counter_sidecar_recovers_when_size_disagrees() {
        let dir = std::env::temp_dir()
            .join(format!("treeship-evtlog-stale-counter-{}", rand::random::<u32>()));

        {
            let log = EventLog::open(&dir).unwrap();
            let mut e = make_event("ssn_stale", EventType::SessionStarted);
            log.append(&mut e).unwrap();
        }

        // Simulate a crash mid-append: append one extra raw line to
        // events.jsonl WITHOUT updating the counter. Now the counter
        // says (1, S) but events.jsonl is (S + |line|) bytes.
        let events_path = dir.join("events.jsonl");
        let mut extra = make_event("ssn_stale", EventType::AgentStarted {
            parent_agent_instance_id: None,
        });
        extra.sequence_no = 999; // intentionally wrong; will be overwritten on read
        let mut line = serde_json::to_vec(&extra).unwrap();
        line.push(b'\n');
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&events_path)
            .unwrap();
        std::io::Write::write_all(&mut f, &line).unwrap();
        std::io::Write::flush(&mut f).unwrap();

        // Re-open. The size mismatch must trigger a recount; we should see 2.
        let log = EventLog::open(&dir).unwrap();
        assert_eq!(
            log.event_count(),
            2,
            "size mismatch must force recount, ignoring stale counter"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The counter sidecar fix must not break the cross-process race
    /// safety established by the flock layer. This is the same shape as
    /// `concurrent_appends_have_unique_sequence_numbers` but exists to
    /// guard against a regression where the counter is read OUTSIDE the
    /// lock, which would let two writers both see count=N and assign N
    /// to two different events.
    #[cfg(not(target_family = "wasm"))]
    #[test]
    fn counter_sidecar_preserves_concurrent_uniqueness() {
        use std::sync::Arc;
        use std::thread;

        let dir = std::env::temp_dir()
            .join(format!("treeship-evtlog-counter-race-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&dir).unwrap();

        const WRITERS: usize = 16;
        let dir = Arc::new(dir);
        let mut handles = Vec::with_capacity(WRITERS);

        for _ in 0..WRITERS {
            let dir = Arc::clone(&dir);
            handles.push(thread::spawn(move || {
                let log = EventLog::open(&dir).unwrap();
                let mut e = make_event("ssn_counter_race", EventType::SessionStarted);
                log.append(&mut e).unwrap();
                e.sequence_no
            }));
        }

        let mut seqs: Vec<u64> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        seqs.sort();
        let expected: Vec<u64> = (0..WRITERS as u64).collect();
        assert_eq!(seqs, expected, "counter must not bypass the flock race protection");

        // Counter should reflect the final state.
        let log = EventLog::open(&dir).unwrap();
        assert_eq!(log.event_count(), WRITERS as u64);

        let _ = std::fs::remove_dir_all(&*dir);
    }

    /// Counter sidecar must be created mode 0o600 (owner-only) on Unix --
    /// same scoping as the lock file; the existence of a counter is a
    /// session signal that doesn't need to leak to other users.
    #[cfg(all(not(target_family = "wasm"), unix))]
    #[test]
    fn counter_sidecar_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir()
            .join(format!("treeship-evtlog-counter-perms-{}", rand::random::<u32>()));
        let log = EventLog::open(&dir).unwrap();

        let mut e = make_event("ssn_counter_perms", EventType::SessionStarted);
        log.append(&mut e).unwrap();

        let counter = log.path().with_extension("jsonl.count");
        let mode = std::fs::metadata(&counter).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "counter sidecar mode is {:o}, expected 0o600 (owner-only)",
            mode
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
