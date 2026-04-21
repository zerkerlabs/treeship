//! Append-only, file-backed event log for session events.
//!
//! Events are stored as newline-delimited JSON (JSONL) in
//! `.treeship/sessions/<session_id>/events.jsonl`.
//!
//! Concurrency model: `append()` is safe to call from multiple processes
//! concurrently. Each call acquires an exclusive advisory lock (via
//! `fs2::FileExt::lock_exclusive` -- backed by `flock(2)` on Unix and
//! `LockFileEx` on Windows) on a sidecar `events.jsonl.lock` file, then
//! re-counts the JSONL lines under the lock to derive `sequence_no`. This
//! makes sequence numbers monotonic and unique even when several
//! `treeship session event` processes race (e.g. parallel PostToolUse hook
//! invocations from a Claude Code plugin). The per-process AtomicU64 is
//! retained as a hot-path optimization for non-contended single-process
//! use, but the on-disk count is always authoritative.

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
    pub fn open(session_dir: &Path) -> Result<Self, EventLogError> {
        std::fs::create_dir_all(session_dir)?;
        let path = session_dir.join("events.jsonl");

        // Count existing events to initialize the sequence counter.
        let sequence = if path.exists() {
            let file = std::fs::File::open(&path)?;
            let reader = std::io::BufReader::new(file);
            let count = reader.lines().filter(|l| l.is_ok()).count() as u64;
            AtomicU64::new(count)
        } else {
            AtomicU64::new(0)
        };

        Ok(Self { path, sequence })
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

        // Under the lock (or unlocked fallback): re-derive sequence_no
        // from the actual on-disk line count. The per-process AtomicU64
        // is a stale hint -- only the on-disk count is authoritative
        // when multiple processes are appending.
        let count = if self.path.exists() {
            let f = std::fs::File::open(&self.path)?;
            let r = std::io::BufReader::new(f);
            r.lines().filter(|l| l.is_ok()).count() as u64
        } else {
            0
        };
        event.sequence_no = count;

        let mut line = serde_json::to_vec(event)?;
        line.push(b'\n');

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&line)?;
        file.flush()?;

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
    pub fn read_all(&self) -> Result<Vec<SessionEvent>, EventLogError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        let file = std::fs::File::open(&self.path)?;
        let reader = std::io::BufReader::new(file);
        let mut events = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let event: SessionEvent = serde_json::from_str(&line)?;
            events.push(event);
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
/// On Unix the mode is set atomically via `OpenOptionsExt::mode` so the
/// file can never exist on disk with a more permissive mode (a separate
/// `set_permissions` call after create would race). On Windows the mode
/// concept doesn't apply; ACLs default to inheriting the parent dir's
/// permissions, which for `.treeship/sessions/<id>/` should already be
/// scoped to the owning user.
///
/// If the file already exists, `OpenOptionsExt::mode` is a no-op (the
/// file is opened with its existing permissions). That's correct -- a
/// pre-existing lock file from a prior crash is reused as-is, and we
/// have no business widening or narrowing whatever the OS or admin set.
#[cfg(all(not(target_family = "wasm"), unix))]
fn open_lock_file(path: &Path) -> Result<std::fs::File, std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)
}

#[cfg(all(not(target_family = "wasm"), not(unix)))]
fn open_lock_file(path: &Path) -> Result<std::fs::File, std::io::Error> {
    std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
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
}
