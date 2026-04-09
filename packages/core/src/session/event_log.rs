//! Append-only, file-backed event log for session events.
//!
//! Events are stored as newline-delimited JSON (JSONL) in
//! `.treeship/sessions/<session_id>/events.jsonl`.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

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
    /// The event's `sequence_no` is set automatically based on the log position.
    pub fn append(&self, event: &mut SessionEvent) -> Result<(), EventLogError> {
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
}
