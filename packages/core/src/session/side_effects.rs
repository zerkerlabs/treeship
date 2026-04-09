//! Side-effect aggregation from session events.
//!
//! Groups file, network, port, and process side effects for the
//! side-effect ledger in the Session Report.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::event::{EventType, SessionEvent};

/// A file access event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccess {
    pub file_path: String,
    pub agent_instance_id: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

/// A port opened by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAccess {
    pub port: u16,
    pub agent_instance_id: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// A network connection made by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub agent_instance_id: String,
    pub timestamp: String,
}

/// A process execution by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExecution {
    pub process_name: String,
    pub agent_instance_id: String,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// A tool invocation by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocation {
    pub tool_name: String,
    pub agent_instance_id: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Aggregated side effects from a session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SideEffects {
    pub files_read: Vec<FileAccess>,
    pub files_written: Vec<FileAccess>,
    pub ports_opened: Vec<PortAccess>,
    pub network_connections: Vec<NetworkConnection>,
    pub processes: Vec<ProcessExecution>,
    pub tool_invocations: Vec<ToolInvocation>,
}

impl SideEffects {
    /// Build side effects from a sequence of session events.
    pub fn from_events(events: &[SessionEvent]) -> Self {
        let mut se = SideEffects::default();

        // Track started processes so we can match with completed events.
        // Key: (agent_instance_id, process_name)
        let mut started_processes: BTreeMap<(String, String), usize> = BTreeMap::new();

        for event in events {
            match &event.event_type {
                EventType::AgentReadFile { file_path, digest } => {
                    se.files_read.push(FileAccess {
                        file_path: file_path.clone(),
                        agent_instance_id: event.agent_instance_id.clone(),
                        timestamp: event.timestamp.clone(),
                        digest: digest.clone(),
                    });
                }

                EventType::AgentWroteFile { file_path, digest } => {
                    se.files_written.push(FileAccess {
                        file_path: file_path.clone(),
                        agent_instance_id: event.agent_instance_id.clone(),
                        timestamp: event.timestamp.clone(),
                        digest: digest.clone(),
                    });
                }

                EventType::AgentOpenedPort { port, protocol } => {
                    se.ports_opened.push(PortAccess {
                        port: *port,
                        agent_instance_id: event.agent_instance_id.clone(),
                        timestamp: event.timestamp.clone(),
                        protocol: protocol.clone(),
                    });
                }

                EventType::AgentConnectedNetwork { destination, port } => {
                    se.network_connections.push(NetworkConnection {
                        destination: destination.clone(),
                        port: *port,
                        agent_instance_id: event.agent_instance_id.clone(),
                        timestamp: event.timestamp.clone(),
                    });
                }

                EventType::AgentStartedProcess { process_name, pid: _ } => {
                    let idx = se.processes.len();
                    se.processes.push(ProcessExecution {
                        process_name: process_name.clone(),
                        agent_instance_id: event.agent_instance_id.clone(),
                        started_at: event.timestamp.clone(),
                        exit_code: None,
                        duration_ms: None,
                    });
                    started_processes.insert(
                        (event.agent_instance_id.clone(), process_name.clone()),
                        idx,
                    );
                }

                EventType::AgentCompletedProcess { process_name, exit_code, duration_ms } => {
                    let key = (event.agent_instance_id.clone(), process_name.clone());
                    if let Some(&idx) = started_processes.get(&key) {
                        if let Some(proc) = se.processes.get_mut(idx) {
                            proc.exit_code = *exit_code;
                            proc.duration_ms = *duration_ms;
                        }
                    } else {
                        // Completed without a started event (e.g., joined mid-session)
                        se.processes.push(ProcessExecution {
                            process_name: process_name.clone(),
                            agent_instance_id: event.agent_instance_id.clone(),
                            started_at: event.timestamp.clone(),
                            exit_code: *exit_code,
                            duration_ms: *duration_ms,
                        });
                    }
                }

                EventType::AgentCalledTool { tool_name, duration_ms, .. } => {
                    se.tool_invocations.push(ToolInvocation {
                        tool_name: tool_name.clone(),
                        agent_instance_id: event.agent_instance_id.clone(),
                        timestamp: event.timestamp.clone(),
                        duration_ms: *duration_ms,
                    });
                }

                _ => {}
            }
        }

        se
    }

    /// Summary counts for display.
    pub fn summary(&self) -> SideEffectSummary {
        SideEffectSummary {
            files_read: self.files_read.len() as u32,
            files_written: self.files_written.len() as u32,
            ports_opened: self.ports_opened.len() as u32,
            network_connections: self.network_connections.len() as u32,
            processes: self.processes.len() as u32,
            tool_invocations: self.tool_invocations.len() as u32,
        }
    }
}

/// Summary counts of side effects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideEffectSummary {
    pub files_read: u32,
    pub files_written: u32,
    pub ports_opened: u32,
    pub network_connections: u32,
    pub processes: u32,
    pub tool_invocations: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::event::*;

    fn evt(event_type: EventType) -> SessionEvent {
        SessionEvent {
            session_id: "ssn_001".into(),
            event_id: generate_event_id(),
            timestamp: "2026-04-05T08:00:00Z".into(),
            sequence_no: 0,
            trace_id: "t".into(),
            span_id: "s".into(),
            parent_span_id: None,
            agent_id: "agent://test".into(),
            agent_instance_id: "ai_1".into(),
            agent_name: "test".into(),
            agent_role: None,
            host_id: "h".into(),
            tool_runtime_id: None,
            event_type,
            artifact_ref: None,
            meta: None,
        }
    }

    #[test]
    fn aggregates_file_and_tool_events() {
        let events = vec![
            evt(EventType::AgentReadFile { file_path: "src/main.rs".into(), digest: None }),
            evt(EventType::AgentWroteFile { file_path: "src/lib.rs".into(), digest: Some("sha256:abc".into()) }),
            evt(EventType::AgentCalledTool { tool_name: "read_file".into(), tool_input_digest: None, tool_output_digest: None, duration_ms: Some(10) }),
            evt(EventType::AgentCalledTool { tool_name: "write_file".into(), tool_input_digest: None, tool_output_digest: None, duration_ms: None }),
        ];

        let se = SideEffects::from_events(&events);
        assert_eq!(se.files_read.len(), 1);
        assert_eq!(se.files_written.len(), 1);
        assert_eq!(se.tool_invocations.len(), 2);
        let summary = se.summary();
        assert_eq!(summary.tool_invocations, 2);
    }

    #[test]
    fn matches_process_start_and_complete() {
        let events = vec![
            evt(EventType::AgentStartedProcess { process_name: "npm test".into(), pid: Some(1234) }),
            evt(EventType::AgentCompletedProcess { process_name: "npm test".into(), exit_code: Some(0), duration_ms: Some(5000) }),
        ];

        let se = SideEffects::from_events(&events);
        assert_eq!(se.processes.len(), 1);
        assert_eq!(se.processes[0].exit_code, Some(0));
        assert_eq!(se.processes[0].duration_ms, Some(5000));
    }
}
