//! Session event model for Session Receipt v1.
//!
//! Events are the raw building blocks of a session. They are emitted by
//! SDKs, CLI wrappers, and daemons, then composed into the receipt.

use serde::{Deserialize, Serialize};

/// All supported session event types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventType {
    #[serde(rename = "session.started")]
    SessionStarted,

    #[serde(rename = "session.closed")]
    SessionClosed {
        #[serde(skip_serializing_if = "Option::is_none")]
        summary: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
    },

    #[serde(rename = "agent.started")]
    AgentStarted {
        #[serde(skip_serializing_if = "Option::is_none")]
        parent_agent_instance_id: Option<String>,
    },

    #[serde(rename = "agent.spawned")]
    AgentSpawned {
        spawned_by_agent_instance_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },

    #[serde(rename = "agent.handoff")]
    AgentHandoff {
        from_agent_instance_id: String,
        to_agent_instance_id: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        artifacts: Vec<String>,
    },

    #[serde(rename = "agent.collaborated")]
    AgentCollaborated {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        collaborator_agent_instance_ids: Vec<String>,
    },

    #[serde(rename = "agent.returned")]
    AgentReturned {
        returned_to_agent_instance_id: String,
    },

    #[serde(rename = "agent.completed")]
    AgentCompleted {
        #[serde(skip_serializing_if = "Option::is_none")]
        termination_reason: Option<String>,
    },

    #[serde(rename = "agent.failed")]
    AgentFailed {
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },

    #[serde(rename = "agent.called_tool")]
    AgentCalledTool {
        tool_name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        tool_input_digest: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tool_output_digest: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
    },

    #[serde(rename = "agent.read_file")]
    AgentReadFile {
        file_path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        digest: Option<String>,
    },

    #[serde(rename = "agent.wrote_file")]
    AgentWroteFile {
        file_path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        digest: Option<String>,
        /// "created", "modified", or "deleted". Absent in legacy events.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        additions: Option<u32>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        deletions: Option<u32>,
    },

    #[serde(rename = "agent.opened_port")]
    AgentOpenedPort {
        port: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        protocol: Option<String>,
    },

    #[serde(rename = "agent.connected_network")]
    AgentConnectedNetwork {
        destination: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        port: Option<u16>,
    },

    #[serde(rename = "agent.started_process")]
    AgentStartedProcess {
        process_name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pid: Option<u32>,
        /// Full command string (e.g. "npm test --runInBand"). Absent in legacy events.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command: Option<String>,
    },

    #[serde(rename = "agent.completed_process")]
    AgentCompletedProcess {
        process_name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        exit_code: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        command: Option<String>,
    },

    /// LLM inference decision with model and token usage.
    ///
    // Cost is deliberately not captured. Pricing depends on provider,
    // subscription tier, contract rates, and timing. Baking a dollar
    // amount into a signed receipt would make old receipts falsely
    // signed when pricing changes. Consumers (dashboards, billing tools)
    // calculate cost from model + tokens + their pricing config.
    #[serde(rename = "agent.decision")]
    AgentDecision {
        #[serde(skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tokens_in: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tokens_out: Option<u64>,
        /// Provider e.g. "anthropic", "openrouter", "bedrock", "openai"
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        summary: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        confidence: Option<f64>,
    },
}

/// A single session event with full context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEvent {
    pub session_id: String,
    pub event_id: String,
    pub timestamp: String,
    pub sequence_no: u64,
    pub trace_id: String,
    pub span_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    pub agent_id: String,
    pub agent_instance_id: String,
    pub agent_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_role: Option<String>,
    pub host_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_runtime_id: Option<String>,
    #[serde(flatten)]
    pub event_type: EventType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

/// Generate a random event ID: `evt_<16 hex chars>`.
pub fn generate_event_id() -> String {
    let mut buf = [0u8; 8];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut buf);
    format!("evt_{}", hex::encode(buf))
}

/// Generate a random span ID: 16 hex chars (8 bytes, W3C compatible).
pub fn generate_span_id() -> String {
    let mut buf = [0u8; 8];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Generate a random trace ID: 32 hex chars (16 bytes, W3C compatible).
pub fn generate_trace_id() -> String {
    let mut buf = [0u8; 16];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_serialization() {
        let evt = EventType::AgentCalledTool {
            tool_name: "read_file".into(),
            tool_input_digest: None,
            tool_output_digest: None,
            duration_ms: Some(42),
        };
        let json = serde_json::to_string(&evt).unwrap();
        assert!(json.contains("agent.called_tool"));
        assert!(json.contains("read_file"));

        let back: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(back, evt);
    }

    #[test]
    fn full_event_roundtrip() {
        let event = SessionEvent {
            session_id: "ssn_001".into(),
            event_id: generate_event_id(),
            timestamp: "2026-04-05T08:00:00Z".into(),
            sequence_no: 1,
            trace_id: generate_trace_id(),
            span_id: generate_span_id(),
            parent_span_id: None,
            agent_id: "agent://claude-code".into(),
            agent_instance_id: "ai_cc_1".into(),
            agent_name: "claude-code".into(),
            agent_role: Some("planner".into()),
            host_id: "host_macbook".into(),
            tool_runtime_id: Some("rt_cc_1".into()),
            event_type: EventType::AgentStarted {
                parent_agent_instance_id: None,
            },
            artifact_ref: None,
            meta: None,
        };

        let json = serde_json::to_string_pretty(&event).unwrap();
        let back: SessionEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.session_id, "ssn_001");
        assert_eq!(back.agent_name, "claude-code");
    }

    #[test]
    fn id_generation() {
        let eid = generate_event_id();
        assert!(eid.starts_with("evt_"));
        assert_eq!(eid.len(), 4 + 16); // "evt_" + 16 hex

        let sid = generate_span_id();
        assert_eq!(sid.len(), 16);

        let tid = generate_trace_id();
        assert_eq!(tid.len(), 32);
    }
}
