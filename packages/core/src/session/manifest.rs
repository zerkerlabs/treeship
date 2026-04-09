//! Enhanced session manifest for Session Receipt v1.

use serde::{Deserialize, Serialize};

/// Session lifecycle mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleMode {
    /// User explicitly starts and ends the session.
    Manual,
    /// Auto-starts when registered agents begin activity in a watched workspace.
    AutoWorkspace,
    /// Day-level session with optional mission segments.
    DailyRollup,
}

impl Default for LifecycleMode {
    fn default() -> Self {
        Self::AutoWorkspace
    }
}

/// Summary of all participants in a session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Participants {
    /// Instance ID of the root agent that initiated the session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_agent_instance_id: Option<String>,

    /// Instance ID of the agent that produced the final output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub final_output_agent_instance_id: Option<String>,

    /// Total number of distinct agents involved.
    #[serde(default)]
    pub total_agents: u32,

    /// Number of sub-agents spawned during the session.
    #[serde(default)]
    pub spawned_subagents: u32,

    /// Total number of handoffs between agents.
    #[serde(default)]
    pub handoffs: u32,

    /// Deepest agent delegation chain depth.
    #[serde(default)]
    pub max_depth: u32,

    /// Number of distinct hosts involved.
    #[serde(default)]
    pub hosts: u32,

    /// Number of distinct tool runtimes involved.
    #[serde(default)]
    pub tool_runtimes: u32,
}

/// Information about a host involved in the session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    pub host_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
}

/// Information about a tool runtime involved in the session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    pub tool_id: String,
    pub tool_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_runtime_id: Option<String>,
    #[serde(default)]
    pub invocation_count: u32,
}

/// Session status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Completed,
    Failed,
    Abandoned,
}

impl Default for SessionStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Enhanced session manifest for Session Receipt v1.
///
/// Backward-compatible with the original CLI SessionManifest:
/// all new fields use `#[serde(default)]` so old session.json files
/// deserialize without error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionManifest {
    pub session_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    pub actor: String,

    pub started_at: String,

    #[serde(default)]
    pub started_at_ms: u64,

    #[serde(default)]
    pub artifact_count: u64,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_artifact_id: Option<String>,

    // --- v1 fields below ---

    #[serde(default)]
    pub mode: LifecycleMode,

    #[serde(default)]
    pub status: SessionStatus,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub mission_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_artifact_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    #[serde(default)]
    pub participants: Participants,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<HostInfo>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolInfo>,
}

impl SessionManifest {
    /// Create a new manifest with required fields; v1 fields default.
    pub fn new(session_id: String, actor: String, started_at: String, started_at_ms: u64) -> Self {
        Self {
            session_id,
            name: None,
            actor,
            started_at,
            started_at_ms,
            artifact_count: 0,
            root_artifact_id: None,
            mode: LifecycleMode::default(),
            status: SessionStatus::Active,
            workspace_id: None,
            mission_id: None,
            closed_at: None,
            close_artifact_id: None,
            summary: None,
            participants: Participants::default(),
            hosts: Vec::new(),
            tools: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_legacy_manifest() {
        // Old format without v1 fields should still deserialize
        let json = r#"{
            "session_id": "ssn_abc123",
            "name": "test",
            "actor": "ship://local",
            "started_at": "2026-04-05T08:00:00Z",
            "started_at_ms": 1743843600000,
            "artifact_count": 5,
            "root_artifact_id": "art_deadbeef"
        }"#;
        let m: SessionManifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.session_id, "ssn_abc123");
        assert_eq!(m.mode, LifecycleMode::AutoWorkspace);
        assert_eq!(m.status, SessionStatus::Active);
        assert_eq!(m.participants.total_agents, 0);
    }

    #[test]
    fn roundtrip_full_manifest() {
        let m = SessionManifest {
            session_id: "ssn_001".into(),
            name: Some("daily dev".into()),
            actor: "agent://claude".into(),
            started_at: "2026-04-05T08:00:00Z".into(),
            started_at_ms: 1743843600000,
            artifact_count: 12,
            root_artifact_id: Some("art_root".into()),
            mode: LifecycleMode::Manual,
            status: SessionStatus::Completed,
            workspace_id: Some("ws_abc".into()),
            mission_id: None,
            closed_at: Some("2026-04-05T12:00:00Z".into()),
            close_artifact_id: Some("art_close".into()),
            summary: Some("Fixed auth bug".into()),
            participants: Participants {
                root_agent_instance_id: Some("ai_root_1".into()),
                final_output_agent_instance_id: Some("ai_review_2".into()),
                total_agents: 6,
                spawned_subagents: 4,
                handoffs: 7,
                max_depth: 3,
                hosts: 2,
                tool_runtimes: 5,
            },
            hosts: vec![HostInfo {
                host_id: "host_1".into(),
                hostname: Some("macbook".into()),
                os: Some("darwin".into()),
                arch: Some("arm64".into()),
            }],
            tools: vec![ToolInfo {
                tool_id: "tool_1".into(),
                tool_name: "claude-code".into(),
                tool_runtime_id: Some("rt_cc1".into()),
                invocation_count: 42,
            }],
        };
        let json = serde_json::to_string_pretty(&m).unwrap();
        let m2: SessionManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m2.session_id, "ssn_001");
        assert_eq!(m2.participants.total_agents, 6);
        assert_eq!(m2.hosts.len(), 1);
    }
}
