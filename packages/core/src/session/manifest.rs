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

/// Who may mint invitations for a room. Mirrors the Q3 decision in
/// `docs/specs/agent-invitations-rooms.md`: HostOnly is the default,
/// DelegatedTo and Open are explicit opt-in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InvitationAuthority {
    /// Only the room's host key may mint invitations.
    HostOnly,
    /// The host plus a named list of delegate pubkeys may mint invitations.
    DelegatedTo { delegates: Vec<String> },
    /// Any current participant may mint invitations.
    Open,
}

impl Default for InvitationAuthority {
    fn default() -> Self {
        Self::HostOnly
    }
}

/// Room wrapper around a session, per `docs/specs/agent-invitations-rooms.md`
/// Phase 2 ("room concept"). A room is a session whose participant set is
/// expected to evolve over time via invitations rather than being fixed at
/// start; this struct carries the fields the spec proposes on top of the
/// plain session/invitation/participant primitives that already ship.
///
/// `room` is `Option` on `SessionManifest` -- most sessions are not rooms.
/// Absent entirely on legacy manifests and on any session that never calls
/// `treeship room create`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoomInfo {
    /// Stable room identifier, distinct from `session_id` -- a room can in
    /// principle outlive the session that hosts it (roadmap; today the two
    /// are 1:1).
    pub room_id: String,

    /// The room's signing authority. Base64url-no-pad Ed25519 public key,
    /// same encoding as `SessionParticipantStatement::joining_agent`. This
    /// is the pubkey invitations are issued under and that a joining
    /// agent's participant event is countersigned by.
    pub host_pubkey: String,

    #[serde(default)]
    pub invitation_authority: InvitationAuthority,

    /// Optional workflow this room's participants are bound to (Phase 3 of
    /// the spec, PR #107 -- carried here now so the field name is settled
    /// before that lands).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_ref: Option<String>,

    /// How often the room commits a Merkle checkpoint, independent of
    /// session close. Free-form for now (e.g. "50actions", "15m") --
    /// the spec doesn't lock a format, so this isn't a typed duration yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_cadence: Option<String>,

    /// Finalized (both-signed) participant artifact ids, in join order.
    /// A pending (single-signed, not yet countersigned) join does not
    /// appear here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub participants: Vec<String>,
}

impl RoomInfo {
    pub fn new(room_id: impl Into<String>, host_pubkey: impl Into<String>) -> Self {
        Self {
            room_id: room_id.into(),
            host_pubkey: host_pubkey.into(),
            invitation_authority: InvitationAuthority::default(),
            workflow_ref: None,
            checkpoint_cadence: None,
            participants: Vec::new(),
        }
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

    /// Tools declared as authorized for this session (from declaration.json).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authorized_tools: Vec<String>,

    /// Git HEAD SHA captured at session start, when the project is a
    /// git repo. Used by session::close to compute committed-during-
    /// session changes via `git diff <sha>..HEAD` for the
    /// reconciliation pass. Absent for non-git projects or for
    /// sessions started before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_commit_sha: Option<String>,

    /// Set by `treeship room create`. Absent for ordinary (non-room)
    /// sessions and for any manifest written before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub room: Option<RoomInfo>,
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
            authorized_tools: Vec::new(),
            start_commit_sha: None,
            room: None,
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
            authorized_tools: vec!["read_file".into(), "write_file".into()],
            start_commit_sha: Some("abc1234567890abcdef1234567890abcdef12345".into()),
            room: Some(RoomInfo {
                room_id: "room_001".into(),
                host_pubkey: "AbCdEf123".into(),
                invitation_authority: InvitationAuthority::DelegatedTo {
                    delegates: vec!["DeLeGaTe1".into()],
                },
                workflow_ref: Some("wf_abc".into()),
                checkpoint_cadence: Some("50actions".into()),
                participants: vec!["art_part_1".into(), "art_part_2".into()],
            }),
        };
        let json = serde_json::to_string_pretty(&m).unwrap();
        let m2: SessionManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m2.session_id, "ssn_001");
        assert_eq!(m2.participants.total_agents, 6);
        assert_eq!(m2.hosts.len(), 1);
        assert_eq!(m2.room.as_ref().unwrap().room_id, "room_001");
        assert_eq!(m2.room.as_ref().unwrap().participants.len(), 2);
    }

    #[test]
    fn legacy_manifest_has_no_room() {
        // A manifest predating the `room` field must still deserialize,
        // with `room` defaulting to `None` -- same backward-compat
        // contract every other v1 field already follows.
        let json = r#"{
            "session_id": "ssn_legacy",
            "actor": "ship://local",
            "started_at": "2026-04-05T08:00:00Z",
            "started_at_ms": 1743843600000,
            "artifact_count": 0
        }"#;
        let m: SessionManifest = serde_json::from_str(json).unwrap();
        assert!(m.room.is_none());
    }

    #[test]
    fn room_omitted_from_json_when_absent() {
        // Ordinary (non-room) sessions shouldn't grow a `"room": null` in
        // every session.json on disk.
        let m = SessionManifest::new(
            "ssn_plain".into(),
            "ship://local".into(),
            "2026-04-05T08:00:00Z".into(),
            1743843600000,
        );
        let json = serde_json::to_string(&m).unwrap();
        assert!(!json.contains("\"room\""));
    }

    #[test]
    fn invitation_authority_defaults_to_host_only() {
        assert_eq!(
            InvitationAuthority::default(),
            InvitationAuthority::HostOnly
        );
    }
}
