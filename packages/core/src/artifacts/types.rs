//! Command artifact payload types.
//!
//! Each struct is the signed payload of a DSSE envelope. `payload_type` on
//! the envelope discriminates which struct to deserialize into. The
//! `CommandType` enum is the parsed result `verify_command` returns.

use serde::{Deserialize, Serialize};

/// payloadType prefix shared by all command artifacts.
pub const COMMAND_PAYLOAD_PREFIX: &str = "application/vnd.treeship.command.";

/// payloadType for KillCommand.
pub const TYPE_KILL_COMMAND: &str = "application/vnd.treeship.command.kill.v1+json";
/// payloadType for ApprovalDecision.
pub const TYPE_APPROVAL_DECISION: &str =
    "application/vnd.treeship.command.approval_decision.v1+json";
/// payloadType for MandateUpdate.
pub const TYPE_MANDATE_UPDATE: &str = "application/vnd.treeship.command.mandate_update.v1+json";
/// payloadType for BudgetUpdate.
pub const TYPE_BUDGET_UPDATE: &str = "application/vnd.treeship.command.budget_update.v1+json";
/// payloadType for TerminateSession.
pub const TYPE_TERMINATE_SESSION: &str =
    "application/vnd.treeship.command.terminate_session.v1+json";

/// Immediate halt of a running session. Issuer demands the ship stop, do not
/// drain in-flight work, write the receipt up to the cut point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillCommand {
    pub session_id: String,
    pub reason: String,
    pub issued_at: String,
}

/// Approver's signed decision on a pending approval-required artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecision {
    pub approval_artifact_id: String,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub decided_at: String,
}

/// Approve / reject outcome on an approval-required artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approve,
    Reject,
}

/// Replace the bounded_actions / forbidden lists on a ship's mandate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandateUpdate {
    pub ship_id: String,
    pub new_bounded_actions: Vec<String>,
    pub new_forbidden: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

/// Adjust a ship's token budget by a signed delta. Positive grants tokens,
/// negative revokes. Witness applies these against its own running tally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BudgetUpdate {
    pub ship_id: String,
    pub token_limit_delta: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,
}

/// Graceful shutdown request: the ship should drain in-flight work, close
/// the session cleanly, and emit a final receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminateSession {
    pub session_id: String,
    pub reason: String,
    pub requested_at: String,
}

/// The discriminated parse result of a verified command artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandType {
    Kill(KillCommand),
    ApprovalDecision(ApprovalDecision),
    MandateUpdate(MandateUpdate),
    BudgetUpdate(BudgetUpdate),
    TerminateSession(TerminateSession),
}

impl CommandType {
    /// Stable string label for logs and CLI output.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Kill(_) => "kill",
            Self::ApprovalDecision(_) => "approval_decision",
            Self::MandateUpdate(_) => "mandate_update",
            Self::BudgetUpdate(_) => "budget_update",
            Self::TerminateSession(_) => "terminate_session",
        }
    }
}
