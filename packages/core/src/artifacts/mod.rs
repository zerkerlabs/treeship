//! Command artifact schemas: signed control-plane messages a Witness (or
//! comparable supervisor) sends to a running ship.
//!
//! These are primitives. v0.9.0 ships the schemas, payload-type strings, and
//! a single signature-validation helper (`verify_command`). The CLI surfaces
//! that issue and consume them ship in later releases (approval loop in
//! v0.10.0, kill/terminate in v1.0). Witness consumes them today.
//!
//! All command artifacts are wrapped in the same DSSE envelope used for
//! actions/approvals — verification reuses `treeship_core::attestation`.

pub mod types;
pub mod verify;

pub use types::{
    ApprovalDecision, BudgetUpdate, CommandType, Decision, KillCommand, MandateUpdate,
    TerminateSession, COMMAND_PAYLOAD_PREFIX, TYPE_APPROVAL_DECISION, TYPE_BUDGET_UPDATE,
    TYPE_KILL_COMMAND, TYPE_MANDATE_UPDATE, TYPE_TERMINATE_SESSION,
};
pub use verify::{verify_command, VerifyCommandError, VerifyCommandResult};
