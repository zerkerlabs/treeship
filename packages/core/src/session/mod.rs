//! Session Receipt v1: unified session model for multi-agent workflows.
//!
//! This module provides the complete data model for Session Receipts:
//! session manifests, events, context propagation, agent graphs,
//! side-effect tracking, and receipt composition.

pub mod context;
pub mod event;
pub mod event_log;
pub mod git;
pub mod graph;
pub mod manifest;
pub mod package;
pub mod receipt;
pub mod render;
pub mod side_effects;

pub use context::PropagationContext;
pub use event::*;
pub use event_log::EventLog;
pub use git::{
    current_head_sha, git_toplevel, reconcile_changes, reconcile_changes_with_options, GitChange,
    ReconcileOptions, ReconcileResult, ReconcileSummary,
};
pub use graph::{AgentEdge, AgentEdgeType, AgentGraph, AgentNode};
pub use manifest::*;
pub use package::{
    build_package, build_package_with_approvals, read_approvals_bundle, read_package,
    render_preview_html, verify_package, verify_package_with_trust, ApprovalsBundle,
    ApprovalsIndex, VerifyCheck, VerifyStatus,
};
pub use receipt::{ArtifactEntry, ReceiptComposer, SessionReceipt};
pub use render::RenderConfig;
pub use side_effects::{FileAccess, SideEffects};
