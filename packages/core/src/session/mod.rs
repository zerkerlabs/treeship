//! Session Receipt v1: unified session model for multi-agent workflows.
//!
//! This module provides the complete data model for Session Receipts:
//! session manifests, events, context propagation, agent graphs,
//! side-effect tracking, and receipt composition.

pub mod manifest;
pub mod event;
pub mod event_log;
pub mod context;
pub mod graph;
pub mod side_effects;
pub mod receipt;
pub mod render;
pub mod package;
pub mod git;

pub use manifest::*;
pub use event::*;
pub use event_log::EventLog;
pub use context::PropagationContext;
pub use graph::{AgentGraph, AgentNode, AgentEdge, AgentEdgeType};
pub use side_effects::{FileAccess, SideEffects};
pub use receipt::{ArtifactEntry, ReceiptComposer, SessionReceipt};
pub use render::RenderConfig;
pub use package::{
    build_package, build_package_with_approvals, build_signed_package,
    build_signed_package_with_approvals, compute_package_manifest_digest,
    read_approvals_bundle, read_package,
    render_preview_html, verify_package, verify_package_with_trust,
    ApprovalsBundle, ApprovalsIndex, EvidencePlane, PackageFile, PackageManifest,
    VerifyCheck, VerifyStatus,
};
pub use git::{
    reconcile_changes, reconcile_changes_with_options, current_head_sha, git_toplevel,
    GitChange, ReconcileOptions, ReconcileResult, ReconcileSummary,
};
