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
    build_package, build_package_with_approvals, package_close_signed_by, package_verdict,
    read_approvals_bundle, read_package, render_preview_html, verify_package,
    verify_package_structural, verify_package_with_options, verify_package_with_trust,
    ApprovalsBundle, ApprovalsIndex, PackageKeys, PackageVerdict, VerifyCheck, VerifyStatus,
    KEYS_FILE, PACKAGE_KEYS_SCHEMA, RECORD_FILE,
};
pub use receipt::{ArtifactEntry, ReceiptComposer, SessionReceipt};
pub use render::RenderConfig;
pub use side_effects::{FileAccess, SideEffects};

/// A file path as a receipt records it: a path under the user's home is
/// written as `~/...`. Receipts are published; one carried 1014 absolute
/// `/Users/<name>/...` paths. This runs where the receipt is composed, so
/// the redacted form is what the close record signs; digests of file
/// contents are untouched.
pub fn redact_home_path(path: &str) -> String {
    let Some(home) = std::env::var_os("HOME") else {
        return path.to_string();
    };
    let home = home.to_string_lossy();
    let home = home.trim_end_matches('/');
    if home.is_empty() {
        return path.to_string();
    }
    if path == home {
        return "~".to_string();
    }
    match path.strip_prefix(home) {
        Some(rest) if rest.starts_with('/') => format!("~{rest}"),
        _ => path.to_string(),
    }
}

#[cfg(test)]
mod redact_tests {
    #[test]
    fn home_paths_become_tilde_and_others_are_untouched() {
        std::env::set_var("HOME", "/Users/someone");
        assert_eq!(
            super::redact_home_path("/Users/someone/src/a.rs"),
            "~/src/a.rs"
        );
        assert_eq!(super::redact_home_path("/Users/someone"), "~");
        assert_eq!(
            super::redact_home_path("/Users/someoneelse/x"),
            "/Users/someoneelse/x"
        );
        assert_eq!(super::redact_home_path("/opt/x"), "/opt/x");
        assert_eq!(super::redact_home_path("src/a.rs"), "src/a.rs");
    }
}
