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

/// Replace the home directory with `~` wherever it names a path in `text`,
/// so a receipt never carries `/Users/<name>/...`.
///
/// Works on a bare path and on free text such as a command line: every
/// occurrence of `$HOME` that starts at a path boundary (start of text,
/// whitespace, a quote, `=`, `:` and the like) and ends at one (end of text,
/// `/`, or a non-path character) becomes `~`. `/Users/someoneelse/x` is not
/// touched: the home must end where the path component ends.
pub fn redact_home_path(text: &str) -> String {
    let Some(home) = std::env::var_os("HOME") else {
        return text.to_string();
    };
    let home = home.to_string_lossy();
    let home = home.trim_end_matches('/');
    if home.is_empty() {
        return text.to_string();
    }
    redact_home_in(text, home)
}

fn is_path_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '/' | '.' | '_' | '-' | '~' | '+' | '%' | '@')
}

fn redact_home_in(text: &str, home: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut copied = 0; // bytes of `text` already in `out`
    let mut from = 0;
    while let Some(off) = text[from..].find(home) {
        let at = from + off;
        let after = at + home.len();
        let prev_ok = text[..at]
            .chars()
            .next_back()
            .is_none_or(|c| !is_path_char(c));
        let next_ok = text[after..]
            .chars()
            .next()
            .is_none_or(|c| c == '/' || !is_path_char(c));
        if prev_ok && next_ok {
            out.push_str(&text[copied..at]);
            out.push('~');
            copied = after;
            from = after;
        } else {
            // Step over one character and keep looking; `home` is non-empty.
            from = at + home.chars().next().map_or(1, char::len_utf8);
        }
    }
    out.push_str(&text[copied..]);
    out
}

#[cfg(test)]
mod redact_tests {
    use super::redact_home_in as r;
    const H: &str = "/Users/someone";

    #[test]
    fn home_paths_become_tilde_and_others_are_untouched() {
        assert_eq!(r("/Users/someone/src/a.rs", H), "~/src/a.rs");
        assert_eq!(r("/Users/someone", H), "~");
        assert_eq!(r("/Users/someoneelse/x", H), "/Users/someoneelse/x");
        assert_eq!(r("/opt/x", H), "/opt/x");
        assert_eq!(r("src/a.rs", H), "src/a.rs");
        assert_eq!(r("/opt/Users/someone/x", H), "/opt/Users/someone/x");
    }

    #[test]
    fn command_lines_are_redacted_at_path_boundaries() {
        assert_eq!(
            r("cat /Users/someone/a.txt /Users/someoneelse/b.txt", H),
            "cat ~/a.txt /Users/someoneelse/b.txt"
        );
        assert_eq!(r("--out=/Users/someone/o.json", H), "--out=~/o.json");
        assert_eq!(r("cd /Users/someone && ls", H), "cd ~ && ls");
        assert_eq!(r("'/Users/someone/a b'", H), "'~/a b'");
        assert_eq!(
            r("PATH=/Users/someone/bin:/usr/bin", H),
            "PATH=~/bin:/usr/bin"
        );
        assert_eq!(r("/Users/someone/x:/Users/someone/y", H), "~/x:~/y");
        assert_eq!(r("x/Users/someone/y", H), "x/Users/someone/y");
    }

    #[test]
    fn env_home_drives_the_public_function() {
        // A home that cannot be a prefix of this test's strings keeps them intact.
        std::env::set_var("HOME", "/nonexistent/home/for/redaction/test");
        assert_eq!(super::redact_home_path("/opt/x"), "/opt/x");
    }
}
