//! Git-based reconciliation for session close.
//!
//! Backstop layer of the trust-fabric file-capture stack:
//!
//!   1. (highest trust) specialized event types (`agent.wrote_file`)
//!   2. (medium)        promoted from generic `agent.called_tool`
//!   3. (this module)   shell out to `git` at session close and pick
//!                      up anything an agent edited outside any
//!                      captured tool channel
//!
//! Why this matters: the trust-fabric bar is "if a file changed, it
//! must appear in the receipt." Hooks and MCP cover most paths but
//! not all -- an agent that ran `sed -i` inside a Bash command, a
//! build tool that modified files, or any other untracked side
//! effect would otherwise vanish silently. Running `git diff` and
//! `git ls-files --others` at close catches the rest.
//!
//! Fail-open by design: if the working dir isn't a git repo, if the
//! git binary is missing, or if any git command errors, returns an
//! empty list. The receipt is still produced; reconciliation is a
//! best-effort enhancement, never a gate.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const DEFAULT_UNTRACKED_MAX: usize = 5_000;

/// One file change observed via git that wasn't already captured by a
/// tool channel. Mapped 1:1 into a synthetic `AgentWroteFile` event
/// at session close so it flows through the normal aggregator and
/// receipt composition path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitChange {
    pub file_path: String,
    /// "created", "modified", "deleted", "renamed", or "untracked".
    pub operation: String,
    pub additions: Option<u32>,
    pub deletions: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileOptions {
    pub untracked_max: usize,
}

impl Default for ReconcileOptions {
    fn default() -> Self {
        Self {
            untracked_max: DEFAULT_UNTRACKED_MAX,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileSummary {
    pub untracked_seen: usize,
    pub untracked_cap: usize,
    pub untracked_truncated: bool,
    /// Whether a git work tree was actually present when reconcile ran
    /// (AUD-07). `false` means `is_git_repo` returned false — not in a repo,
    /// git binary missing/PATH-poisoned, or `.git` removed/corrupted — so the
    /// git-diff backstop produced NO changes for a reason other than "clean
    /// tree". The close path cross-checks this against the session's
    /// start-of-session HEAD: if git worked at start but not at close, the
    /// backstop was disabled mid-session and the receipt is stamped degraded.
    /// Defaults to false so a `ReconcileSummary::default()` (reconcile never
    /// ran) is treated as "git not confirmed present", not a clean tree.
    pub git_repo_present: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileResult {
    pub changes: Vec<GitChange>,
    pub summary: ReconcileSummary,
}

/// Run `git` in `repo_dir` with the given args, returning stdout
/// trimmed of trailing newline. Returns None on any failure (not
/// a git repo, git missing, non-zero exit, etc.) -- this module is
/// fail-open by contract.
fn git_capture(repo_dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let mut s = String::from_utf8(output.stdout).ok()?;
    while s.ends_with('\n') {
        s.pop();
    }
    Some(s)
}

fn git_capture_lines_limited(
    repo_dir: &Path,
    args: &[&str],
    limit: usize,
) -> Option<(Vec<String>, bool)> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let stdout = child.stdout.take()?;
    let reader = BufReader::new(stdout);
    let mut lines = Vec::new();
    let mut truncated = false;
    for line in reader.lines() {
        let line = line.ok()?;
        if lines.len() >= limit {
            truncated = true;
            let _ = child.kill();
            break;
        }
        lines.push(line);
    }
    let status = child.wait().ok()?;
    if !truncated && !status.success() {
        return None;
    }
    Some((lines, truncated))
}

/// Fast probe: is this directory inside a git repo?
fn is_git_repo(repo_dir: &Path) -> bool {
    git_capture(repo_dir, &["rev-parse", "--is-inside-work-tree"]).as_deref() == Some("true")
}

pub fn git_toplevel(repo_dir: &Path) -> Option<PathBuf> {
    git_capture(repo_dir, &["rev-parse", "--show-toplevel"]).map(PathBuf::from)
}

/// Translate a git diff/status name-status code to our operation
/// vocabulary. Codes from `git diff --name-status`: A=added,
/// M=modified, D=deleted, R=renamed, C=copied, T=type-change,
/// U=unmerged, plus special "??" for ls-files untracked.
fn translate_status(code: &str) -> &'static str {
    match code.chars().next().unwrap_or(' ') {
        'A' => "created",
        'D' => "deleted",
        'R' => "renamed",
        'C' => "created", // copy = new file at the destination
        'T' => "modified",
        '?' => "untracked",
        _ => "modified", // M, U, anything else
    }
}

/// Parse a single line of `git diff --name-status`, returning the
/// canonical operation and the FINAL path of the change.
///
/// Codex round-2 finding 5: the original `parts.next() / parts.next()`
/// shorthand grabbed the FIRST path, which on rename / copy lines is
/// the OLD path. So `git mv src/old.rs src/new.rs` produced
/// `R100\told.rs\tnew.rs`, and reconcile recorded `src/old.rs` (which
/// no longer exists) instead of `src/new.rs` (the destination the
/// agent actually created). Cross-verify against a cert that allowed
/// "src/new.rs" then incorrectly flagged the change as touching an
/// unauthorized file.
///
/// Format from `git diff --name-status`:
///   M\tpath               -- modified
///   A\tpath               -- added
///   D\tpath               -- deleted
///   T\tpath               -- type-changed
///   R<score>\told\tnew    -- renamed (with similarity score)
///   C<score>\told\tnew    -- copied
///   ?\?\tpath             -- (only from ls-files, never name-status)
///
/// For R* and C* we return the destination (new) path. For everything
/// else, the single path. Returns None when the line is empty or
/// missing fields.
fn parse_name_status_line(line: &str) -> Option<(&'static str, String)> {
    let mut parts = line.split('\t');
    let code = parts.next()?;
    if code.is_empty() {
        return None;
    }
    let first_path = parts.next()?;
    let op = translate_status(code);
    let path = match code.chars().next().unwrap_or(' ') {
        'R' | 'C' => {
            // Rename / copy: the FINAL path is the third field.
            // If the destination is missing for any reason, fall
            // back to the source so we still record SOMETHING.
            parts
                .next()
                .map(|p| p.to_string())
                .unwrap_or_else(|| first_path.to_string())
        }
        _ => first_path.to_string(),
    };
    Some((op, path))
}

/// Parse a single line of `git diff --numstat` (additions, deletions,
/// path). Numeric fields are "-" for binary files; we represent
/// those as None.
fn parse_numstat_line(line: &str) -> Option<(String, Option<u32>, Option<u32>)> {
    let mut parts = line.splitn(3, '\t');
    let adds_s = parts.next()?;
    let dels_s = parts.next()?;
    let path = parts.next()?.to_string();
    let adds = adds_s.parse::<u32>().ok();
    let dels = dels_s.parse::<u32>().ok();
    Some((path, adds, dels))
}

/// Decides whether a path discovered by git reconciliation should be
/// included in the receipt.
///
/// Treeship's own runtime artifacts -- session.closing markers,
/// sessions/<id>/ event logs, artifact storage, scratch tmp -- live
/// inside `.treeship/` and get touched by the very session that's
/// closing. Without this filter they show up in `files_written` as
/// "the agent modified .treeship/sessions/ssn_X/events.jsonl",
/// noisy and misleading: it was Treeship's own bookkeeping, not the
/// agent's work.
///
/// User-authored Treeship files (config.yaml, declaration.json, agent
/// cards, policy) DO get surfaced -- those are the operator's own
/// changes that an audit reader cares about.
fn is_treeship_runtime_artifact(path: &str) -> bool {
    // Strip leading "./" if present so both forms compare cleanly.
    let p = path.strip_prefix("./").unwrap_or(path);
    if !p.starts_with(".treeship/") && p != ".treeship" {
        return false;
    }
    // Within .treeship/, exclude generated runtime state.
    p == ".treeship/session.closing"
        || p == ".treeship/session.json"
        || p.starts_with(".treeship/sessions/")
        || p.starts_with(".treeship/artifacts/")
        || p.starts_with(".treeship/tmp/")
        || p.starts_with(".treeship/proof_queue/")
}

/// Collect every file change in `repo_dir` worth surfacing in a
/// session receipt: working-tree modifications (staged or not),
/// committed-since-`since_sha` changes (when provided), and untracked
/// files.
///
/// Deduplicated across the three sources so a single file shows up
/// once. When `git diff --numstat` reports additions/deletions for a
/// path, those are attached; binary files leave them as None.
///
/// Returns an empty Vec if `repo_dir` isn't a git repo or git isn't
/// available -- callers (i.e. session close) should treat absence as
/// "nothing to reconcile" and continue.
pub fn reconcile_changes(repo_dir: &Path, since_sha: Option<&str>) -> Vec<GitChange> {
    reconcile_changes_with_options(repo_dir, since_sha, &ReconcileOptions::default()).changes
}

pub fn reconcile_changes_with_options(
    repo_dir: &Path,
    since_sha: Option<&str>,
    options: &ReconcileOptions,
) -> ReconcileResult {
    let mut result = ReconcileResult {
        summary: ReconcileSummary {
            untracked_cap: options.untracked_max,
            ..ReconcileSummary::default()
        },
        ..ReconcileResult::default()
    };

    if !is_git_repo(repo_dir) {
        // git_repo_present stays false: the caller can distinguish "clean tree
        // in a real repo" from "no repo / git unavailable" (AUD-07).
        return result;
    }
    result.summary.git_repo_present = true;

    use std::collections::BTreeMap;
    // path -> change. BTreeMap so output is deterministic across runs,
    // which matters for canonical receipt JSON / merkle stability.
    let mut by_path: BTreeMap<String, GitChange> = BTreeMap::new();

    let mut record = |path: String, op: &str| {
        if is_treeship_runtime_artifact(&path) {
            return;
        }
        by_path.entry(path.clone()).or_insert(GitChange {
            file_path: path,
            operation: op.to_string(),
            additions: None,
            deletions: None,
        });
    };

    // 1. Uncommitted changes vs HEAD (staged + unstaged combined via
    //    name-status). The common agent case: edited a file, didn't
    //    commit.
    if let Some(out) = git_capture(repo_dir, &["diff", "HEAD", "--name-status"]) {
        for line in out.lines() {
            if let Some((op, path)) = parse_name_status_line(line) {
                record(path, op);
            }
        }
    }

    // 2. Committed-during-session changes if the caller captured a
    //    starting SHA at session start.
    if let Some(sha) = since_sha {
        let range = format!("{sha}..HEAD");
        if let Some(out) = git_capture(repo_dir, &["diff", &range, "--name-status"]) {
            for line in out.lines() {
                if let Some((op, path)) = parse_name_status_line(line) {
                    record(path, op);
                }
            }
        }
    }

    // 3. Untracked files (new files the agent added but didn't `git
    //    add`). These never show in `git diff` so they need their own
    //    pass.
    if let Some((lines, truncated)) = git_capture_lines_limited(
        repo_dir,
        &["ls-files", "--others", "--exclude-standard"],
        options.untracked_max.saturating_add(1),
    ) {
        result.summary.untracked_seen = lines.len();
        result.summary.untracked_truncated = truncated || lines.len() > options.untracked_max;
        if result.summary.untracked_truncated {
            result.summary.untracked_seen = result
                .summary
                .untracked_seen
                .max(options.untracked_max.saturating_add(1));
        } else {
            for path in lines.iter().filter(|l| !l.is_empty()) {
                record(path.to_string(), "untracked");
            }
        }
    }

    // 4. Numstat for the same diff range -- attach additions/deletions
    //    where available. Numstat reports differently than name-status
    //    (no rename indicator), so we just match by path.
    if let Some(out) = git_capture(repo_dir, &["diff", "HEAD", "--numstat"]) {
        for line in out.lines() {
            if let Some((path, adds, dels)) = parse_numstat_line(line) {
                if let Some(entry) = by_path.get_mut(&path) {
                    entry.additions = adds;
                    entry.deletions = dels;
                }
            }
        }
    }
    if let Some(sha) = since_sha {
        let range = format!("{sha}..HEAD");
        if let Some(out) = git_capture(repo_dir, &["diff", &range, "--numstat"]) {
            for line in out.lines() {
                if let Some((path, adds, dels)) = parse_numstat_line(line) {
                    if let Some(entry) = by_path.get_mut(&path) {
                        entry.additions = adds;
                        entry.deletions = dels;
                    }
                }
            }
        }
    }

    result.changes = by_path.into_values().collect();
    result
}

/// Capture the current HEAD commit SHA so it can be stored in the
/// session manifest at session start. The session close pass uses it
/// as the diff base for committed-during-session changes. Returns
/// None when not in a git repo or no commits exist yet.
pub fn current_head_sha(repo_dir: &Path) -> Option<String> {
    if !is_git_repo(repo_dir) {
        return None;
    }
    git_capture(repo_dir, &["rev-parse", "HEAD"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translate_status_maps_known_codes() {
        assert_eq!(translate_status("A"), "created");
        assert_eq!(translate_status("M"), "modified");
        assert_eq!(translate_status("D"), "deleted");
        assert_eq!(translate_status("R100"), "renamed");
        assert_eq!(translate_status("??"), "untracked");
        assert_eq!(translate_status(""), "modified");
        assert_eq!(translate_status("X"), "modified");
    }

    #[test]
    fn parse_numstat_handles_text_and_binary() {
        let (p, a, d) = parse_numstat_line("12\t3\tsrc/a.rs").unwrap();
        assert_eq!(p, "src/a.rs");
        assert_eq!(a, Some(12));
        assert_eq!(d, Some(3));

        // Binary files: numstat uses "-\t-\tpath".
        let (p, a, d) = parse_numstat_line("-\t-\tassets/logo.png").unwrap();
        assert_eq!(p, "assets/logo.png");
        assert_eq!(a, None);
        assert_eq!(d, None);
    }

    #[test]
    fn reconcile_in_non_git_dir_returns_empty() {
        let tmp =
            std::env::temp_dir().join(format!("treeship-not-a-repo-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmp).unwrap();
        let result = reconcile_changes(&tmp, None);
        assert!(result.is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // AUD-07: git_repo_present distinguishes "clean tree in a real repo" from
    // "no repo / git unavailable" so the close path can detect a backstop that
    // was disabled mid-session.
    #[test]
    fn git_repo_present_false_outside_repo() {
        let tmp = std::env::temp_dir().join(format!("treeship-nogit-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmp).unwrap();
        let r = reconcile_changes_with_options(&tmp, None, &ReconcileOptions::default());
        assert!(
            !r.summary.git_repo_present,
            "no git repo -> git_repo_present must be false"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn git_repo_present_true_in_real_repo() {
        let tmp = std::env::temp_dir().join(format!("treeship-git-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmp).unwrap();
        let inited = Command::new("git")
            .arg("-C")
            .arg(&tmp)
            .arg("init")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if inited {
            let r = reconcile_changes_with_options(&tmp, None, &ReconcileOptions::default());
            assert!(
                r.summary.git_repo_present,
                "real git repo -> git_repo_present must be true"
            );
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ── Codex round-2 finding 5: rename / copy parsing returned the
    //    SOURCE path instead of the destination, so `git mv old new`
    //    surfaced "old" (which no longer exists) instead of "new"
    //    (which the agent created).

    #[test]
    fn parse_name_status_modify_uses_single_path() {
        let (op, path) = parse_name_status_line("M\tsrc/lib.rs").unwrap();
        assert_eq!(op, "modified");
        assert_eq!(path, "src/lib.rs");
    }

    #[test]
    fn parse_name_status_added_uses_single_path() {
        let (op, path) = parse_name_status_line("A\tsrc/new.rs").unwrap();
        assert_eq!(op, "created");
        assert_eq!(path, "src/new.rs");
    }

    #[test]
    fn parse_name_status_deleted_uses_single_path() {
        let (op, path) = parse_name_status_line("D\tsrc/gone.rs").unwrap();
        assert_eq!(op, "deleted");
        assert_eq!(path, "src/gone.rs");
    }

    #[test]
    fn parse_name_status_rename_uses_destination() {
        // The bug Codex caught: this line produced path="src/old.rs"
        // even though the agent's `git mv` ended with src/new.rs as
        // the actual file on disk.
        let (op, path) = parse_name_status_line("R100\tsrc/old.rs\tsrc/new.rs").unwrap();
        assert_eq!(op, "renamed");
        assert_eq!(
            path, "src/new.rs",
            "rename must record the destination, not the source"
        );
    }

    #[test]
    fn parse_name_status_copy_uses_destination() {
        // Copies map to "created" semantically -- a new file appeared
        // at the destination -- and we record the destination path.
        let (op, path) =
            parse_name_status_line("C75\tsrc/template.rs\tsrc/new-from-template.rs").unwrap();
        assert_eq!(op, "created");
        assert_eq!(
            path, "src/new-from-template.rs",
            "copy must record the destination"
        );
    }

    #[test]
    fn parse_name_status_rename_falls_back_to_source_if_dest_missing() {
        // Defensive: if git output were ever truncated to "R100\told"
        // with no destination, we should still record SOMETHING
        // rather than silently swallowing the line. Falls back to
        // the source path -- not perfect, but visible.
        let (op, path) = parse_name_status_line("R100\tsrc/only-old.rs").unwrap();
        assert_eq!(op, "renamed");
        assert_eq!(path, "src/only-old.rs");
    }

    #[test]
    fn parse_name_status_handles_empty_or_garbage_lines() {
        assert!(parse_name_status_line("").is_none());
        assert!(parse_name_status_line("\t\t").is_none()); // empty code field
                                                           // Code with no path -- nothing to record.
        assert!(parse_name_status_line("M").is_none());
    }

    #[test]
    fn runtime_artifact_filter_excludes_generated_state() {
        // Generated runtime state -- never the agent's work.
        assert!(is_treeship_runtime_artifact(".treeship/session.closing"));
        assert!(is_treeship_runtime_artifact(".treeship/session.json"));
        assert!(is_treeship_runtime_artifact(
            ".treeship/sessions/ssn_abc/events.jsonl"
        ));
        assert!(is_treeship_runtime_artifact(
            ".treeship/sessions/ssn_abc/manifest.json"
        ));
        assert!(is_treeship_runtime_artifact(".treeship/artifacts/foo.json"));
        assert!(is_treeship_runtime_artifact(".treeship/tmp/scratch"));
        assert!(is_treeship_runtime_artifact(
            ".treeship/proof_queue/pending.json"
        ));

        // "./"-prefixed forms (some git output emits these).
        assert!(is_treeship_runtime_artifact("./.treeship/session.closing"));
        assert!(is_treeship_runtime_artifact(
            "./.treeship/sessions/ssn_x/events.jsonl"
        ));
    }

    #[test]
    fn runtime_artifact_filter_preserves_user_authored_files() {
        // User-authored Treeship config / policy / cards: these ARE the
        // operator's own changes and must show up in the receipt.
        assert!(!is_treeship_runtime_artifact(".treeship/config.yaml"));
        assert!(!is_treeship_runtime_artifact(".treeship/config.json"));
        assert!(!is_treeship_runtime_artifact(".treeship/declaration.json"));
        assert!(!is_treeship_runtime_artifact(".treeship/policy.yaml"));
        assert!(!is_treeship_runtime_artifact(
            ".treeship/agents/coder.agent"
        ));
        assert!(!is_treeship_runtime_artifact(
            ".treeship/agents/reviewer.json"
        ));

        // Anything outside .treeship/ is never filtered.
        assert!(!is_treeship_runtime_artifact("src/main.rs"));
        assert!(!is_treeship_runtime_artifact("README.md"));
        assert!(!is_treeship_runtime_artifact("treeship-notes.md"));
        assert!(!is_treeship_runtime_artifact(".treeshiprc"));
    }

    #[test]
    fn reconcile_filters_runtime_artifacts_end_to_end() {
        // Build a real one-commit git repo, then make changes to a mix
        // of runtime-artifact paths and user-authored paths. The
        // returned reconciliation must include the user files and
        // exclude the runtime artifacts.
        let tmp =
            std::env::temp_dir().join(format!("treeship-reconcile-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmp).unwrap();

        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(&tmp)
                .args(args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .ok();
        };

        run(&["init", "-q"]);
        run(&["config", "user.email", "test@example.com"]);
        run(&["config", "user.name", "Test"]);
        std::fs::write(tmp.join("README.md"), "hi\n").unwrap();
        run(&["add", "."]);
        run(&["commit", "-q", "-m", "init"]);

        // Now create a mix: runtime artifacts and a real user file.
        std::fs::create_dir_all(tmp.join(".treeship/sessions/ssn_x")).unwrap();
        std::fs::create_dir_all(tmp.join(".treeship/artifacts")).unwrap();
        std::fs::create_dir_all(tmp.join(".treeship/agents")).unwrap();
        std::fs::write(tmp.join(".treeship/sessions/ssn_x/events.jsonl"), "{}\n").unwrap();
        std::fs::write(tmp.join(".treeship/artifacts/foo.json"), "{}\n").unwrap();
        std::fs::write(tmp.join(".treeship/session.closing"), "").unwrap();
        std::fs::write(tmp.join(".treeship/agents/coder.agent"), "name: coder\n").unwrap();
        std::fs::write(tmp.join(".treeship/declaration.json"), "{}\n").unwrap();
        std::fs::write(tmp.join("src.rs"), "fn main() {}\n").unwrap();

        let changes = reconcile_changes(&tmp, None);
        let paths: Vec<&str> = changes.iter().map(|c| c.file_path.as_str()).collect();

        // User-authored content: present.
        assert!(paths.contains(&"src.rs"), "user file missing: {paths:?}");
        assert!(
            paths.contains(&".treeship/agents/coder.agent"),
            "agent card missing: {paths:?}"
        );
        assert!(
            paths.contains(&".treeship/declaration.json"),
            "declaration missing: {paths:?}"
        );

        // Runtime artifacts: excluded.
        assert!(
            !paths.contains(&".treeship/sessions/ssn_x/events.jsonl"),
            "leaked: {paths:?}"
        );
        assert!(
            !paths.contains(&".treeship/artifacts/foo.json"),
            "leaked: {paths:?}"
        );
        assert!(
            !paths.contains(&".treeship/session.closing"),
            "leaked: {paths:?}"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn reconcile_truncates_untracked_without_promoting_per_file_events() {
        let tmp =
            std::env::temp_dir().join(format!("treeship-reconcile-cap-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmp).unwrap();

        let run = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(&tmp)
                .args(args)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .ok();
        };

        run(&["init", "-q"]);
        run(&["config", "user.email", "test@example.com"]);
        run(&["config", "user.name", "Test"]);
        std::fs::write(tmp.join("README.md"), "hi\n").unwrap();
        run(&["add", "."]);
        run(&["commit", "-q", "-m", "init"]);

        std::fs::write(tmp.join("a.txt"), "a\n").unwrap();
        std::fs::write(tmp.join("b.txt"), "b\n").unwrap();
        std::fs::write(tmp.join("c.txt"), "c\n").unwrap();

        let result =
            reconcile_changes_with_options(&tmp, None, &ReconcileOptions { untracked_max: 2 });

        assert!(result.summary.untracked_truncated);
        assert_eq!(result.summary.untracked_cap, 2);
        assert!(result.summary.untracked_seen >= 3);
        assert!(
            result.changes.iter().all(|c| c.operation != "untracked"),
            "truncated untracked files must not be emitted one-per-file: {:?}",
            result.changes,
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
