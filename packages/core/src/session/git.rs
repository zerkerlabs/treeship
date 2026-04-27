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

use std::path::Path;
use std::process::{Command, Stdio};

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

/// Run `git` in `repo_dir` with the given args, returning stdout
/// trimmed of trailing newline. Returns None on any failure (not
/// a git repo, git missing, non-zero exit, etc.) -- this module is
/// fail-open by contract.
fn git_capture(repo_dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C").arg(repo_dir)
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

/// Fast probe: is this directory inside a git repo?
fn is_git_repo(repo_dir: &Path) -> bool {
    git_capture(repo_dir, &["rev-parse", "--is-inside-work-tree"])
        .as_deref()
        == Some("true")
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
        _   => "modified", // M, U, anything else
    }
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
    if !is_git_repo(repo_dir) {
        return Vec::new();
    }

    use std::collections::BTreeMap;
    // path -> change. BTreeMap so output is deterministic across runs,
    // which matters for canonical receipt JSON / merkle stability.
    let mut by_path: BTreeMap<String, GitChange> = BTreeMap::new();

    let mut record = |path: String, op: &str| {
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
            let mut parts = line.split('\t');
            if let (Some(code), Some(path)) = (parts.next(), parts.next()) {
                let op = translate_status(code);
                record(path.to_string(), op);
            }
        }
    }

    // 2. Committed-during-session changes if the caller captured a
    //    starting SHA at session start.
    if let Some(sha) = since_sha {
        let range = format!("{sha}..HEAD");
        if let Some(out) = git_capture(repo_dir, &["diff", &range, "--name-status"]) {
            for line in out.lines() {
                let mut parts = line.split('\t');
                if let (Some(code), Some(path)) = (parts.next(), parts.next()) {
                    let op = translate_status(code);
                    record(path.to_string(), op);
                }
            }
        }
    }

    // 3. Untracked files (new files the agent added but didn't `git
    //    add`). These never show in `git diff` so they need their own
    //    pass.
    if let Some(out) = git_capture(repo_dir, &["ls-files", "--others", "--exclude-standard"]) {
        for path in out.lines().filter(|l| !l.is_empty()) {
            record(path.to_string(), "untracked");
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

    by_path.into_values().collect()
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
        let tmp = std::env::temp_dir().join(format!("treeship-not-a-repo-{}", rand::random::<u32>()));
        std::fs::create_dir_all(&tmp).unwrap();
        let result = reconcile_changes(&tmp, None);
        assert!(result.is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
