//! CLI commands for inspecting and verifying .treeship packages.

use std::path::{Path, PathBuf};

use treeship_core::session::{read_package, verify_package, FileAccess, VerifyStatus};

use crate::commands::cards;
use crate::commands::harnesses;
use crate::ctx;
use crate::printer::Printer;

// ---------------------------------------------------------------------------
// Files Changed filtering
// ---------------------------------------------------------------------------

/// Treeship's own runtime artifacts that should NOT show up in the user's
/// "files changed" list. These are written by Treeship itself during
/// session capture and are noise to a reader trying to understand what
/// the agent did.
///
/// Path-shape based, not glob, so the filter is robust whether paths are
/// absolute, relative, or contain a workspace prefix.
fn is_treeship_runtime_artifact(path: &str) -> bool {
    // Strip any leading workspace prefix; we care about the trailing
    // segment under .treeship/.
    let key = path
        .rsplit_once(".treeship/")
        .map(|(_, after)| after)
        .unwrap_or(path);
    if key == path && !path.contains(".treeship/") {
        return false;
    }
    // Specific files
    if matches!(key, "session.json" | "session.closing") {
        return true;
    }
    // Subdirectories of .treeship that Treeship owns
    for prefix in &["sessions/", "artifacts/", "tmp/"] {
        if key.starts_with(prefix) {
            return true;
        }
    }
    // User-authored .treeship files we explicitly preserve. Listed for
    // documentation; they fall through to "false" below since none of the
    // earlier checks matched, but spelling them out keeps the rule
    // honest if someone adds a sweepier prefix above.
    let preserved = [
        "config.yaml", "config.json", "policy.yaml", "declaration.json",
        "agents/",     // user-approved Agent Cards
        "harnesses/",  // workspace harness state
    ];
    if preserved.iter().any(|p| key.starts_with(p)) {
        return false;
    }
    // Anything else under .treeship/ that we don't recognize stays
    // visible -- safer to over-show than to hide a file the user might
    // care about.
    false
}

fn source_label(file: &FileAccess) -> &'static str {
    match file.source.as_deref() {
        Some("hook")               => "hook",
        Some("mcp")                => "mcp",
        Some("git-reconcile")      => "git-reconcile",
        Some("shell-wrap")         => "shell-wrap",
        Some("session-event-cli")  => "session-event-cli",
        Some("daemon-atime")       => "daemon-atime",
        Some(_)                    => "unknown",
        None                       => "unknown",
    }
}

// ---------------------------------------------------------------------------
// treeship package inspect <path>
// ---------------------------------------------------------------------------

pub fn inspect(
    path: PathBuf,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = read_package(&path)?;

    let session = &receipt.session;
    let p = &receipt.participants;
    let se = &receipt.side_effects;

    printer.blank();
    printer.section("session receipt");
    printer.info(&format!("  type:       {}", receipt.type_));
    printer.info(&format!("  id:         {}", session.id));
    if let Some(ref name) = session.name {
        printer.info(&format!("  name:       {}", name));
    }
    printer.info(&format!("  mode:       {:?}", session.mode));
    printer.info(&format!("  status:     {:?}", session.status));
    printer.info(&format!("  started:    {}", session.started_at));
    if let Some(ref ended) = session.ended_at {
        printer.info(&format!("  ended:      {}", ended));
    }
    if let Some(ms) = session.duration_ms {
        printer.info(&format!("  duration:   {}ms", ms));
    }

    printer.blank();
    printer.section("participants");
    printer.info(&format!("  agents:     {}", p.total_agents));
    printer.info(&format!("  spawned:    {}", p.spawned_subagents));
    printer.info(&format!("  handoffs:   {}", p.handoffs));
    printer.info(&format!("  max depth:  {}", p.max_depth));
    printer.info(&format!("  hosts:      {}", p.hosts));
    if let Some(ref root) = p.root_agent_instance_id {
        printer.info(&format!("  root agent: {}", root));
    }

    if !receipt.agent_graph.nodes.is_empty() {
        printer.blank();
        printer.section("agent graph");
        for node in &receipt.agent_graph.nodes {
            let role = node.agent_role.as_deref().unwrap_or("--");
            let status = node.status.as_deref().unwrap_or("active");
            printer.info(&format!(
                "  {} ({}) depth={} tools={} [{}] @{}",
                node.agent_name, role, node.depth, node.tool_calls, status, node.host_id,
            ));
            // Model attribution -- only print when populated, so agents
            // without decision events stay one-line.
            if node.model.is_some() || node.tokens_in > 0 || node.tokens_out > 0 {
                let model = node.model.as_deref().unwrap_or("--");
                let provider = node.provider.as_deref().unwrap_or("--");
                printer.info(&format!(
                    "    model: {} | provider: {} | tokens: {}↓ {}↑",
                    model, provider, node.tokens_in, node.tokens_out,
                ));
            }
        }
    }

    printer.blank();
    printer.section("side effects");
    let summary = se.summary();
    printer.info(&format!("  files read:     {}", summary.files_read));
    printer.info(&format!("  files written:  {}", summary.files_written));
    printer.info(&format!("  tool calls:     {}", summary.tool_invocations));
    printer.info(&format!("  processes:      {}", summary.processes));
    printer.info(&format!("  ports opened:   {}", summary.ports_opened));
    printer.info(&format!("  network conns:  {}", summary.network_connections));

    // ---- files changed (with source badges, runtime artifacts filtered) ----
    print_files_changed(&se.files_written, &se.files_read, printer);

    // ---- workspace-local Agent Cards + Harness coverage ----
    //
    // These panels read from the workspace's .treeship/agents/ and
    // .treeship/harnesses/ stores via cards::list and harnesses::list_states.
    // No data fork: same modules `treeship agents` and `treeship harness`
    // already use. If the user is inspecting a package outside any
    // workspace (no config), we silently skip these panels rather than
    // erroring -- inspect must work on bare receipts that arrive in
    // someone's inbox.
    if let Ok(ctx_opened) = ctx::open(config) {
        print_agent_cards_panel(&ctx_opened.config_path, printer);
        print_harness_coverage_panel(&ctx_opened.config_path, printer);
    }

    printer.blank();
    printer.section("timeline");
    printer.info(&format!("  events: {}", receipt.timeline.len()));
    for entry in receipt.timeline.iter().take(20) {
        let detail = entry.summary.as_deref().unwrap_or("");
        printer.dim_info(&format!(
            "  {} {} {} {}",
            &entry.timestamp[11..19.min(entry.timestamp.len())],
            entry.event_type,
            entry.agent_name,
            detail,
        ));
    }
    if receipt.timeline.len() > 20 {
        printer.dim_info(&format!("  ... and {} more", receipt.timeline.len() - 20));
    }

    printer.blank();
    printer.section("merkle");
    printer.info(&format!("  leaves:  {}", receipt.merkle.leaf_count));
    if let Some(ref root) = receipt.merkle.root {
        printer.info(&format!("  root:    {}", root));
    }
    printer.info(&format!("  proofs:  {}", receipt.merkle.inclusion_proofs.len()));

    printer.blank();
    printer.section("artifacts");
    printer.info(&format!("  count: {}", receipt.artifacts.len()));
    for art in receipt.artifacts.iter().take(10) {
        let digest = art.digest.as_deref().unwrap_or("--");
        printer.dim_info(&format!("  {} ({}) {}", art.artifact_id, art.payload_type, digest));
    }
    if receipt.artifacts.len() > 10 {
        printer.dim_info(&format!("  ... and {} more", receipt.artifacts.len() - 10));
    }

    // Surface event-log incompleteness when present (Codex finding #8).
    // The receipt is still cryptographically valid, but it represents
    // fewer events than were appended to the log because some lines
    // failed to parse during close. Make that visible without burying
    // it in the proofs subtree.
    if receipt.proofs.event_log_skipped > 0 {
        printer.blank();
        printer.warn(
            &format!(
                "event log incomplete: {} skipped",
                receipt.proofs.event_log_skipped,
            ),
            &[(
                "what",
                "events.jsonl had lines that failed to parse during close",
            ), (
                "impact",
                "the receipt does not represent the full event stream",
            ), (
                "next",
                "inspect close-time stderr or events.jsonl to investigate",
            )],
        );
    }

    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// files changed panel
// ---------------------------------------------------------------------------

/// Render the files-changed list with source badges. Filters Treeship's
/// runtime artifacts (session.json, sessions/**, etc.) but preserves
/// user-authored .treeship trust files (config.yaml, agents/**, etc.).
///
/// "Hidden" rather than "removed" -- if the filter dropped anything, we
/// say so explicitly with a count, so a reader can't mistake a quiet
/// list for a complete one.
fn print_files_changed(
    written: &[FileAccess],
    read: &[FileAccess],
    printer: &Printer,
) {
    let (visible_w, hidden_w) = partition(written);
    let (visible_r, hidden_r) = partition(read);

    if visible_w.is_empty() && visible_r.is_empty() && hidden_w == 0 && hidden_r == 0 {
        return;
    }

    printer.blank();
    printer.section("files changed");

    if !visible_w.is_empty() {
        printer.dim_info(&format!("  written ({}):", visible_w.len()));
        // Cap at 30 paths so a churn-heavy session doesn't drown the
        // rest of the report; the count above is the honest total.
        for f in visible_w.iter().take(30) {
            let badge = source_label(f);
            let op = f.operation.as_deref().unwrap_or("write");
            printer.dim_info(&format!("    [{badge:<17}] {op:<8} {}", f.file_path));
        }
        if visible_w.len() > 30 {
            printer.dim_info(&format!("    ... and {} more", visible_w.len() - 30));
        }
    }
    if !visible_r.is_empty() {
        printer.dim_info(&format!("  read ({}):", visible_r.len()));
        for f in visible_r.iter().take(15) {
            let badge = source_label(f);
            printer.dim_info(&format!("    [{badge:<17}] read     {}", f.file_path));
        }
        if visible_r.len() > 15 {
            printer.dim_info(&format!("    ... and {} more", visible_r.len() - 15));
        }
    }
    if hidden_w > 0 || hidden_r > 0 {
        printer.dim_info(&format!(
            "  hidden: {} write, {} read (Treeship runtime artifacts under .treeship/)",
            hidden_w, hidden_r,
        ));
    }
}

fn partition(files: &[FileAccess]) -> (Vec<&FileAccess>, usize) {
    let mut visible = Vec::with_capacity(files.len());
    let mut hidden = 0usize;
    for f in files {
        if is_treeship_runtime_artifact(&f.file_path) {
            hidden += 1;
        } else {
            visible.push(f);
        }
    }
    (visible, hidden)
}

// ---------------------------------------------------------------------------
// agent cards panel
// ---------------------------------------------------------------------------

fn print_agent_cards_panel(config_path: &Path, printer: &Printer) {
    let agents_dir = cards::agents_dir_for(config_path);
    let cards_list = match cards::list(&agents_dir) {
        Ok(list) if !list.is_empty() => list,
        _ => return, // no cards in this workspace; nothing to render
    };

    printer.blank();
    printer.section(&format!("agent cards ({} in workspace)", cards_list.len()));
    for card in &cards_list {
        let mark = match card.status {
            cards::CardStatus::Verified    => "✓",
            cards::CardStatus::Active      => "✓",
            cards::CardStatus::NeedsReview => "?",
            cards::CardStatus::Draft       => "·",
        };
        let harness = card.active_harness_id.as_deref().unwrap_or("none");
        printer.info(&format!(
            "  {mark} {}  ({}, harness: {}, {})",
            card.agent_name,
            card.surface.kind(),
            harness,
            card.status.label(),
        ));
        if let Some(model) = &card.model {
            printer.dim_info(&format!("    model:    {model}"));
        }
        printer.dim_info(&format!("    host:     {}", card.host));
    }
}

// ---------------------------------------------------------------------------
// harness coverage panel
// ---------------------------------------------------------------------------

fn print_harness_coverage_panel(config_path: &Path, printer: &Printer) {
    let dir = harnesses::harnesses_dir_for(config_path);
    let states = match harnesses::list_states(&dir) {
        Ok(list) if !list.is_empty() => list,
        _ => return, // no harness state in this workspace
    };

    printer.blank();
    printer.section(&format!("harness coverage ({} attached)", states.len()));
    for state in &states {
        let manifest = harnesses::find(&state.harness_id);
        let display = manifest
            .map(|m| m.display_name)
            .unwrap_or(state.harness_id.as_str());
        printer.info(&format!(
            "  {}  ({}, coverage: {})",
            display,
            state.status.label(),
            state.coverage.label(),
        ));
        // Two distinct rows -- potential vs verified -- to honor the
        // trust-semantics tightening from PR 5's drift fix.
        if let Some(m) = manifest {
            let p = m.captures;
            printer.dim_info(&format!(
                "    potential: read={} write={} cmd={} mcp={} model={}",
                yes_or_no(p.files_read),
                yes_or_no(p.files_write),
                yes_or_no(p.commands_run),
                yes_or_no(p.mcp_call),
                yes_or_no(p.model_provider),
            ));
        }
        let v = state.verified_captures;
        if v.is_empty() {
            printer.dim_info("    verified:  (none yet -- run a real session through this harness)");
        } else {
            printer.dim_info(&format!(
                "    verified:  read={} write={} cmd={} mcp={} model={}",
                tri(v.files_read),
                tri(v.files_write),
                tri(v.commands_run),
                tri(v.mcp_call),
                tri(v.model_provider),
            ));
        }
        if let Some(smoke) = &state.last_smoke_result {
            printer.dim_info(&format!(
                "    last smoke ({}): {}",
                if smoke.passed { "pass" } else { "fail" },
                smoke.summary,
            ));
        }
        // Surface known gaps once so report readers see the honest
        // limits without having to inspect each harness separately.
        if !state.known_gaps.is_empty() {
            for gap in state.known_gaps.iter().take(2) {
                printer.dim_info(&format!("    gap: {}", gap));
            }
            if state.known_gaps.len() > 2 {
                printer.dim_info(&format!(
                    "    ... and {} more (run `treeship harness inspect {}`)",
                    state.known_gaps.len() - 2,
                    state.harness_id,
                ));
            }
        }
    }
}

fn yes_or_no(b: bool) -> &'static str { if b { "y" } else { "n" } }
fn tri(v: Option<bool>) -> &'static str {
    match v { Some(true) => "y", Some(false) => "no-fire", None => "?" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_artifacts_are_hidden() {
        // Files Treeship writes during capture must not pollute the
        // user's "files changed" list.
        for hidden in &[
            ".treeship/session.json",
            ".treeship/session.closing",
            ".treeship/sessions/ssn_abc.treeship",
            ".treeship/artifacts/foo.bin",
            ".treeship/tmp/scratch",
            "/abs/path/to/proj/.treeship/session.json",
            "../../.treeship/sessions/ssn_xyz.treeship",
        ] {
            assert!(
                is_treeship_runtime_artifact(hidden),
                "{hidden} should be filtered out"
            );
        }
    }

    #[test]
    fn user_authored_treeship_files_are_preserved() {
        // Trust files the user actually authors must remain visible
        // even though they live under .treeship/.
        for visible in &[
            ".treeship/config.yaml",
            ".treeship/config.json",
            ".treeship/policy.yaml",
            ".treeship/declaration.json",
            ".treeship/agents/agent_abc.json",
            ".treeship/harnesses/claude-code.json",
            "/abs/proj/.treeship/policy.yaml",
        ] {
            assert!(
                !is_treeship_runtime_artifact(visible),
                "{visible} must NOT be filtered out -- it's a user-authored trust file"
            );
        }
    }

    #[test]
    fn non_treeship_files_pass_through() {
        for path in &["src/main.rs", "README.md", "/etc/hosts", "package.json"] {
            assert!(
                !is_treeship_runtime_artifact(path),
                "{path} is not a Treeship file and must pass through"
            );
        }
    }

    #[test]
    fn unknown_treeship_subpath_stays_visible() {
        // If someone adds a new file under .treeship/ that we don't
        // explicitly classify, we err on the side of showing it. The
        // alternative -- silently filtering anything under .treeship/
        // -- would hide files the user might care about.
        assert!(!is_treeship_runtime_artifact(".treeship/something-new.json"));
    }

    #[test]
    fn source_label_maps_known_provenance() {
        for (input, want) in &[
            (Some("hook"),               "hook"),
            (Some("mcp"),                "mcp"),
            (Some("git-reconcile"),      "git-reconcile"),
            (Some("shell-wrap"),         "shell-wrap"),
            (Some("session-event-cli"),  "session-event-cli"),
            (Some("daemon-atime"),       "daemon-atime"),
            (Some("future-source"),      "unknown"),
            (None,                       "unknown"),
        ] {
            let f = FileAccess {
                file_path: "x".into(),
                agent_instance_id: "a".into(),
                timestamp: "t".into(),
                digest: None,
                operation: None,
                additions: None,
                deletions: None,
                source: input.map(|s| s.to_string()),
            };
            assert_eq!(source_label(&f), *want, "input {input:?}");
        }
    }
}

// ---------------------------------------------------------------------------
// treeship package verify <path>
// ---------------------------------------------------------------------------

pub fn verify(
    path: PathBuf,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let checks = verify_package(&path)?;

    let pass_count = checks.iter().filter(|c| c.status == VerifyStatus::Pass).count();
    let fail_count = checks.iter().filter(|c| c.status == VerifyStatus::Fail).count();
    let warn_count = checks.iter().filter(|c| c.status == VerifyStatus::Warn).count();

    printer.blank();
    printer.section("package verification");
    printer.info(&format!("  package: {}", path.display()));
    printer.blank();

    for check in &checks {
        let icon = match check.status {
            VerifyStatus::Pass => printer.green("PASS"),
            VerifyStatus::Fail => printer.red("FAIL"),
            VerifyStatus::Warn => printer.yellow("WARN"),
        };
        printer.info(&format!("  {} {} -- {}", icon, check.name, check.detail));
    }

    printer.blank();
    printer.info(&format!(
        "  {} passed, {} failed, {} warnings",
        pass_count, fail_count, warn_count,
    ));

    if fail_count > 0 {
        printer.blank();
        printer.warn("package verification failed", &[]);
    } else {
        printer.blank();
        printer.success("package verified", &[]);
    }

    printer.blank();

    Ok(())
}
