//! CLI commands for inspecting and verifying .treeship packages.

use std::path::{Path, PathBuf};

use treeship_core::session::{
    read_package, verify_package, ApprovalsBundle, FileAccess, SessionReceipt, VerifyStatus,
};
use treeship_core::statements::{ApprovalUse, ReplayCheckLevel};

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
        "config.yaml",
        "config.json",
        "policy.yaml",
        "declaration.json",
        "agents/",    // user-approved Agent Cards
        "harnesses/", // workspace harness state
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
        Some("hook") => "hook",
        Some("mcp") => "mcp",
        Some("git-reconcile") => "git-reconcile",
        Some("shell-wrap") => "shell-wrap",
        Some("session-event-cli") => "session-event-cli",
        Some("daemon-atime") => "daemon-atime",
        Some(_) => "unknown",
        None => "unknown",
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

    if printer.format == crate::printer::Format::Json {
        // The receipt as the package carries it, plus the side-effect
        // tally the text view prints. Panels that need workspace state
        // (cards, harness coverage, approvals) are not in this view.
        let summary = receipt.side_effects.summary();
        printer.json(&serde_json::json!({
            "path": path,
            "receipt": receipt,
            "side_effects_summary": {
                "files_read": summary.files_read,
                "files_written": summary.files_written,
                "tool_invocations": summary.tool_invocations,
                "processes": summary.processes,
                "ports_opened": summary.ports_opened,
                "network_connections": summary.network_connections,
            },
        }));
        return Ok(());
    }

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
    printer.info(&format!(
        "  network conns:  {}",
        summary.network_connections
    ));

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

    // Approval Authority panel + Decision Cards (v0.9.9 PR 5).
    // Reads from PR 4's read_approvals_bundle plus, when workspace
    // context is available, the local journal for the local-journal
    // replay level. Both pure functions; no schema fork.
    let approvals_bundle = treeship_core::session::read_approvals_bundle(&path).unwrap_or_default();
    let workspace_config_path = ctx::open(config).ok().map(|c| c.config_path);
    // Load the operator's trust roots once; the approval-authority and
    // replay-warning panels both pin embedded hub-org checkpoints
    // against it. Missing file is fine -- the panels render "not
    // trusted" rather than hiding the checkpoint.
    let trust = treeship_core::trust::TrustRootStore::open_default_or_empty()
        .unwrap_or_else(|_| treeship_core::trust::TrustRootStore::empty());
    print_approval_authority_panel(
        &approvals_bundle,
        workspace_config_path.as_deref(),
        &trust,
        printer,
    );
    print_decision_cards(&receipt, &approvals_bundle, &trust, printer);

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
    printer.info(&format!(
        "  proofs:  {}",
        receipt.merkle.inclusion_proofs.len()
    ));

    printer.blank();
    printer.section("artifacts");
    printer.info(&format!("  count: {}", receipt.artifacts.len()));
    for art in receipt.artifacts.iter().take(10) {
        let digest = art.digest.as_deref().unwrap_or("--");
        printer.dim_info(&format!(
            "  {} ({}) {}",
            art.artifact_id, art.payload_type, digest
        ));
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
            &[
                (
                    "what",
                    "events.jsonl had lines that failed to parse during close",
                ),
                (
                    "impact",
                    "the receipt does not represent the full event stream",
                ),
                (
                    "next",
                    "inspect close-time stderr or events.jsonl to investigate",
                ),
            ],
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
fn print_files_changed(written: &[FileAccess], read: &[FileAccess], printer: &Printer) {
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
            cards::CardStatus::Verified => "✓",
            cards::CardStatus::Active => "✓",
            cards::CardStatus::NeedsReview => "?",
            cards::CardStatus::Draft => "·",
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
            printer
                .dim_info("    verified:  (none yet -- run a real session through this harness)");
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

fn yes_or_no(b: bool) -> &'static str {
    if b {
        "y"
    } else {
        "n"
    }
}
fn tri(v: Option<bool>) -> &'static str {
    match v {
        Some(true) => "y",
        Some(false) => "no-fire",
        None => "?",
    }
}

// ---------------------------------------------------------------------------
// approval authority panel (v0.9.9 PR 5)
// ---------------------------------------------------------------------------

/// Render the Approval Authority panel for `treeship package inspect`.
///
/// Reads from PR 4's `ApprovalsBundle` (embedded in the package). When a
/// Treeship workspace is available at `workspace_config_path`, also
/// consults the local journal via `journal::find_use_for_action` for the
/// local-journal replay row -- same primitive PR 4's verify uses; no fork.
///
/// Honesty rule pinned by tests: no row says "global single-use" or
/// "hub-org passed" unless an actual signed Hub checkpoint is present.
/// PR 6 will land that scaffold; until then the hub-org row is reported
/// as "not checked" rather than absent or false-passing.
fn print_approval_authority_panel(
    bundle: &ApprovalsBundle,
    workspace_config_path: Option<&Path>,
    trust: &treeship_core::trust::TrustRootStore,
    printer: &Printer,
) {
    if bundle.uses.is_empty() && bundle.grants.is_empty() {
        return;
    }

    printer.blank();
    printer.section(&format!(
        "approval authority ({} use{} from {} grant{})",
        bundle.uses.len(),
        if bundle.uses.len() == 1 { "" } else { "s" },
        bundle.grants.len(),
        if bundle.grants.len() == 1 { "" } else { "s" },
    ));

    // Resolve grant envelopes once. The grants vec carries
    // (grant_id, raw_envelope_json); decode each so the panel can
    // surface approver / scope without callers walking storage.
    use std::collections::HashMap;
    let mut grants_by_id: HashMap<String, treeship_core::statements::ApprovalStatement> =
        HashMap::new();
    for (grant_id, env_bytes) in &bundle.grants {
        if let Ok(env) = serde_json::from_slice::<treeship_core::attestation::Envelope>(env_bytes) {
            if let Ok(approval) =
                env.unmarshal_statement::<treeship_core::statements::ApprovalStatement>()
            {
                grants_by_id.insert(grant_id.clone(), approval);
            }
        }
    }

    // For the local-journal row we need a Journal handle. Optional --
    // bare-package inspection in someone's inbox skips this row.
    let journal_opt = workspace_config_path.map(|cp| {
        let dir = cp
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("journals")
            .join("approval-use");
        treeship_core::journal::Journal::new(dir)
    });

    // Index uses by grant_id so each grant gets one summary card with
    // its uses underneath, instead of repeating the grant header per use.
    let mut uses_by_grant: HashMap<String, Vec<&ApprovalUse>> = HashMap::new();
    for u in &bundle.uses {
        uses_by_grant.entry(u.grant_id.clone()).or_default().push(u);
    }

    // Stable display order: by grant_id ascending. Uses inside a grant
    // already in journal append order (use_number).
    let mut grant_ids: Vec<&String> = uses_by_grant.keys().collect();
    grant_ids.sort();

    for grant_id in grant_ids {
        let uses = &uses_by_grant[grant_id];
        let grant = grants_by_id.get(grant_id);

        printer.blank();
        // Header line: approver -> actor on action.subject
        match grant {
            Some(g) => {
                let actor_label = uses
                    .first()
                    .map(|u| u.actor.as_str())
                    .unwrap_or("agent://?");
                let action_label = uses.first().map(|u| u.action.as_str()).unwrap_or("?");
                printer.info(&format!(
                    "  {} approved {}  ({})",
                    g.approver, actor_label, action_label,
                ));
            }
            None => {
                printer.info(&format!("  grant {grant_id}  (envelope not in package)"));
            }
        }

        // Subject + scope summary
        if let Some(g) = grant {
            if let Some(scope) = &g.scope {
                let max_label = scope
                    .max_actions
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "unbounded".into());
                let subj = uses
                    .first()
                    .map(|u| u.subject.as_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("(none)");
                printer.dim_info(&format!("    grant_id:    {grant_id}"));
                printer.dim_info(&format!(
                    "    subject:     {subj}      max_uses: {max_label}      uses recorded: {}",
                    uses.len(),
                ));
            } else {
                printer.dim_info(&format!("    grant_id:    {grant_id}  (unscoped)"));
            }
        }

        for u in uses {
            printer.dim_info(&format!(
                "    use {}/{}  use_id={}",
                u.use_number,
                u.max_uses
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "?".into()),
                u.use_id,
            ));
        }

        // Replay levels -- exactly four rows. Honest about what was
        // checked vs not checked. Hub-org never reports "passed"
        // here; it reports "not checked" until PR 6's scaffold (and
        // even then, only when a Hub checkpoint is present).
        let nonce_dig = uses
            .first()
            .map(|u| u.nonce_digest.clone())
            .unwrap_or_default();

        // package-local: re-derive from the bundle directly. The check
        // PR 4's verifier emits is per-package; in the panel we
        // restate it briefly.
        let package_local_pass = {
            let count = uses.len() as u32;
            let max = uses.iter().filter_map(|u| u.max_uses).next();
            match max {
                Some(m) => count <= m,
                None => true,
            }
        };
        printer.dim_info(&format!(
            "    {} package-local        {}",
            if package_local_pass { "✓" } else { "✗" },
            if package_local_pass {
                "no duplicate use inside package"
            } else {
                "duplicate use exceeds max_uses"
            },
        ));

        // local-journal: if we have a workspace journal, ask
        // find_use_for_action whether the recorded use is within
        // bounds. If we don't, say so.
        match journal_opt.as_ref().filter(|j| j.exists()) {
            Some(j) => {
                let max_uses = grant
                    .and_then(|g| g.scope.as_ref())
                    .and_then(|s| s.max_actions);
                match treeship_core::journal::find_use_for_action(
                    j,
                    grant_id,
                    &nonce_dig,
                    max_uses,
                    // The inspect panel summarises a grant, not one action:
                    // the latest use record answers "within max_uses".
                    uses.first().and_then(|u| u.action_artifact_id.as_deref()),
                ) {
                    Ok(Some((_rec, replay))) => {
                        let mark = match replay.passed {
                            Some(false) => "✗",
                            _ => "✓",
                        };
                        let detail = replay
                            .details
                            .clone()
                            .unwrap_or_else(|| "local Approval Use Journal consulted".into());
                        printer.dim_info(&format!("    {mark} local-journal        {detail}"));
                    }
                    Ok(None) => {
                        printer
                            .dim_info("    - local-journal        not present in this workspace");
                    }
                    Err(e) => {
                        printer.dim_info(&format!("    ✗ local-journal        error: {e}"));
                    }
                }
            }
            None => {
                printer.dim_info(
                    "    - local-journal        no Treeship workspace at this config path",
                );
            }
        }

        // included-checkpoint: any embedded JournalCheckpoint? We
        // don't pin which checkpoint covers which use here -- the
        // panel just reports "checkpoints present and verify offline."
        if bundle.checkpoints.is_empty() {
            printer
                .dim_info("    - included-checkpoint  no journal checkpoint included in package");
        } else {
            // Reuse the integrity recompute helper indirectly: if the
            // verifier already gave us a pass row, we trust that.
            // For the panel, just acknowledge presence and let
            // `package verify` carry the actual chain check.
            printer.dim_info(&format!(
                "    ✓ included-checkpoint  {} embedded checkpoint(s)",
                bundle.checkpoints.len(),
            ));
        }

        // hub-org: v0.9.9 PR 6 wires the consumer side. The release
        // rule is non-negotiable -- PASS only when an embedded Hub
        // checkpoint declares kind=hub-org, every required field is
        // populated, signature verifies, AND the checkpoint covers
        // this use_id via covered_use_ids. Otherwise: "not checked"
        // (when no hub-org checkpoint is in the package) or "✗"
        // (when one is present but a gate failed).
        let hub_cps: Vec<&treeship_core::statements::JournalCheckpoint> = bundle
            .checkpoints
            .iter()
            .filter(|cp| cp.checkpoint_kind == treeship_core::statements::CheckpointKind::HubOrg)
            .collect();
        if hub_cps.is_empty() {
            printer
                .dim_info("    - hub-org              not checked (no Hub checkpoint in package)");
        } else {
            // For each use, check whether SOME hub-org checkpoint
            // verifies AND covers this use_id. The strongest finding
            // wins per use.
            let mut all_uses_covered = true;
            let mut summary: Vec<String> = Vec::new();
            for u in uses.iter() {
                let mut this_use_ok = false;
                let mut this_use_detail: Option<String> = None;
                for cp in &hub_cps {
                    match treeship_core::statements::verify_hub_checkpoint_signature(cp, trust) {
                        treeship_core::statements::HubCheckpointVerification::Valid => {
                            if cp.covered_use_ids.iter().any(|id| id == &u.use_id) {
                                this_use_ok = true;
                                this_use_detail =
                                    Some(format!("use {} signed by {}", u.use_id, cp.hub_id,));
                                break;
                            } else {
                                this_use_detail = Some(format!(
                                    "use {} not covered by {}",
                                    u.use_id, cp.checkpoint_id,
                                ));
                            }
                        }
                        treeship_core::statements::HubCheckpointVerification::MissingFields(f) => {
                            this_use_detail =
                                Some(format!("{} missing field {}", cp.checkpoint_id, f,));
                        }
                        treeship_core::statements::HubCheckpointVerification::Tampered => {
                            this_use_detail =
                                Some(format!("{} hub signature failed", cp.checkpoint_id,));
                        }
                        treeship_core::statements::HubCheckpointVerification::UntrustedIssuer => {
                            this_use_detail = Some(format!(
                                "{} hub_public_key not in trust roots (run `treeship trust add`)",
                                cp.checkpoint_id,
                            ));
                        }
                        treeship_core::statements::HubCheckpointVerification::NotHubKind => {}
                    }
                }
                if !this_use_ok {
                    all_uses_covered = false;
                }
                if let Some(d) = this_use_detail {
                    summary.push(d);
                }
            }
            let mark = if all_uses_covered { "✓" } else { "✗" };
            let detail = if summary.is_empty() {
                "no hub-signed coverage found".into()
            } else {
                summary.join("; ")
            };
            printer.dim_info(&format!("    {mark} hub-org              {detail}"));
        }

        let _ = ReplayCheckLevel::HubOrg;
    }

    // v0.9.10 PR A: bundle-level integrity rows. Render once per
    // package after the per-use replay rows. Each is computed inline
    // from the bundle so the panel stays self-contained even when the
    // verify checks haven't been threaded through.
    if !bundle.uses.is_empty() {
        use treeship_core::statements::approval_use_record_digest;
        let tampered_digest = bundle
            .uses
            .iter()
            .any(|u| approval_use_record_digest(u) != u.record_digest);
        printer.dim_info(&format!(
            "  {} approval-use-record-digest    {}",
            if tampered_digest { "✗" } else { "✓" },
            if tampered_digest {
                "one or more use records tampered post-write"
            } else {
                "every use record's stored digest recomputes identically"
            },
        ));

        // Nonce binding: each use's nonce_digest must equal
        // nonce_digest(grant.nonce) for the grant carried in the
        // package. If the grant is missing from the bundle, the row
        // reports the gap honestly.
        use treeship_core::attestation::envelope::Envelope;
        use treeship_core::statements::{nonce_digest, ApprovalStatement};
        let mut grant_nonce_digest: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for (gid, env_bytes) in &bundle.grants {
            if let Ok(env) = Envelope::from_json(env_bytes) {
                if let Ok(g) = env.unmarshal_statement::<ApprovalStatement>() {
                    grant_nonce_digest.insert(gid.clone(), nonce_digest(&g.nonce));
                }
            }
        }
        let nonce_ok = bundle
            .uses
            .iter()
            .all(|u| grant_nonce_digest.get(&u.grant_id) == Some(&u.nonce_digest));
        printer.dim_info(&format!(
            "  {} approval-use-nonce-binding    {}",
            if nonce_ok { "✓" } else { "✗" },
            if nonce_ok {
                "use.nonce_digest == sha256(grant.nonce) for every use"
            } else {
                "one or more uses do not bind to a grant signed nonce"
            },
        ));

        // Action binding row: empty action_envelopes -> "not asserted"
        // (pre-v0.9.10 packages); otherwise pass/fail based on the
        // approval_use_id pointer + nonce match.
        if bundle.action_envelopes.is_empty() {
            printer.dim_info(
                "  - approval-use-action-binding  not asserted by package (pre-v0.9.10 -- artifacts/ empty)",
            );
        } else {
            use treeship_core::statements::ActionStatement;
            let use_ids: std::collections::HashSet<&str> =
                bundle.uses.iter().map(|u| u.use_id.as_str()).collect();
            let mut all_ok = true;
            let mut bound = 0usize;
            for (_aid, env_bytes) in &bundle.action_envelopes {
                let Ok(env) = Envelope::from_json(env_bytes) else {
                    all_ok = false;
                    continue;
                };
                let Ok(action) = env.unmarshal_statement::<ActionStatement>() else {
                    all_ok = false;
                    continue;
                };
                let Some(raw_nonce) = action.approval_nonce.as_deref() else {
                    continue;
                };
                let claimed = action
                    .meta
                    .as_ref()
                    .and_then(|m| m.get("approval_use_id"))
                    .and_then(|v| v.as_str());
                match claimed {
                    Some(uid) if use_ids.contains(uid) => {
                        let expected = nonce_digest(raw_nonce);
                        let matched = bundle.uses.iter().find(|u| u.use_id == uid);
                        if matched.is_some_and(|u| u.nonce_digest == expected) {
                            bound += 1;
                        } else {
                            all_ok = false;
                        }
                    }
                    _ => all_ok = false,
                }
            }
            printer.dim_info(&format!(
                "  {} approval-use-action-binding  {}",
                if all_ok { "✓" } else { "✗" },
                if all_ok {
                    format!("{bound} action(s) bind cleanly to embedded use records")
                } else {
                    "one or more actions fail action↔use binding".into()
                },
            ));
        }

        // Chain continuity: every previous_record_digest must point at
        // an in-package record_digest or be empty (genesis).
        let mut owned: std::collections::HashSet<String> = std::collections::HashSet::new();
        owned.insert(String::new());
        for u in &bundle.uses {
            owned.insert(u.record_digest.clone());
        }
        for cp in &bundle.checkpoints {
            owned.insert(cp.record_digest.clone());
        }
        let chain_ok = bundle
            .uses
            .iter()
            .all(|u| owned.contains(&u.previous_record_digest))
            && bundle
                .checkpoints
                .iter()
                .all(|cp| owned.contains(&cp.previous_record_digest));
        printer.dim_info(&format!(
            "  {} approval-use-chain-continuity {}",
            if chain_ok { "✓" } else { "✗" },
            if chain_ok {
                "every previous_record_digest anchors in-package or genesis"
            } else {
                "one or more previous_record_digest values dangle"
            },
        ));
    }

    printer.blank();
}

// ---------------------------------------------------------------------------
// Decision Cards v0 (v0.9.9 PR 5)
// ---------------------------------------------------------------------------

/// Render Decision Cards from receipt evidence. Every card carries
/// evidence pointers (artifact_ids, grant_ids, use_ids, receipt digest,
/// verify check rows). No LLM, no invented intent. The narrative text
/// is generated mechanically from the evidence; if there's nothing to
/// say, the card doesn't appear.
///
/// v0 cards (this PR):
///   1. Approval card -- one per grant with at least one use
///   2. Replay-warning card -- when only package-local replay is
///      available (no journal, no checkpoint, no Hub)
///   3. Verification-warning card -- when receipt.proofs reports
///      skipped events
fn print_decision_cards(
    receipt: &SessionReceipt,
    bundle: &ApprovalsBundle,
    trust: &treeship_core::trust::TrustRootStore,
    printer: &Printer,
) {
    use std::collections::HashSet;

    let mut cards_emitted = 0usize;

    // Approval cards: one per grant with uses.
    let mut grants_seen: HashSet<&str> = HashSet::new();
    let approval_cards: Vec<&ApprovalUse> = bundle
        .uses
        .iter()
        .filter(|u| grants_seen.insert(u.grant_id.as_str()))
        .collect();

    if approval_cards.is_empty() && receipt.proofs.event_log_skipped == 0 && bundle.uses.is_empty()
    {
        // Nothing to say -- omit the section entirely.
        return;
    }

    printer.blank();
    printer.section("key decisions");

    for u in &approval_cards {
        let grant_uses: Vec<&ApprovalUse> = bundle
            .uses
            .iter()
            .filter(|x| x.grant_id == u.grant_id)
            .collect();
        let count = grant_uses.len() as u32;
        let max = u.max_uses;

        printer.blank();
        printer.info(&format!(
            "  ▸ Approval consumed: {} on {}",
            u.action, u.subject
        ));
        printer.dim_info(&format!(
            "      {} use(s) recorded against grant {} (max_uses={})",
            count,
            u.grant_id,
            max.map(|m| m.to_string())
                .unwrap_or_else(|| "unbounded".into()),
        ));
        printer.dim_info("      evidence:");
        printer.dim_info(&format!("        grant_id:        {}", u.grant_id));
        printer.dim_info(&format!("        approval_use_id: {}", u.use_id));
        if let Some(aid) = &u.action_artifact_id {
            printer.dim_info(&format!("        action_id:       {}", aid));
        }
        for sib in &grant_uses[1..] {
            printer.dim_info(&format!("        sibling use:     {}", sib.use_id));
        }
        cards_emitted += 1;
    }

    // Replay-warning card. Trigger: at least one approval use exists
    // AND no Hub-signed checkpoint that covers every use is present.
    // Local-journal-only is still a warning here (the v0.9.9 PR 6
    // honesty rule: "global single-use" requires verified Hub
    // coverage). When such coverage IS present, the card stays
    // silent -- the Approval Authority panel already shows the
    // happy ✓ row, no need to repeat.
    let has_hub_coverage = bundle
        .checkpoints
        .iter()
        .filter(|cp| cp.checkpoint_kind == treeship_core::statements::CheckpointKind::HubOrg)
        .any(|cp| {
            // Must verify AND cover every use.
            matches!(
                treeship_core::statements::verify_hub_checkpoint_signature(cp, trust),
                treeship_core::statements::HubCheckpointVerification::Valid,
            ) && bundle
                .uses
                .iter()
                .all(|u| cp.covered_use_ids.iter().any(|id| id == &u.use_id))
        });
    if !bundle.uses.is_empty() && !has_hub_coverage {
        printer.blank();
        printer.info("  ⚠ Replay posture: no verified Hub coverage");
        printer.dim_info("      Verifiers without access to your workspace's local journal can");
        printer.dim_info(
            "      only check package-local replay (duplicate uses inside this package).",
        );
        printer.dim_info("      Hub-org replay is not asserted -- a global single-use guarantee");
        printer.dim_info("      requires a signed Hub checkpoint that covers every use_id in this");
        printer.dim_info("      package. v0.9.9 supports verifying such checkpoints when present;");
        printer.dim_info("      the Hub signer itself is out of scope for this release.");
        printer.dim_info("      evidence:");
        printer.dim_info(&format!(
            "        approval uses:   {} (see approval authority panel above)",
            bundle.uses.len(),
        ));
        printer.dim_info(&format!(
                "        hub checkpoints: {} embedded ({})",
                bundle
                    .checkpoints
                    .iter()
                    .filter(|cp| cp.checkpoint_kind
                        == treeship_core::statements::CheckpointKind::HubOrg)
                    .count(),
                if bundle
                    .checkpoints
                    .iter()
                    .any(|cp| cp.checkpoint_kind
                        == treeship_core::statements::CheckpointKind::HubOrg)
                {
                    "see hub-org row above for per-checkpoint detail"
                } else {
                    "none"
                },
            ));
        printer.dim_info("        verify rows:     replay-package-local, replay-local-journal");
        cards_emitted += 1;
    }

    // Verification-warning card: skipped events, broken chain, etc.
    // The receipt already exposes event_log_skipped; tampered uses /
    // broken checkpoints are surfaced by `package verify` and don't
    // round-trip into the receipt itself, so we link to `verify`
    // there.
    if receipt.proofs.event_log_skipped > 0 {
        printer.blank();
        printer.info(&format!(
            "  ⚠ Verification posture: {} event(s) skipped during close",
            receipt.proofs.event_log_skipped,
        ));
        printer
            .dim_info("      Treeship dropped malformed lines from events.jsonl when sealing the");
        printer.dim_info(
            "      receipt. The receipt is cryptographically valid but does not represent",
        );
        printer.dim_info("      the full event stream.");
        printer.dim_info("      evidence:");
        printer.dim_info(&format!(
            "        receipt.proofs.event_log_skipped: {}",
            receipt.proofs.event_log_skipped,
        ));
        printer.dim_info("        next: inspect close-time stderr or events.jsonl directly");
        cards_emitted += 1;
    }

    if cards_emitted == 0 {
        // We printed the section header above; soften it.
        printer.dim_info("  no decisions to surface from this package");
    }

    printer.blank();
}

// ---------------------------------------------------------------------------
// treeship package verify <path>
// ---------------------------------------------------------------------------

/// The operator's pinned trust roots plus this ship's own signing keys, as
/// `session_host` roots. A package verified where it was produced must not
/// warn that the producer has not pinned itself; the same package on a
/// stranger's machine warns until they pin, which is the point.
pub fn trust_with_own_keys(
    ctx: &ctx::Ctx,
) -> Result<treeship_core::trust::TrustRootStore, Box<dyn std::error::Error>> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use treeship_core::trust::{TrustRoot, TrustRootKind, TrustRootStore};
    let mut trust = TrustRootStore::open_default_or_empty()?;
    for key in ctx.keys.list()? {
        // Skip only a root that is this very key (same id AND same public
        // key). A root that reuses an own key id for a different key is not
        // this ship's key; adding ours alongside it lets key_id_collision
        // catch the clash instead of our own key silently disappearing.
        let own_pub = format!("ed25519:{}", URL_SAFE_NO_PAD.encode(&key.public_key));
        if trust
            .roots()
            .iter()
            .any(|r| r.key_id == key.id && r.public_key == own_pub)
        {
            continue;
        }
        trust.add(TrustRoot {
            key_id: key.id.clone(),
            public_key: format!("ed25519:{}", URL_SAFE_NO_PAD.encode(&key.public_key)),
            kind: TrustRootKind::SessionHost,
            agent: None,
            label: treeship_core::session::package::OWN_KEY_LABEL.into(),
            added_at: crate::commands::session::now_rfc3339(),
        });
    }
    Ok(trust)
}

/// Verify a package the way `package verify` does by default (no --strict,
/// no --structural): this ship's own keys and the pinned roots are trusted.
/// Every other surface that shows a package verdict -- `treeship verify
/// <package>`, the dashboard, `session report` -- goes through this, so the
/// four never disagree about a package.
pub fn default_verdict(
    path: &Path,
    config: Option<&str>,
) -> Result<
    (
        Vec<treeship_core::session::VerifyCheck>,
        treeship_core::session::PackageVerdict,
    ),
    Box<dyn std::error::Error>,
> {
    let checks = match ctx::open(config)
        .ok()
        .and_then(|c| trust_with_own_keys(&c).ok())
    {
        Some(trust) => treeship_core::session::verify_package_with_options(path, &trust, false)?,
        None => verify_package(path)?,
    };
    let verdict = treeship_core::session::package_verdict(&checks, false);
    Ok((checks, verdict))
}

pub fn verify(
    path: PathBuf,
    config: Option<&str>,
    strict: bool,
    structural_only: bool,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx_opened = ctx::open(config).ok();
    let mut checks = if let (true, Some(ctx)) = (structural_only, ctx_opened.as_ref()) {
        // --structural judges trust with the same roots as a full verify,
        // this ship's own keys included, so a package reusing one of our key
        // ids is caught (key_id_collision) here too.
        let trust = trust_with_own_keys(ctx)?;
        treeship_core::session::verify_package_with_options(&path, &trust, true)?
    } else if structural_only {
        treeship_core::session::verify_package_structural(&path)?
    } else if let Some(ctx) = ctx_opened.as_ref() {
        // On the producer's own machine, its own signing keys are trusted by
        // definition; only a stranger has to decide whether to pin them.
        let trust = trust_with_own_keys(ctx)?;
        treeship_core::session::verify_package_with_options(&path, &trust, false)?
    } else {
        verify_package(&path)?
    };

    // v0.9.9 PR 4: layer the local-journal replay level on top of the
    // package-local + included-checkpoint checks core::session::package
    // already emits. The journal lookup needs workspace context; when
    // there's no Treeship workspace at all we skip the check rather
    // than failing -- offline / inbox verification of a bare package
    // must keep working.
    if let Some(ctx_opened) = ctx_opened {
        let journal = treeship_core::journal::Journal::new(ctx_opened.journal_dir()?);
        let bundle = treeship_core::session::read_approvals_bundle(&path).unwrap_or_default();
        // The journal is the producer's own control: only the ship whose
        // key signed this package's close record can hold it (W1-13). The
        // approver's ship signed an approval inside the package, not the
        // session, and has no journal for it; anywhere but the producer the
        // row is not applicable, and says what was checked instead. It is
        // not a replay-* row, so --strict does not promote it.
        let own_keys: Vec<ed25519_dalek::VerifyingKey> = ctx_opened
            .keys
            .list()
            .unwrap_or_default()
            .iter()
            .filter_map(|k| {
                let bytes: [u8; 32] = k.public_key.as_slice().try_into().ok()?;
                ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
            })
            .collect();
        let produced_here =
            !structural_only && treeship_core::session::package_close_signed_by(&path, &own_keys);
        if !bundle.uses.is_empty() && !produced_here {
            checks.push(treeship_core::session::VerifyCheck::warn(
                "local_journal",
                "not applicable here: the Approval Use Journal is the producer's, on the machine that signed this package. Checked instead: duplicate uses inside the package (replay-package-local), use-record digests, nonce and action binding, chain continuity, and any included checkpoint or hub-org evidence",
            ));
        } else if !bundle.uses.is_empty() {
            if !journal.exists() {
                checks.push(treeship_core::session::VerifyCheck::warn(
                    "replay-local-journal",
                    "no local Approval Use Journal in this workspace; package-local replay only",
                ));
            } else {
                let mut detail_parts: Vec<String> = Vec::new();
                let mut all_pass = true;
                for u in &bundle.uses {
                    match treeship_core::journal::find_use_for_action(
                        &journal,
                        &u.grant_id,
                        &u.nonce_digest,
                        u.max_uses,
                        u.action_artifact_id.as_deref(),
                    ) {
                        Ok(Some((_rec, replay))) => {
                            if matches!(replay.passed, Some(false)) {
                                all_pass = false;
                                detail_parts.push(format!("use {} exceeds max_uses", u.use_id,));
                            } else if let Some(d) = replay.details {
                                detail_parts.push(d);
                            }
                        }
                        Ok(None) => {
                            // Journal exists but has no record for
                            // this nonce. Could be a different
                            // workspace's package; warn rather than
                            // fail.
                            detail_parts.push(format!(
                                "use {} not present in this workspace's journal",
                                u.use_id,
                            ));
                        }
                        Err(e) => {
                            all_pass = false;
                            detail_parts.push(format!("journal error: {e}"));
                        }
                    }
                }
                let combined = detail_parts.join("; ");
                checks.push(if all_pass {
                    treeship_core::session::VerifyCheck::pass(
                        "replay-local-journal",
                        if combined.is_empty() {
                            "local Approval Use Journal consulted".into()
                        } else {
                            combined.clone()
                        }
                        .as_str(),
                    )
                } else {
                    treeship_core::session::VerifyCheck::fail("replay-local-journal", &combined)
                });
            }
        }
    }

    let pass_count = checks
        .iter()
        .filter(|c| c.status == VerifyStatus::Pass)
        .count();
    let mut fail_count = checks
        .iter()
        .filter(|c| c.status == VerifyStatus::Fail)
        .count();
    let mut warn_count = checks
        .iter()
        .filter(|c| c.status == VerifyStatus::Warn)
        .count();

    // --strict promotes warnings touching approval evidence to
    // failures. Existing receipt-determinism / event-log warnings
    // stay warnings; only the approval rows are promoted, since the
    // release rule is "strict mode fails on duplicate use, tampered
    // record, broken checkpoint chain."
    if strict {
        let mut promoted = 0usize;
        for c in checks.iter_mut() {
            // Approval-evidence rows: every replay-* row plus the
            // four binding/integrity rows from v0.9.10 PR A. The old
            // `approval-use-integrity` label is kept here for backward
            // compatibility with any external tooling that pinned on
            // it, but the live emitter now uses
            // `approval-use-record-digest`.
            let approval_row = c.name.starts_with("replay-")
                || c.name == "signer_trust"
                // Audit follow-up AUD-34: under --strict a loose artifact, a
                // package without its close record, or an artifact signed
                // outside the session window is a failure, not a note.
                || c.name == "chain_completeness"
                // An approval signed by an approver key nobody pinned.
                || c.name == "approval_signer"
                // CLI-1: an endorsement made by 0.31.9 or earlier signs no
                // parent; chain_linkage warns, and strict cannot count it.
                || c.name == "chain_linkage"
                || c.name == "receipt_binding"
                || c.name == "session_window"
                || c.name == "approval-use-integrity"
                || c.name == "approval-use-record-digest"
                || c.name == "approval-use-nonce-binding"
                || c.name == "approval-use-action-binding"
                || c.name == "approval-use-chain-continuity"
                || c.name == "approval-use-limit";
            if approval_row && c.status == VerifyStatus::Warn {
                c.status = VerifyStatus::Fail;
                promoted += 1;
            }
        }
        warn_count -= promoted;
        fail_count += promoted;
    }

    printer.blank();
    printer.section("package verification");
    printer.info(&format!("  package: {}", path.display()));
    if strict {
        printer.dim_info(
            "  --strict: approval-evidence and unpinned-signer warnings promoted to failures",
        );
    }
    if structural_only {
        printer.dim_info("  --structural: structure and approvals checked; signatures are NOT");
    }
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

    // The verdict word. `verified` is reserved for a package whose every
    // signature verifies under a key the verifier has pinned; when the keys
    // are not pinned here the signatures still verify, and the word for that
    // is `signatures-pass` (audit follow-up AUD-35: the previous line said
    // "package verified" for an unknown signer, exit 0, and the JSON carried
    // no rows at all).
    //
    // The word comes from treeship_core::session::package_verdict, which
    // needs rows that PASSED (a signature, receipt_binding, a signer_trust
    // row), not merely no row that failed: an empty package used to read
    // `verified` because nothing had failed.
    let signer_unpinned = !checks
        .iter()
        .any(|c| c.name == "signer_trust" && c.status == VerifyStatus::Pass);
    let pv = treeship_core::session::package_verdict(&checks, structural_only);
    let failed_message;
    let (verdict, status, message) = match &pv {
        treeship_core::session::PackageVerdict::Failed(reason) => {
            failed_message = format!("package verification failed ({reason})");
            ("failed", "error", failed_message.as_str())
        }
        treeship_core::session::PackageVerdict::StructuralPass => (
            "structural-pass",
            "warning",
            "structural-pass: structure and approvals verified, signatures not checked",
        ),
        treeship_core::session::PackageVerdict::SignaturesPass => (
            "signatures-pass",
            "warning",
            "signatures-pass: every signature verifies, but no signing key is pinned here; pin the producer's key for `verified`",
        ),
        treeship_core::session::PackageVerdict::VerifiedPartial => (
            "verified-partial",
            "warning",
            "verified-partial: everything disclosed verifies, and the producer withheld at least one artifact under a signed redaction. You are holding part of a trace",
        ),
        treeship_core::session::PackageVerdict::Verified => ("verified", "ok", "package verified"),
    };

    if printer.format == crate::printer::Format::Json {
        let rows: Vec<serde_json::Value> = checks
            .iter()
            .map(|c| {
                serde_json::json!({
                    "name": c.name,
                    "status": match c.status {
                        VerifyStatus::Pass => "pass",
                        VerifyStatus::Warn => "warn",
                        VerifyStatus::Fail => "fail",
                    },
                    "detail": c.detail,
                })
            })
            .collect();
        printer.json(&serde_json::json!({
            "status": status,
            "verdict": verdict,
            "message": message,
            "package": path.display().to_string(),
            "passed": pass_count,
            "failed": fail_count,
            "warnings": warn_count,
            "signer_pinned": !signer_unpinned,
            "checks": rows,
        }));
        if verdict == "failed" {
            return Err("package verification failed".into());
        }
        return Ok(());
    }

    printer.blank();
    if verdict == "failed" {
        printer.warn(message, &[]);
        return Err("package verification failed".into());
    }
    printer.success(message, &[]);

    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// package redact -- a copy with chosen steps withheld
// ---------------------------------------------------------------------------

/// Write a copy of `pkg` into `out` with `withhold` steps withheld.
///
/// Three things leave the copy for each withheld artifact: its signed
/// envelope, its timeline entries, and its recorded process executions. The
/// third matters most. The envelope carries the argv and the digests, but the
/// receipt's own `side_effects.processes` carries the command, so withholding
/// the envelope alone would have hidden the proof and left the thing being
/// proved sitting in the clear. Those entries are found by the `artifact_id`
/// they carry, not by matching timestamps or names, because a redaction that
/// silently misses an entry is worse than none: it tells someone their data
/// is gone when it is not.
///
/// The original close record is kept rather than re-signed. It still proves
/// what the producer sealed at close, and the redaction, signed by the same
/// producer, proves this view was derived from it. Re-signing would have
/// replaced a provable original with a fresh signature over edited content,
/// which proves only that someone with a key edited something.
pub fn redact(
    pkg: PathBuf,
    out: PathBuf,
    withhold: &[String],
    reason: Option<&str>,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    use treeship_core::session::{RedactionPayload, WithheldArtifact};
    use treeship_core::statements::{payload_type, ReceiptStatement};

    let ctx = ctx::open(config)?;

    let receipt_path = pkg.join("receipt.json");
    let raw = std::fs::read(&receipt_path)
        .map_err(|e| crate::exit::usage(format!("{}: {e}", receipt_path.display())))?;
    let source_digest = format!("sha256:{}", hex::encode(Sha256::digest(&raw)));
    let mut receipt: SessionReceipt = serde_json::from_slice(&raw)
        .map_err(|e| crate::exit::usage(format!("receipt.json does not parse: {e}")))?;

    // Every id must be in this package. A typo would otherwise produce a
    // redaction that names nothing and a copy that withholds nothing, while
    // reading as though it had.
    let sealed: std::collections::BTreeSet<&str> = receipt
        .artifacts
        .iter()
        .map(|a| a.artifact_id.as_str())
        .collect();
    for id in withhold {
        if !sealed.contains(id.as_str()) {
            return Err(crate::exit::usage(format!(
                "{id} is not sealed in this package; nothing would be withheld"
            )));
        }
    }
    let drop: std::collections::BTreeSet<&str> = withhold.iter().map(|s| s.as_str()).collect();

    // Copy first, then take things out of the copy, so a failure part way
    // through never damages the original.
    if out.exists() {
        return Err(crate::exit::usage(format!(
            "{} already exists; choose a path that does not",
            out.display()
        )));
    }
    crate::commands::session::copy_dir_all(&pkg, &out)?;

    // The parent each withheld step claimed, read before its envelope goes.
    let mut withheld_entries: Vec<WithheldArtifact> = Vec::new();
    for id in withhold {
        let env_path = out.join("artifacts").join(format!("{id}.json"));
        let parent_id = std::fs::read(&env_path)
            .ok()
            .and_then(|b| treeship_core::attestation::Envelope::from_json(&b).ok())
            .and_then(|e| e.payload_bytes().ok())
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| {
                v.get("parentId")
                    .and_then(|p| p.as_str())
                    .map(str::to_string)
            });
        let _ = std::fs::remove_file(&env_path);
        withheld_entries.push(WithheldArtifact {
            artifact_id: id.clone(),
            parent_id,
        });
    }

    // Content follows the step that named it. A blob is in a package
    // because a signed statement there names its digest; withholding that
    // statement takes the only thing that justified the bytes, so leaving
    // them behind would both disclose what was meant to be withheld and
    // fail the copy's own `content` row. Recomputed from what is left in
    // the copy rather than from the withheld envelopes, so a digest two
    // steps both name survives the withholding of one of them.
    let kept_digests: std::collections::BTreeSet<String> = {
        let mut r = receipt.clone();
        r.artifacts
            .retain(|a| !drop.contains(a.artifact_id.as_str()));
        treeship_core::session::package::signed_digests(&out, &r)
            .into_keys()
            .collect()
    };
    let mut content_dropped: Vec<String> = Vec::new();
    if let Ok((blobs, _)) = treeship_core::session::content::list_blobs(&out) {
        for blob in blobs {
            if !kept_digests.contains(&blob.digest) {
                treeship_core::session::content::remove_blob(&out, &blob.digest)?;
                content_dropped.push(format!("sha256:{}", blob.digest));
            }
        }
    }

    // The narrative that describes what was withheld goes with it.
    let before_timeline = receipt.timeline.len();
    receipt
        .timeline
        .retain(|t| !t.artifact_id.as_deref().is_some_and(|a| drop.contains(a)));
    let before_procs = receipt.side_effects.processes.len();
    receipt
        .side_effects
        .processes
        .retain(|p| !p.artifact_id.as_deref().is_some_and(|a| drop.contains(a)));

    let new_bytes = treeship_core::session::ReceiptComposer::to_canonical_json(&receipt)?;
    let new_digest = format!("sha256:{}", hex::encode(Sha256::digest(&new_bytes)));
    crate::safe_fs::write_under_treeship(&out.join("receipt.json"), &new_bytes, 0o644)?;

    // preview.html embeds the receipt and renders it in the browser, so a
    // stale one would serve the withheld content straight back.
    let preview_path = out.join("preview.html");
    if preview_path.exists() {
        let html = treeship_core::session::render_preview_html(&receipt);
        crate::safe_fs::write_under_treeship(&preview_path, html.as_bytes(), 0o644)?;
    }

    let payload = RedactionPayload {
        session_id: receipt.session.id.clone(),
        merkle_root: receipt.merkle.root.clone().unwrap_or_default(),
        withheld: withheld_entries.clone(),
        reason: reason.map(str::to_string),
        redacted_at: Some(crate::commands::session::now_rfc3339()),
        source_receipt_digest: Some(source_digest),
        receipt_digest: Some(new_digest),
    };

    let mut stmt = ReceiptStatement::new("system://treeship-redact", "redaction.v1");
    stmt.payload = Some(serde_json::to_value(&payload)?);
    let signer = ctx.keys.default_signer()?;
    let pt = payload_type("receipt");
    let result = treeship_core::attestation::sign(&pt, &stmt, signer.as_ref())?;
    let envelope = result.envelope.to_json()?;
    crate::safe_fs::write_under_treeship(&out.join("redaction.json"), &envelope, 0o644)?;

    let timeline_removed = before_timeline - receipt.timeline.len();
    let commands_removed = before_procs - receipt.side_effects.processes.len();

    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "status": "ok",
            "message": "package redacted",
            "from": pkg.display().to_string(),
            "to": out.display().to_string(),
            "withheld": withheld_entries.iter().map(|w| &w.artifact_id).collect::<Vec<_>>(),
            "content_dropped": content_dropped,
            "timeline_entries_removed": timeline_removed,
            "commands_removed": commands_removed,
            "source_receipt_digest": payload.source_receipt_digest,
            "receipt_digest": payload.receipt_digest,
            "signed_by": signer.key_id(),
            "verdict_when_verified": "verified-partial",
        }));
        return Ok(());
    }

    printer.success(
        "package redacted",
        &[
            ("from", &pkg.display().to_string()),
            ("to", &out.display().to_string()),
            (
                "withheld",
                &format!("{} artifact(s)", withheld_entries.len()),
            ),
            (
                "entries removed",
                &format!("{timeline_removed} timeline, {commands_removed} command(s)"),
            ),
            (
                "content dropped",
                &format!("{} blob(s)", content_dropped.len()),
            ),
            ("signed by", signer.key_id()),
        ],
    );
    printer.hint("treeship package verify <out>  reads it as verified-partial");
    Ok(())
}

// --- content ---------------------------------------------------------------
//
// The bytes behind a digest. A step receipt commits to its output by digest,
// which is what lets a trace be handed to someone who should not see the data
// -- and also what leaves a reader holding a commitment to something nobody
// can open. These four commands are the way content gets attached, read and
// taken out again, and all four rest on one rule: a blob may live in a
// package only when a signed statement there already names its digest.
//
// Nothing here re-signs anything. The digest is the binding, so attaching
// content after sealing and dropping it before sharing both leave every
// signature, the Merkle root and the chain exactly as they were.

/// Every digest the trace names, and whether its bytes are here.
pub fn content_ls(pkg: PathBuf, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    use treeship_core::session::content;

    let receipt = read_receipt(&pkg)?;
    let named = treeship_core::session::package::signed_digests(&pkg, &receipt);
    let (blobs, strays) = content::list_blobs(&pkg)?;
    let stored: std::collections::BTreeMap<&str, &content::StoredBlob> =
        blobs.iter().map(|b| (b.digest.as_str(), b)).collect();

    // Rows are the trace's digests, not the files on disk: the question a
    // reader has is "what does this commit to, and can I open it", and a
    // listing of only what is present cannot answer the second half.
    #[derive(serde::Serialize)]
    struct Row {
        digest: String,
        present: bool,
        bytes: Option<u64>,
        /// Set only when the stored bytes do not hash to their own name.
        hashes_to: Option<String>,
        named_by: Vec<serde_json::Value>,
    }
    let rows: Vec<Row> = named
        .iter()
        .map(|(d, refs)| {
            let blob = stored.get(d.as_str());
            Row {
                digest: format!("sha256:{d}"),
                present: blob.is_some(),
                bytes: blob.map(|b| b.bytes),
                hashes_to: blob
                    .and_then(|b| b.mismatch.clone())
                    .map(|a| format!("sha256:{a}")),
                named_by: refs
                    .iter()
                    .map(|r| serde_json::json!({"artifact_id": r.artifact_id, "field": r.field}))
                    .collect(),
            }
        })
        .collect();
    // Blobs the trace does not name are listed too rather than hidden: they
    // are why `package verify` fails, so the listing has to show them.
    let unreferenced: Vec<String> = blobs
        .iter()
        .filter(|b| !named.contains_key(&b.digest))
        .map(|b| format!("sha256:{}", b.digest))
        .collect();

    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "status": "ok",
            "package": pkg.display().to_string(),
            "committed": rows.len(),
            "present": rows.iter().filter(|r| r.present).count(),
            "content": rows,
            "unreferenced": unreferenced,
            "not_content": strays,
        }));
        return Ok(());
    }

    if rows.is_empty() {
        printer.info("no signed statement in this package names a sha-256 digest");
        printer.hint("nothing can be attached here: content is bound by a digest the trace signs");
        return Ok(());
    }
    let present = rows.iter().filter(|r| r.present).count();
    printer.section(&format!(
        "content  {present} of {} digest(s) openable here",
        rows.len()
    ));
    for r in &rows {
        let state = match (&r.hashes_to, r.present) {
            (Some(_), _) => printer.red("substituted"),
            (None, true) => printer.green("present"),
            (None, false) => printer.dim("absent"),
        };
        let size = match r.bytes {
            Some(n) => human_bytes(n),
            None => "-".to_string(),
        };
        printer.info(&format!(
            "  {}  {:>9}  {}",
            &r.digest[..r.digest.len().min(19)],
            size,
            state
        ));
        for n in &r.named_by {
            printer.dim_info(&format!(
                "      {} {}",
                n["artifact_id"].as_str().unwrap_or("?"),
                n["field"].as_str().unwrap_or("?")
            ));
        }
    }
    for d in &unreferenced {
        printer.info(&format!(
            "  {}  {}",
            &d[..d.len().min(19)],
            printer.red("named by no signed statement")
        ));
    }
    for s in &strays {
        printer.info(&format!("  {s}  {}", printer.red("not a blob")));
    }
    if present < rows.len() {
        printer
            .hint("the rest stay commitments: a reader can check the digest, not open the bytes");
    }
    Ok(())
}

/// Write the bytes stored for one digest, after confirming they hash to it.
pub fn content_get(
    pkg: PathBuf,
    digest: &str,
    out: Option<PathBuf>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    use treeship_core::session::content;

    // The hash is recomputed inside `read_blob`, so a substituted file is
    // refused here rather than written out and trusted downstream.
    let bytes = content::read_blob(&pkg, digest).map_err(|e| crate::exit::usage(e.to_string()))?;
    let digest = content::digest_bytes(&bytes);

    match out {
        Some(path) => {
            std::fs::write(&path, &bytes)?;
            if printer.format == crate::printer::Format::Json {
                printer.json(&serde_json::json!({
                    "status": "ok",
                    "message": "content written",
                    "digest": digest,
                    "bytes": bytes.len(),
                    "path": path.display().to_string(),
                }));
                return Ok(());
            }
            printer.success(
                "content written",
                &[
                    ("digest", &digest),
                    ("bytes", &bytes.len().to_string()),
                    ("path", &path.display().to_string()),
                ],
            );
        }
        None => {
            // No --out means stdout, so the bytes can be piped into
            // `shasum -a 256` and checked against the signed statement by
            // someone who trusts neither this package nor this binary.
            use std::io::Write;
            std::io::stdout().write_all(&bytes)?;
        }
    }
    Ok(())
}

/// Attach a file's bytes, which the trace must already name by digest.
pub fn content_add(
    pkg: PathBuf,
    file: PathBuf,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    use treeship_core::session::content;

    let bytes =
        std::fs::read(&file).map_err(|e| crate::exit::usage(format!("{}: {e}", file.display())))?;
    let receipt = read_receipt(&pkg)?;
    let named = treeship_core::session::package::signed_digests(&pkg, &receipt);
    let referenced: std::collections::BTreeSet<String> = named.keys().cloned().collect();

    let digest = content::write_blob(&pkg, &bytes, &referenced).map_err(|e| match e {
        // The useful error names the file and says what the rule is, because
        // the common cause is a file that has been edited since the step ran
        // rather than a misunderstanding of the command.
        content::ContentError::Unreferenced(d) => crate::exit::usage(format!(
            "{} hashes to sha256:{d}, which no signed statement in this package names.\n\
             Content is bound by a digest the trace signs, so these are not the bytes that step saw.",
            file.display()
        )),
        other => crate::exit::usage(other.to_string()),
    })?;
    let hex_digest = content::normalize_digest(&digest).unwrap_or_default();
    let named_by: Vec<serde_json::Value> = named
        .get(&hex_digest)
        .map(|refs| {
            refs.iter()
                .map(|r| serde_json::json!({"artifact_id": r.artifact_id, "field": r.field}))
                .collect()
        })
        .unwrap_or_default();

    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "status": "ok",
            "message": "content attached",
            "digest": digest,
            "bytes": bytes.len(),
            "from": file.display().to_string(),
            "named_by": named_by,
        }));
        return Ok(());
    }
    printer.success(
        "content attached",
        &[
            ("digest", &digest),
            ("bytes", &bytes.len().to_string()),
            ("from", &file.display().to_string()),
            ("named by", &format!("{} signed field(s)", named_by.len())),
        ],
    );
    printer.hint("no signature changed: the bytes are bound by their own hash");
    Ok(())
}

/// Remove the bytes stored for one digest, keeping the commitment to them.
pub fn content_drop(
    pkg: PathBuf,
    digest: &str,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    use treeship_core::session::content;

    let removed =
        content::remove_blob(&pkg, digest).map_err(|e| crate::exit::usage(e.to_string()))?;
    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "status": "ok",
            "message": if removed { "content dropped" } else { "no content stored for that digest" },
            "digest": digest,
            "removed": removed,
        }));
        return Ok(());
    }
    if removed {
        printer.success("content dropped", &[("digest", digest)]);
        printer.hint("the trace still commits to it; the bytes are no longer here");
    } else {
        printer.info(&format!("no content stored for {digest}"));
    }
    Ok(())
}

/// The package's receipt, or a usage error naming the path that is not one.
fn read_receipt(pkg: &Path) -> Result<SessionReceipt, Box<dyn std::error::Error>> {
    treeship_core::session::read_package(pkg)
        .map_err(|e| crate::exit::usage(format!("{}: {e}", pkg.display())))
}

/// Sizes as a reader would say them, matching the `content` verify row.
fn human_bytes(n: u64) -> String {
    if n < 1000 {
        return format!("{n} B");
    }
    let units = ["kB", "MB", "GB", "TB"];
    let mut v = n as f64 / 1000.0;
    let mut i = 0;
    while v >= 1000.0 && i + 1 < units.len() {
        v /= 1000.0;
        i += 1;
    }
    if v < 10.0 {
        format!("{v:.1} {}", units[i])
    } else {
        format!("{v:.0} {}", units[i])
    }
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
        assert!(!is_treeship_runtime_artifact(
            ".treeship/something-new.json"
        ));
    }

    #[test]
    fn source_label_maps_known_provenance() {
        for (input, want) in &[
            (Some("hook"), "hook"),
            (Some("mcp"), "mcp"),
            (Some("git-reconcile"), "git-reconcile"),
            (Some("shell-wrap"), "shell-wrap"),
            (Some("session-event-cli"), "session-event-cli"),
            (Some("daemon-atime"), "daemon-atime"),
            (Some("future-source"), "unknown"),
            (None, "unknown"),
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
