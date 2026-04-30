//! `treeship setup` -- guided first-run orchestration.
//!
//! Composition over the existing PR 1 / PR 2 modules:
//!
//!   1. `init` (delegated) if the user has no Treeship config yet
//!   2. `discovery::discover` (PR 1) to find local agents
//!   3. `cards::upsert` (PR 2) to write Draft cards for each detection
//!   4. confirm with the user before instrumenting (or `--yes`)
//!   5. delegate to existing `add::run` for actual config writes
//!   6. optional smoke session that proves Treeship can capture; on success,
//!      promote the matching card's status to `Verified`
//!
//! `setup` deliberately doesn't have its own detector or its own
//! instrumenter. Adding either would re-introduce the "two of these
//! exist now" problem that PRs 1 and 2 closed.
//!
//! Verification semantics: `Verified` means a smoke session proved
//! Treeship can capture session events end-to-end on this machine, against
//! a real isolated keystore. It is *not* a claim about the live agent
//! itself doing the right thing -- v0.9.8 has no global identity check.
//! The verify pass output preserves this honesty.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

use crate::commands::cards::{self, AgentCard, CardStatus};
use crate::commands::discovery::{self, DiscoveredAgent, Env};
use crate::ctx;
use crate::printer::Printer;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub struct SetupOpts {
    /// Skip the confirmation prompt before instrumenting. Equivalent to
    /// `treeship add --all`.
    pub yes: bool,
    /// Skip the smoke verification pass. Useful in CI sandboxes that
    /// can't fork another Treeship binary, and as a fast escape hatch
    /// for users who only want detection + cards.
    pub skip_smoke: bool,
    /// Skip instrumentation entirely -- only detect + draft cards.
    pub no_instrument: bool,
    /// Output format. `text` (default) prints the orchestrated setup
    /// flow as a human-readable transcript; `json` returns a stable
    /// agent-readable payload describing what was detected,
    /// instrumented, and smoke-tested. AI agents call this with
    /// `--yes --format json` to bootstrap Treeship without a TTY.
    pub format: String,
}

impl Default for SetupOpts {
    fn default() -> Self {
        Self {
            yes:           false,
            skip_smoke:    false,
            no_instrument: false,
            format:        "text".into(),
        }
    }
}

/// `treeship setup` entry point.
pub fn run(
    config: Option<&str>,
    opts: SetupOpts,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let json_mode = opts.format == "json";
    // Accumulator. When json_mode is on, the function fills this in as
    // it proceeds and emits the structured payload at the end. When
    // json_mode is off, the existing text printing is the canonical
    // output and the accumulator goes unused. AI agents call
    // `treeship setup --yes --format json` to bootstrap Treeship
    // without a TTY; this is the response shape they branch on.
    let mut result = SetupResult::default();

    printer.blank();
    printer.section("Treeship setup");
    printer.blank();

    // Step 1: ensure init. We don't auto-run it -- the user invoked setup
    // for a reason and might have a project-local keystore expectation;
    // surfacing the missing config and pointing at `init` is friendlier
    // than silently creating a global one.
    let ctx_result = ctx::open(config);
    let ctx = match ctx_result {
        Ok(c) => c,
        Err(_) => {
            printer.warn("  Treeship is not initialized in this workspace.", &[]);
            printer.blank();
            printer.hint("Run: treeship init   (or `treeship init --config <path>` for a project-local config)");
            printer.dim_info("  After init, re-run `treeship setup` and Treeship will pick up where you left off.");
            printer.blank();
            if json_mode {
                result.error = Some("not initialized -- run `treeship init` first".into());
                emit_setup_json(&result);
            }
            return Ok(());
        }
    };
    result.ship_id    = Some(ctx.config.ship_id.clone());
    result.config_path = Some(ctx.config_path.display().to_string());
    printer.dim_info(&format!("  config:    {}", ctx.config_path.display()));
    printer.dim_info(&format!("  ship:      {}", ctx.config.ship_id));

    // Step 2: discover local agents.
    let env = Env::current();
    let agents = discovery::discover(&env);

    // Always record what we detected -- json_mode consumers want
    // visibility on "the machine had no agents" (which is itself
    // useful info for an orchestration agent).
    for agent in &agents {
        result.detected.push(DetectedSummary {
            surface:                agent.surface.kind().into(),
            display_name:           agent.display_name.clone(),
            confidence:             agent.confidence.label().into(),
            recommended_harness_id: Some(agent.recommended_harness_id().to_string()),
        });
    }

    if agents.is_empty() {
        printer.blank();
        printer.dim_info("  No agents detected on this machine.");
        printer.blank();
        printer.hint("Treeship still works -- start a session with `treeship session start` and wrap commands with `treeship wrap`.");
        printer.blank();
        if json_mode {
            emit_setup_json(&result);
        }
        return Ok(());
    }

    // Step 3: write draft cards for everything we found. Idempotent --
    // re-running setup never loses Active/Verified cards or their session
    // linkage (see cards::upsert).
    let agents_dir = cards::agents_dir_for(&ctx.config_path);
    let workspace = ctx
        .config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let host = cards::local_hostname();
    let now = now_rfc3339();

    let mut written: Vec<AgentCard> = Vec::new();
    for agent in &agents {
        let card = AgentCard::from_discovery(agent, &host, &workspace, &now);
        match cards::upsert(&agents_dir, card, &now) {
            Ok(merged) => written.push(merged),
            Err(e) => printer.warn(
                &format!("could not save card for {}", agent.display_name),
                &[("error", &e.to_string())],
            ),
        }
    }

    print_detection_summary(&written, printer);

    if opts.no_instrument {
        printer.dim_info("  --no-instrument set; skipping instrumentation and smoke.");
        printer.blank();
        printer.hint("Approve cards manually with `treeship agents review <id>` then `treeship agents approve <id>`.");
        printer.blank();
        if json_mode {
            populate_card_counts(&mut result, &written);
            result.next_steps.push("treeship agents review <id>".into());
            result.next_steps.push("treeship agents approve <id>".into());
            emit_setup_json(&result);
        }
        return Ok(());
    }

    // Step 4: confirm.
    let confirmed = if opts.yes {
        true
    } else if io::stdin().is_terminal_lite() {
        prompt_yes_no("Instrument these agents now? (Y/n): ", true)
    } else {
        // Non-interactive (no --yes, no TTY). Be conservative: only write
        // cards, never instrument silently.
        false
    };

    if !confirmed {
        printer.dim_info("  Skipping instrumentation. Run `treeship add` or re-run `treeship setup --yes` later.");
        printer.blank();
        if json_mode {
            populate_card_counts(&mut result, &written);
            result.next_steps.push("treeship setup --yes".into());
            emit_setup_json(&result);
        }
        return Ok(());
    }

    // Step 5: delegate to existing `add::run`. Same instrumenter as
    // `treeship add`, no fork.
    printer.blank();
    printer.section("Instrumenting");
    printer.blank();
    let names_for_add: Vec<String> = written
        .iter()
        // Only instrument agents we actually have an instrumentation path
        // for. SuperNinja (remote VM) and GenericMcp/ShellWrap fall through
        // to their cards but `add::run` won't recognize them as installable
        // names today; passing them would just be a no-op printed warning.
        .filter(|c| matches!(
            c.surface,
            discovery::AgentSurface::ClaudeCode
            | discovery::AgentSurface::CursorAgent
            | discovery::AgentSurface::Cline
            | discovery::AgentSurface::Codex
            | discovery::AgentSurface::Hermes
            | discovery::AgentSurface::OpenClaw
        ))
        .map(|c| match c.surface {
            discovery::AgentSurface::ClaudeCode  => "claude-code".to_string(),
            discovery::AgentSurface::CursorAgent => "cursor".to_string(),
            discovery::AgentSurface::Cline       => "cline".to_string(),
            discovery::AgentSurface::Codex       => "codex".to_string(),
            discovery::AgentSurface::Hermes      => "hermes".to_string(),
            discovery::AgentSurface::OpenClaw    => "openclaw".to_string(),
            // unreachable thanks to the filter above
            _                                    => String::new(),
        })
        .filter(|s| !s.is_empty())
        .collect();

    let mut instrumented_cards: Vec<&AgentCard> = Vec::new();
    if names_for_add.is_empty() {
        printer.dim_info("  No agents in this set have an automated instrumenter yet.");
    } else {
        // Capture instrumented surface names for the JSON shape before
        // delegating; `add::run` doesn't return them as a value.
        result.instrumented = names_for_add.clone();
        // `add::run` takes ownership of stdout for its own printing; let
        // it run. `--all` (true) skips its prompt since we already asked.
        crate::commands::add::run(names_for_add, true, false, printer)?;
        // Promote instrumented Draft cards to NeedsReview. The user just
        // confirmed they want Treeship attached to these agents -- the
        // card status should reflect "something to review" rather than
        // "yet to be looked at." Smoke (next step) pushes them further to
        // Verified.
        instrumented_cards = written
            .iter()
            .filter(|c| matches!(
                c.surface,
                discovery::AgentSurface::ClaudeCode
                | discovery::AgentSurface::CursorAgent
                | discovery::AgentSurface::Cline
                | discovery::AgentSurface::Codex
                | discovery::AgentSurface::Hermes
                | discovery::AgentSurface::OpenClaw
            ))
            .collect();
        for card in &instrumented_cards {
            if card.status == CardStatus::Draft {
                if let Err(e) = cards::set_status(
                    &agents_dir,
                    &card.agent_id,
                    CardStatus::NeedsReview,
                    &now_rfc3339(),
                ) {
                    printer.warn(
                        &format!("could not promote {} to needs-review", card.agent_id),
                        &[("error", &e.to_string())],
                    );
                }
            }
        }
    }

    // Step 6: smoke verify.
    if opts.skip_smoke {
        let final_cards = cards::list(&agents_dir).unwrap_or(written.clone());
        print_complete(&final_cards, false, printer);
        if json_mode {
            populate_card_counts(&mut result, &final_cards);
            result.smoke = Some(SmokeSummary { ran: false, passed: false, error: None });
            result.next_steps.push("treeship setup            (re-run later with --skip-smoke off to verify)".into());
            emit_setup_json(&result);
        }
        return Ok(());
    }

    let smoke_start = std::time::Instant::now();
    let (smoke_ok, smoke_err) = match run_smoke_session(printer) {
        Ok(()) => (true, None),
        Err(e) => {
            printer.warn(
                "smoke session did not complete; cards stay at draft / needs-review",
                &[("error", &e.to_string())],
            );
            (false, Some(e.to_string()))
        }
    };
    result.smoke = Some(SmokeSummary {
        ran:    true,
        passed: smoke_ok,
        error:  smoke_err,
    });
    let _ = smoke_start;

    if smoke_ok {
        // Trust-semantics note (v0.9.8 PR 5 patch):
        //
        // The smoke we ran is the GENERIC trust-fabric round-trip
        // (init/session/wrap/close/verify). It proves Treeship's signing,
        // session log, package emission, and verify pipeline all work on
        // this machine. It does NOT exercise any specific harness's
        // capture path -- no Claude native hook fired, no Cursor MCP
        // tool was routed, no Codex shell-wrap was tested. Marking
        // harnesses Verified here would over-claim.
        //
        // Instead:
        //   - cards confirmed by the user move Draft -> Active
        //     (they survive `treeship agents review`)
        //   - harnesses move Detected -> Instrumented with a smoke
        //     summary that explicitly says "generic trust-fabric only"
        //   - `verified_captures` stays empty
        //   - HarnessStatus::Verified is reserved for v0.9.9 per-harness
        //     smokes that assert on specific signals (files.read,
        //     mcp.call, etc.)
        let now = now_rfc3339();
        let harnesses_dir = crate::commands::harnesses::harnesses_dir_for(&ctx.config_path);
        for card in &instrumented_cards {
            if let Err(e) = cards::set_status(
                &agents_dir,
                &card.agent_id,
                CardStatus::Active,
                &now,
            ) {
                printer.warn(
                    &format!("could not promote {} to active", card.agent_id),
                    &[("error", &e.to_string())],
                );
            }
            if let Some(harness_id) = card.active_harness_id.as_deref() {
                if let Some(manifest) = crate::commands::harnesses::find(harness_id) {
                    let mut state = crate::commands::harnesses::load_state(&harnesses_dir, harness_id)
                        .unwrap_or_else(|_| crate::commands::harnesses::HarnessState::from_manifest(manifest, &now));
                    state.status = crate::commands::harnesses::HarnessStatus::Instrumented;
                    // Do NOT set last_verified_at: nothing was verified
                    // about this specific harness.
                    state.last_smoke_result = Some(crate::commands::harnesses::SmokeResult {
                        at:      now.clone(),
                        passed:  true,
                        summary: "setup generic trust-fabric smoke ok (does not prove harness-specific capture)".into(),
                    });
                    if !state.linked_agent_ids.iter().any(|s| s == &card.agent_id) {
                        state.linked_agent_ids.push(card.agent_id.clone());
                        state.linked_agent_ids.sort();
                    }
                    let _ = crate::commands::harnesses::save_state(&harnesses_dir, &state);
                }
            }
        }
    }

    // Re-read from disk so the summary reflects the latest status after
    // any promotions we just made.
    let final_cards = match cards::list(&agents_dir) {
        Ok(list) => list,
        Err(_) => written,
    };
    print_complete(&final_cards, smoke_ok, printer);
    if json_mode {
        populate_card_counts(&mut result, &final_cards);
        result.next_steps.push("treeship session start --name <task>".into());
        result.next_steps.push("treeship session report --share --format json".into());
        emit_setup_json(&result);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Agent-readable JSON output (v0.10.0 PR 5 — Agent-Native Bootstrap)
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, Default)]
struct SetupResult {
    schema:       String,
    ship_id:      Option<String>,
    config_path:  Option<String>,
    detected:     Vec<DetectedSummary>,
    cards:        CardCounts,
    instrumented: Vec<String>,
    smoke:        Option<SmokeSummary>,
    next_steps:   Vec<String>,
    error:        Option<String>,
}

#[derive(serde::Serialize)]
struct DetectedSummary {
    surface:                String,
    display_name:           String,
    confidence:             String,
    recommended_harness_id: Option<String>,
}

#[derive(serde::Serialize, Default)]
struct CardCounts {
    total:        usize,
    draft:        usize,
    needs_review: usize,
    active:       usize,
    verified:     usize,
}

#[derive(serde::Serialize)]
struct SmokeSummary {
    ran:    bool,
    passed: bool,
    error:  Option<String>,
}

fn populate_card_counts(result: &mut SetupResult, cards_list: &[AgentCard]) {
    let mut c = CardCounts::default();
    c.total = cards_list.len();
    for card in cards_list {
        match card.status {
            CardStatus::Draft       => c.draft        += 1,
            CardStatus::NeedsReview => c.needs_review += 1,
            CardStatus::Active      => c.active       += 1,
            CardStatus::Verified    => c.verified     += 1,
        }
    }
    result.cards = c;
}

fn emit_setup_json(result: &SetupResult) {
    let mut payload = result.clone_with_schema();
    payload.schema = "treeship/setup-result/v1".into();
    if let Ok(s) = serde_json::to_string_pretty(&payload) {
        println!("{}", s);
    }
}

impl SetupResult {
    fn clone_with_schema(&self) -> SetupResult {
        SetupResult {
            schema:       self.schema.clone(),
            ship_id:      self.ship_id.clone(),
            config_path:  self.config_path.clone(),
            detected:     self.detected.iter().map(|d| DetectedSummary {
                surface:                d.surface.clone(),
                display_name:           d.display_name.clone(),
                confidence:             d.confidence.clone(),
                recommended_harness_id: d.recommended_harness_id.clone(),
            }).collect(),
            cards:        CardCounts {
                total:        self.cards.total,
                draft:        self.cards.draft,
                needs_review: self.cards.needs_review,
                active:       self.cards.active,
                verified:     self.cards.verified,
            },
            instrumented: self.instrumented.clone(),
            smoke:        self.smoke.as_ref().map(|s| SmokeSummary {
                ran:    s.ran,
                passed: s.passed,
                error:  s.error.clone(),
            }),
            next_steps:   self.next_steps.clone(),
            error:        self.error.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Smoke session
// ---------------------------------------------------------------------------

/// Run the same end-to-end round-trip the `tests/acceptance/trust-fabric.sh`
/// suite uses: init, session start, wrap, session close, package verify.
/// Runs entirely inside a tmpdir keystore so it never touches the user's
/// real config or artifacts.
///
/// What this proves: Treeship's hooks, signing pipeline, session log,
/// package emission, and verify pass all work on this machine. It does
/// NOT prove that any specific instrumented agent will produce capture
/// (the user has to run a real session for that). The note on the
/// completion screen says so.
fn run_smoke_session(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let workspace = tempfile::tempdir()?;
    let cfg = workspace.path().join(".treeship").join("config.json");

    printer.blank();
    printer.section("Smoke session");
    printer.dim_info(&format!("  workspace: {}", workspace.path().display()));
    printer.dim_info("  isolated tmpdir keystore -- doesn't touch your real config");

    // Run every smoke subcommand inside the workspace tmpdir so cwd and
    // config agree on where session state lives. Mixing cwds caused
    // `session close` to mis-locate session.json during setup smoke.
    let ws = workspace.path();
    run_subcommand_in(ws, &exe, &["init", "--config", to_str(&cfg), "--name", "setup-smoke"])?;
    run_subcommand_in(ws, &exe, &["session", "start", "--config", to_str(&cfg), "--name", "setup-smoke"])?;
    run_subcommand_in(ws, &exe, &["wrap", "--config", to_str(&cfg), "--action", "setup.smoke", "--", "true"])?;
    run_subcommand_in(ws, &exe, &["session", "close", "--config", to_str(&cfg), "--summary", "setup smoke ok"])?;
    let pkg = find_recent_package(ws)?;
    run_subcommand_in(ws, &exe, &["package", "verify", "--config", to_str(&cfg), &pkg.to_string_lossy()])?;

    printer.dim_info("  ✓ smoke session captured and verified");
    Ok(())
}

fn to_str(p: &Path) -> &str {
    // Setup paths are tmpdirs we created; UTF-8 is fine on every OS we
    // build for. Falling back to "" would just produce a confusing error
    // downstream, so panic loudly here if the platform invariant breaks.
    p.to_str().expect("tmpdir path must be UTF-8")
}

fn run_subcommand_in(cwd: &Path, exe: &Path, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let output = ProcCommand::new(exe)
        .current_dir(cwd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let summary = stderr.lines().last().unwrap_or("(no stderr)").to_string();
        return Err(format!(
            "{} {}: exit {} -- {}",
            exe.display(),
            args.join(" "),
            output.status,
            summary
        )
        .into());
    }
    Ok(())
}

fn find_recent_package(workspace: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let sessions = workspace.join(".treeship").join("sessions");
    if !sessions.is_dir() {
        return Err(format!("smoke session produced no .treeship/sessions/ at {}", sessions.display()).into());
    }
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(&sessions)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("treeship") {
            continue;
        }
        let mtime = entry.metadata()?.modified()?;
        match &best {
            Some((t, _)) if *t >= mtime => {}
            _ => best = Some((mtime, path)),
        }
    }
    best.map(|(_, p)| p).ok_or_else(|| {
        format!("no .treeship session package found under {}", sessions.display()).into()
    })
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn print_detection_summary(cards_list: &[AgentCard], printer: &Printer) {
    printer.blank();
    printer.section("Detected agents");
    printer.blank();
    for card in cards_list {
        let mark = match card.status {
            CardStatus::Verified | CardStatus::Active => "✓",
            CardStatus::NeedsReview                   => "?",
            CardStatus::Draft                         => "·",
        };
        printer.info(&format!(
            "  {mark} {}  ({}, coverage: {})",
            card.agent_name,
            card.surface.kind(),
            card.coverage.label(),
        ));
    }
}

fn print_complete(cards_list: &[AgentCard], smoke_ok: bool, printer: &Printer) {
    printer.blank();
    printer.success("Treeship setup complete", &[]);
    printer.blank();
    printer.info("  Agents:");
    for card in cards_list {
        printer.info(&format!(
            "    {}    {} ({})",
            card.surface.kind(),
            match card.status {
                CardStatus::Verified    => "verified",
                CardStatus::Active      => "active",
                CardStatus::NeedsReview => "needs review",
                CardStatus::Draft       => "draft",
            },
            card.coverage.label(),
        ));
    }
    printer.blank();
    if smoke_ok {
        printer.dim_info("  Generic trust-fabric smoke passed: signing, session log, package emission, verify.");
        printer.dim_info("  Each harness is now `instrumented`. Per-harness capture (Claude native hook,");
        printer.dim_info("  Cursor MCP, Codex shell-wrap, etc.) is NOT yet verified. Run a real session");
        printer.dim_info("  through each harness to populate verified_captures and reach `verified`.");
    } else {
        printer.dim_info("  Smoke session skipped or failed; cards remain at draft / needs-review.");
    }
    printer.blank();
    printer.hint("Next: treeship session start --name \"first run\"");
    printer.blank();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    treeship_core::statements::unix_to_rfc3339(secs)
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> bool {
    print!("  {prompt}");
    io::stdout().flush().ok();
    let mut buf = String::new();
    if io::stdin().read_line(&mut buf).is_err() {
        return default_yes;
    }
    let trimmed = buf.trim().to_lowercase();
    if trimmed.is_empty() {
        return default_yes;
    }
    matches!(trimmed.as_str(), "y" | "yes")
}

/// Tiny shim so callers don't need to import `IsTerminal` themselves;
/// also gives us one place to switch the implementation if we move to
/// `crossterm::tty::IsTty` later.
trait IsTerminalLite {
    fn is_terminal_lite(&self) -> bool;
}

impl<T: io::IsTerminal> IsTerminalLite for T {
    fn is_terminal_lite(&self) -> bool {
        self.is_terminal()
    }
}
