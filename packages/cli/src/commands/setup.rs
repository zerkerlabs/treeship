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
}

impl Default for SetupOpts {
    fn default() -> Self {
        Self {
            yes:           false,
            skip_smoke:    false,
            no_instrument: false,
        }
    }
}

/// `treeship setup` entry point.
pub fn run(
    config: Option<&str>,
    opts: SetupOpts,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
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
            return Ok(());
        }
    };
    printer.dim_info(&format!("  config:    {}", ctx.config_path.display()));
    printer.dim_info(&format!("  ship:      {}", ctx.config.ship_id));

    // Step 2: discover local agents.
    let env = Env::current();
    let agents = discovery::discover(&env);

    if agents.is_empty() {
        printer.blank();
        printer.dim_info("  No agents detected on this machine.");
        printer.blank();
        printer.hint("Treeship still works -- start a session with `treeship session start` and wrap commands with `treeship wrap`.");
        printer.blank();
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
        return Ok(());
    }

    let smoke_ok = match run_smoke_session(printer) {
        Ok(()) => true,
        Err(e) => {
            printer.warn(
                "smoke session did not complete; cards stay at draft / needs-review",
                &[("error", &e.to_string())],
            );
            false
        }
    };

    if smoke_ok {
        // Smoke proved Treeship can capture on this machine. Promote
        // every instrumented card straight to Verified. Cards we did not
        // instrument (SuperNinja remote, generic-mcp without a known
        // surface) stay at Draft -- smoke can't speak for them.
        for card in &instrumented_cards {
            if let Err(e) = cards::set_status(
                &agents_dir,
                &card.agent_id,
                CardStatus::Verified,
                &now_rfc3339(),
            ) {
                printer.warn(
                    &format!("could not promote {} to verified", card.agent_id),
                    &[("error", &e.to_string())],
                );
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
    Ok(())
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
        printer.dim_info("  Smoke session proved Treeship can capture on this machine.");
        printer.dim_info("  Live-agent capture only proven when you run a real session.");
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
