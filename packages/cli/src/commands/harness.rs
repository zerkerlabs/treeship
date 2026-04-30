//! `treeship harness` -- inspect and smoke-test the local Harness Manager.
//!
//! Three subcommands wrap the harnesses module's manifest table and
//! per-workspace state store:
//!
//!   treeship harness list                # every known harness + workspace state
//!   treeship harness inspect <id>        # full manifest + state for one
//!   treeship harness smoke <id>          # run an isolated capture session,
//!                                          flip the named harness to verified
//!
//! Companion to `treeship setup` (which calls into the same module to
//! orchestrate first-run flow). Power users invoke `treeship harness *`
//! directly; beginners stick with `setup` and `agents`.

use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;

use crate::commands::harnesses::{
    self, HarnessManifest, HarnessState, HarnessStatus, SmokeResult,
};
use crate::ctx;
use crate::printer::{Format, Printer};

fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    treeship_core::statements::unix_to_rfc3339(secs)
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

/// `treeship harness list` -- every known harness manifest, joined with
/// any workspace state on disk.
pub fn list(
    config: Option<&str>,
    format: Format,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let states = match ctx::open(config) {
        Ok(c) => {
            let dir = harnesses::harnesses_dir_for(&c.config_path);
            harnesses::list_states(&dir).unwrap_or_default()
        }
        // `harness list` is informational; if there's no Treeship workspace
        // yet we can still show the static manifests so the user can decide
        // what they want to set up.
        Err(_) => Vec::new(),
    };

    match format {
        Format::Json => print_list_json(&states),
        Format::Text => print_list_text(&states, printer),
    }
    Ok(())
}

fn print_list_json(states: &[HarnessState]) {
    let rows: Vec<serde_json::Value> = harnesses::HARNESSES
        .iter()
        .map(|m| {
            let state = states.iter().find(|s| s.harness_id == m.harness_id);
            serde_json::json!({
                "harness_id":     m.harness_id,
                "surface":        m.surface,
                "display_name":   m.display_name,
                "coverage":       m.coverage.label(),
                "installable":    m.install.is_some(),
                "status":         state.map(|s| s.status.label()).unwrap_or("detected"),
                "last_smoke":     state.and_then(|s| s.last_smoke_result.as_ref().map(|r| &r.at)),
                "linked_agents":  state.map(|s| s.linked_agent_ids.len()).unwrap_or(0),
            })
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "harnesses": rows })).unwrap_or_default());
}

fn print_list_text(states: &[HarnessState], printer: &Printer) {
    printer.blank();
    printer.section(&format!("Harnesses ({} known)", harnesses::HARNESSES.len()));
    printer.blank();
    for m in harnesses::HARNESSES {
        let state = states.iter().find(|s| s.harness_id == m.harness_id);
        let status = state.map(|s| s.status.label()).unwrap_or("detected");
        let mark = match status {
            "verified"     => "✓",
            "instrumented" => "✓",
            "drifted" | "degraded" => "!",
            "disabled"     => "—",
            _              => "·",
        };
        let installable = if m.install.is_some() { "" } else { " (no auto-installer)" };
        printer.info(&format!(
            "  {mark} {}{}",
            m.display_name, installable,
        ));
        printer.dim_info(&format!("    id:       {}", m.harness_id));
        printer.dim_info(&format!("    surface:  {}", m.surface.kind()));
        printer.dim_info(&format!("    coverage: {}", m.coverage.label()));
        printer.dim_info(&format!("    status:   {status}"));
        printer.blank();
    }
    printer.hint("Run `treeship harness inspect <id>` for full details, or `treeship harness smoke <id>` to verify capture.");
    printer.blank();
}

// ---------------------------------------------------------------------------
// inspect
// ---------------------------------------------------------------------------

/// `treeship harness inspect <id>` -- print the manifest plus any
/// workspace state.
pub fn inspect(
    harness_id: &str,
    config: Option<&str>,
    format: Format,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = harnesses::find(harness_id)
        .ok_or_else(|| format!("no harness with id {harness_id:?}; try `treeship harness list`"))?;

    let state = match ctx::open(config) {
        Ok(c) => {
            let dir = harnesses::harnesses_dir_for(&c.config_path);
            harnesses::load_state(&dir, harness_id).ok()
        }
        Err(_) => None,
    };

    match format {
        Format::Json => print_inspect_json(manifest, state.as_ref()),
        Format::Text => print_inspect_text(manifest, state.as_ref(), printer),
    }
    Ok(())
}

fn print_inspect_json(m: &HarnessManifest, state: Option<&HarnessState>) {
    let install = m.install.as_ref().map(|i| serde_json::json!({
        "method": i.install_method.label(),
    }));
    let potential_captures = serde_json::to_value(m.captures).unwrap_or_default();
    // Verified captures live in state, defaulting to "all None" (nothing
    // proven). Surface them as a distinct field so JSON consumers can
    // never confuse "could capture" with "did capture."
    let verified_captures = state
        .map(|s| serde_json::to_value(s.verified_captures).unwrap_or_default())
        .unwrap_or(serde_json::json!({}));
    let value = serde_json::json!({
        "harness_id":            m.harness_id,
        "surface":               m.surface,
        "display_name":          m.display_name,
        "connection_modes":      m.connection_modes.iter().map(|c| c.label()).collect::<Vec<_>>(),
        "coverage":              m.coverage.label(),
        "potential_captures":    potential_captures,
        "verified_captures":     verified_captures,
        "known_gaps":            m.known_gaps,
        "privacy_posture":       m.privacy_posture,
        "recommended_backstops": m.recommended_backstops.iter().map(|c| c.label()).collect::<Vec<_>>(),
        "install":               install,
        "state":                 state,
    });
    println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
}

fn print_inspect_text(m: &HarnessManifest, state: Option<&HarnessState>, printer: &Printer) {
    printer.blank();
    printer.section(&format!("Harness: {}", m.display_name));
    printer.blank();

    printer.info(&format!("  id:           {}", m.harness_id));
    printer.info(&format!("  surface:      {}", m.surface.kind()));
    let modes: Vec<&str> = m.connection_modes.iter().map(|c| c.label()).collect();
    printer.info(&format!("  connection:   {}", modes.join(" + ")));
    printer.info(&format!("  coverage:     {}", m.coverage.label()));
    printer.info(&format!(
        "  installable:  {}",
        if m.install.is_some() { "yes (treeship add / treeship setup)" } else { "no -- register manually with treeship agent register" },
    ));

    // Two distinct rows: what the harness *could* capture if attached
    // and working, versus what a harness-specific smoke has actually
    // proven on this machine. Don't conflate the two.
    printer.blank();
    printer.dim_info("  potential captures (when attached and working):");
    let c = m.captures;
    printer.dim_info(&format!("    files.read     {}", yes_no(c.files_read)));
    printer.dim_info(&format!("    files.write    {}", yes_no(c.files_write)));
    printer.dim_info(&format!("    commands.run   {}", yes_no(c.commands_run)));
    printer.dim_info(&format!("    mcp.call       {}", yes_no(c.mcp_call)));
    printer.dim_info(&format!("    model/provider {}", yes_no(c.model_provider)));

    printer.blank();
    printer.dim_info("  verified captures (proven by harness-specific smoke):");
    let vc = state.map(|s| s.verified_captures).unwrap_or_default();
    if vc.is_empty() {
        printer.dim_info("    (none yet -- run a real session through this harness)");
    } else {
        printer.dim_info(&format!("    files.read     {}", verified_label(vc.files_read)));
        printer.dim_info(&format!("    files.write    {}", verified_label(vc.files_write)));
        printer.dim_info(&format!("    commands.run   {}", verified_label(vc.commands_run)));
        printer.dim_info(&format!("    mcp.call       {}", verified_label(vc.mcp_call)));
        printer.dim_info(&format!("    model/provider {}", verified_label(vc.model_provider)));
    }

    printer.blank();
    printer.dim_info("  privacy:");
    printer.dim_info(&format!("    {}", m.privacy_posture));

    if !m.known_gaps.is_empty() {
        printer.blank();
        printer.dim_info("  known gaps:");
        for g in m.known_gaps {
            printer.dim_info(&format!("    - {g}"));
        }
    }

    if !m.recommended_backstops.is_empty() {
        printer.blank();
        let backs: Vec<&str> = m.recommended_backstops.iter().map(|c| c.label()).collect();
        printer.dim_info(&format!("  backstops:    {}", backs.join(", ")));
    }

    if let Some(state) = state {
        printer.blank();
        printer.dim_info("  state:");
        printer.dim_info(&format!("    status:        {}", state.status.label()));
        if let Some(at) = &state.last_verified_at {
            printer.dim_info(&format!("    last verified: {at}"));
        }
        if let Some(s) = &state.last_smoke_result {
            printer.dim_info(&format!(
                "    last smoke:    {} -- {} ({})",
                if s.passed { "pass" } else { "fail" },
                s.summary, s.at,
            ));
        }
        if !state.linked_agent_ids.is_empty() {
            printer.dim_info(&format!(
                "    linked agents: {}",
                state.linked_agent_ids.join(", "),
            ));
        }
    } else {
        printer.blank();
        printer.dim_info("  state:        no workspace state on disk; run `treeship setup` or `treeship harness smoke <id>`");
    }

    printer.blank();
}

fn yes_no(b: bool) -> &'static str { if b { "yes" } else { "no" } }

fn verified_label(v: Option<bool>) -> &'static str {
    match v {
        Some(true)  => "yes",
        Some(false) => "smoke ran but signal absent",
        None        => "not yet proven",
    }
}

// ---------------------------------------------------------------------------
// smoke
// ---------------------------------------------------------------------------

/// `treeship harness smoke <id>` -- isolated smoke session that proves
/// Treeship can capture an end-to-end session on this machine, then
/// promotes the named harness's state to Verified.
pub fn smoke(
    harness_id: &str,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = harnesses::find(harness_id)
        .ok_or_else(|| format!("no harness with id {harness_id:?}"))?;
    let ctx = ctx::open(config)?;
    let dir = harnesses::harnesses_dir_for(&ctx.config_path);

    printer.blank();
    printer.section(&format!("Smoke: {}", manifest.display_name));
    printer.blank();

    // Trust-semantics note (v0.9.8 PR 5 patch):
    //
    // This smoke is the GENERIC trust-fabric round-trip. It is identical
    // for every harness: init, session start, wrap, close, package
    // verify. It does not exercise any specific harness's capture path.
    // Promoting to HarnessStatus::Verified here would mean "this harness
    // is verified" when the truth is only "Treeship's pipeline works on
    // this machine."
    //
    // Therefore:
    //   - on success, status moves to Instrumented (or stays at a higher
    //     value already proven by a previous harness-specific smoke)
    //   - last_smoke_result records what was actually proven, in plain
    //     language, so users aren't misled
    //   - verified_captures stays untouched -- only a per-harness smoke
    //     (v0.9.9) writes those bits
    let now = now_rfc3339();
    let outcome = run_smoke();
    let result = match &outcome {
        Ok(()) => SmokeResult {
            at:      now.clone(),
            passed:  true,
            summary: "generic trust-fabric smoke ok (init/session/wrap/close/verify); does not prove harness-specific capture".into(),
        },
        Err(e) => SmokeResult {
            at:      now.clone(),
            passed:  false,
            summary: e.to_string(),
        },
    };

    let mut state = harnesses::load_state(&dir, harness_id)
        .unwrap_or_else(|_| HarnessState::from_manifest(manifest, &now));
    let passed = result.passed;
    if passed {
        // Don't downgrade a state that was previously proven by a real
        // per-harness smoke; only promote up to Instrumented.
        if !matches!(state.status, HarnessStatus::Verified) {
            state.status = HarnessStatus::Instrumented;
        }
    }
    state.last_smoke_result = Some(result);
    harnesses::save_state(&dir, &state)?;

    if passed {
        printer.success("generic trust-fabric smoke passed", &[]);
        printer.dim_info("  status: instrumented (harness-specific capture not yet proven)");
        printer.dim_info("  Run a real session through this harness to populate verified_captures.");
    } else {
        printer.warn("smoke failed", &[]);
        if let Some(r) = state.last_smoke_result.as_ref() {
            printer.dim_info(&format!("  reason: {}", r.summary));
        }
    }
    printer.blank();
    Ok(())
}

/// Identical to setup's smoke session: init, session start, wrap, close,
/// package verify -- all in an isolated tmpdir so the user's real
/// keystore and project state aren't touched.
fn run_smoke() -> Result<(), Box<dyn std::error::Error>> {
    let exe = std::env::current_exe()?;
    let workspace = tempfile::tempdir()?;
    let cfg = workspace.path().join(".treeship").join("config.json");

    run_in(workspace.path(), &exe, &["init", "--config", to_str(&cfg), "--name", "harness-smoke"])?;
    run_in(workspace.path(), &exe, &["session", "start", "--config", to_str(&cfg), "--name", "harness-smoke"])?;
    run_in(workspace.path(), &exe, &["wrap", "--config", to_str(&cfg), "--action", "harness.smoke", "--", "true"])?;
    run_in(workspace.path(), &exe, &["session", "close", "--config", to_str(&cfg), "--summary", "harness smoke ok"])?;
    let pkg = find_recent_package(workspace.path())?;
    run_in(workspace.path(), &exe, &["package", "verify", "--config", to_str(&cfg), &pkg.to_string_lossy()])?;
    Ok(())
}

fn to_str(p: &Path) -> &str {
    p.to_str().expect("tmpdir path must be UTF-8")
}

fn run_in(cwd: &Path, exe: &Path, args: &[&str]) -> Result<(), Box<dyn std::error::Error>> {
    let output = ProcCommand::new(exe)
        .current_dir(cwd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let summary = stderr.lines().last().unwrap_or("(no stderr)").to_string();
        return Err(format!("{} {}: exit {} -- {}", exe.display(), args.join(" "), output.status, summary).into());
    }
    Ok(())
}

fn find_recent_package(workspace: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let sessions = workspace.join(".treeship").join("sessions");
    if !sessions.is_dir() {
        return Err(format!("smoke produced no .treeship/sessions/ at {}", sessions.display()).into());
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
