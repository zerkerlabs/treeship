//! `treeship add` -- auto-detect and instrument installed agent frameworks.
//!
//! Reads from two data sources, both shared:
//!   * `commands::discovery` (PR 1)  detects which agents are on this machine
//!   * `commands::templates` (PR 4)  declarative install rules per surface
//!
//! The PR 4 refactor pulled three separate install functions
//! (`install_mcp_config`, `install_skill`, `install_codex_mcp_config`) and
//! their hardcoded snippets/paths into `templates::PROFILES`. Adding a new
//! surface is now one row in that table; this module just dispatches on
//! `Profile::install_method`.

use std::io::{self, Write};
use std::path::Path;

use crate::commands::discovery::{self, AgentSurface, DiscoveredAgent, Env};
use crate::commands::templates::{self, InstallMethod, Profile};
use crate::printer::{Format, Printer};

// ---------------------------------------------------------------------------
// Detection -> install candidates
// ---------------------------------------------------------------------------

/// One agent we both detected on this machine AND have a template for.
/// Surfaces without an instrumentation template (SuperNinja remote, Ninja
/// Dev, GenericMcp, ShellWrap) are filtered out -- there's nothing
/// `install_via_profile` could write for them.
struct InstallCandidate {
    profile:  &'static Profile,
    /// The DiscoveredAgent reference the candidate came from. Carried so
    /// future tooling can show evidence paths in the install log.
    #[allow(dead_code)]
    detected: DiscoveredAgent,
}

fn install_candidates(env: &Env) -> Vec<InstallCandidate> {
    discovery::discover(env)
        .into_iter()
        .filter_map(|d| templates::for_surface(d.surface).map(|p| InstallCandidate {
            profile:  p,
            detected: d,
        }))
        .collect()
}

// ---------------------------------------------------------------------------
// Symlink guard
// ---------------------------------------------------------------------------

/// Reject paths whose parent chain contains a symlink. Stops a malicious
/// or surprising symlink from redirecting our atomic write to an unrelated
/// file. Identical to the pre-PR-4 behavior.
fn is_safe_path(path: &Path) -> bool {
    let mut check = path.to_path_buf();
    loop {
        if check.is_symlink() { return false; }
        if !check.pop() { break; }
        if check.as_os_str().is_empty() { break; }
    }
    true
}

// ---------------------------------------------------------------------------
// Install dispatch (data-driven)
// ---------------------------------------------------------------------------

/// Install one profile against the given HOME. Returns true if work was
/// performed (or would be performed under `--dry-run`). False means
/// "skipped because already installed."
fn install_via_profile(
    profile: &Profile,
    home: &Path,
    dry_run: bool,
    printer: &Printer,
) -> Result<bool, Box<dyn std::error::Error>> {
    let path = (profile.config_path)(home);

    if !is_safe_path(&path) {
        printer.warn(
            &format!("  {} config path contains a symlink, skipping for safety", profile.display),
            &[],
        );
        return Ok(false);
    }

    if (profile.idempotency)(&path) {
        printer.dim_info(&format!("  {} already configured, skipping", profile.display));
        return Ok(false);
    }

    if dry_run {
        printer.info(&format!("  Would configure {} at {}", profile.display, path.display()));
        return Ok(true);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    match profile.install_method {
        InstallMethod::JsonMcp   => install_json_mcp(profile, &path)?,
        InstallMethod::TomlMcp   => install_toml_mcp(profile, &path)?,
        InstallMethod::SkillFile => install_skill_file(profile, &path)?,
    }

    printer.success(&format!("{} configured", profile.display), &[]);
    printer.dim_info(&format!("  {}", path.display()));
    if profile.install_method == InstallMethod::TomlMcp {
        // Codex (and future TOML clients) need a restart to reload MCP
        // settings. Keep the existing UX hint.
        printer.dim_info("  Restart the agent so it reloads MCP settings.");
    }
    Ok(true)
}

/// JSON merge: read `path` (or start with `{"mcpServers": {}}`), insert
/// `mcpServers.treeship` from the profile snippet, atomic-write back.
fn install_json_mcp(profile: &Profile, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut config: serde_json::Value = if path.exists() {
        serde_json::from_str(&std::fs::read_to_string(path)?)?
    } else {
        serde_json::json!({"mcpServers": {}})
    };

    let entry_json = profile.snippet.replace("__AGENT__", profile.kind);
    let entry: serde_json::Value = serde_json::from_str(&entry_json)?;

    let servers = config
        .as_object_mut()
        .ok_or("invalid config format")?
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    servers
        .as_object_mut()
        .ok_or("mcpServers is not an object")?
        .insert("treeship".into(), entry);

    let json = serde_json::to_string_pretty(&config)?;
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, &json)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// TOML append: leave existing content untouched (preserves user comments
/// and formatting); concatenate the profile snippet at the end.
fn install_toml_mcp(profile: &Profile, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let existing = if path.exists() {
        std::fs::read_to_string(path)?
    } else {
        String::new()
    };
    let mut new_content = existing.clone();
    if !new_content.is_empty() && !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    new_content.push_str(profile.snippet);
    let tmp_path = path.with_extension("toml.tmp");
    std::fs::write(&tmp_path, &new_content)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Skill file: write the snippet (Markdown) to a fixed path. Idempotency
/// already short-circuited if the file exists.
fn install_skill_file(profile: &Profile, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, profile.snippet)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Project-level TREESHIP.md
// ---------------------------------------------------------------------------

const TREESHIP_MD_TEMPLATE: &str = include_str!("../../../../TREESHIP.md");

/// Write `./TREESHIP.md` in the current project so any agent reading the
/// project context (Claude Code, Cursor, Hermes, OpenClaw, future
/// frameworks) sees what Treeship captures, what it doesn't, and how to
/// use it.
///
/// One file, framework-agnostic. Refuses to write if:
///   * cwd is not a Treeship project (no `.treeship/` marker)
///   * `./TREESHIP.md` already exists (never overwrite user content)
///   * the resolved path contains a symlink (matches the rest of `add`)
fn install_treeship_md_in_cwd(dry_run: bool, printer: &Printer) -> Result<bool, Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    if !cwd.join(".treeship").is_dir() {
        printer.dim_info("  No .treeship/ in cwd -- skipping project TREESHIP.md (run `treeship init` first)");
        return Ok(false);
    }
    let treeship_md = cwd.join("TREESHIP.md");
    if !is_safe_path(&treeship_md) {
        printer.warn("  ./TREESHIP.md path contains a symlink, skipping for safety", &[]);
        return Ok(false);
    }
    if treeship_md.exists() {
        printer.dim_info("  ./TREESHIP.md already exists, skipping");
        return Ok(false);
    }
    if dry_run {
        printer.info(&format!("  Would write {}", treeship_md.display()));
        return Ok(true);
    }
    let tmp_path = treeship_md.with_extension("tmp");
    std::fs::write(&tmp_path, TREESHIP_MD_TEMPLATE)?;
    std::fs::rename(&tmp_path, &treeship_md)?;
    printer.success("./TREESHIP.md written", &[]);
    printer.dim_info("  Any agent reading the project will see what Treeship captures and trust the MCP server.");
    Ok(true)
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Read-only discovery mode for `treeship add --discover`. Unchanged in
/// behavior from PR 1; carried forward verbatim.
pub fn run_discover(format: Format, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let agents = discovery::discover(&Env::current());
    match format {
        Format::Json => {
            let value = serde_json::json!({ "agents": agents });
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Format::Text => {
            print_discover_text(&agents, printer);
        }
    }
    Ok(())
}

fn print_discover_text(agents: &[DiscoveredAgent], printer: &Printer) {
    printer.blank();
    if agents.is_empty() {
        printer.dim_info("  No agents detected.");
        printer.blank();
        printer.hint("Treeship still works -- start a session with `treeship session start` and wrap commands with `treeship wrap`.");
        printer.blank();
        return;
    }
    printer.section("Detected agents");
    printer.blank();
    for agent in agents {
        let mark = match agent.confidence {
            discovery::Confidence::High   => "✓",
            discovery::Confidence::Medium => "✓",
            discovery::Confidence::Low    => "?",
        };
        printer.info(&format!("  {} {}", mark, agent.display_name));
        printer.dim_info(&format!("    surface:    {}", agent.surface.kind()));
        let conns: Vec<&str> = agent.connection_modes.iter().map(|c| c.label()).collect();
        printer.dim_info(&format!("    connection: {}", conns.join(" + ")));
        printer.dim_info(&format!("    coverage:   {}", agent.coverage.label()));
        printer.dim_info(&format!("    confidence: {}", agent.confidence.label()));
        printer.dim_info("    card:       draft");
        if let Some(note) = &agent.note {
            printer.dim_info(&format!("    note:       {}", note));
        }
        printer.blank();
    }
    printer.hint("Run `treeship add` to instrument these agents, or `treeship setup` for guided first-run setup.");
    printer.blank();
}

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or_default();
    input.trim().to_string()
}

/// Instrument detected agents.
///
/// `specific_agents` filters by kind (e.g. `["claude-code", "hermes"]`).
/// `all` skips the interactive confirmation. `dry_run` previews without
/// writing.
pub fn run(
    specific_agents: Vec<String>,
    all: bool,
    dry_run: bool,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = Env::current();
    let candidates = install_candidates(&env);

    if candidates.is_empty() {
        printer.blank();
        printer.dim_info("  No agent frameworks detected on this machine that Treeship can instrument.");
        printer.blank();
        printer.info("  Treeship has install templates for:");
        for p in templates::PROFILES {
            printer.info(&format!("    {}  ({})", p.display, p.kind));
        }
        printer.blank();
        printer.hint("Install an agent framework, then run treeship add again.");
        printer.blank();
        return Ok(());
    }

    let targets: Vec<&InstallCandidate> = if !specific_agents.is_empty() {
        candidates
            .iter()
            .filter(|c| specific_agents.iter().any(|s| s.eq_ignore_ascii_case(c.profile.kind)))
            .collect()
    } else {
        candidates.iter().collect()
    };

    if targets.is_empty() && !specific_agents.is_empty() {
        printer.blank();
        printer.warn("None of the specified agents were detected on this machine.", &[]);
        printer.blank();
        printer.info("  Detected:");
        for c in &candidates {
            printer.info(&format!("    {}", c.profile.display));
        }
        printer.blank();
        return Ok(());
    }

    printer.blank();

    if !all && specific_agents.is_empty() && crossterm::tty::IsTty::is_tty(&io::stdin()) {
        printer.info("  Detected:");
        for (i, c) in targets.iter().enumerate() {
            printer.info(&format!(
                "    [{}] {}  -- {}",
                i + 1,
                c.profile.display,
                c.profile.install_method.label()
            ));
        }
        printer.blank();
        let answer = prompt("  Instrument all? (Y/n): ");
        if answer.eq_ignore_ascii_case("n") || answer.eq_ignore_ascii_case("no") {
            printer.dim_info("  Cancelled.");
            printer.blank();
            return Ok(());
        }
        printer.blank();
    }

    let home = match home::home_dir() {
        Some(h) => h,
        None    => return Err("no HOME directory; cannot resolve config paths".into()),
    };

    let mut installed = 0usize;
    for c in &targets {
        match install_via_profile(c.profile, &home, dry_run, printer) {
            Ok(true)  => installed += 1,
            Ok(false) => {}
            Err(e)    => printer.warn(&format!("Failed to configure {}: {}", c.profile.display, e), &[]),
        }
    }

    if let Err(e) = install_treeship_md_in_cwd(dry_run, printer) {
        printer.warn("  Could not write project TREESHIP.md", &[("error", &e.to_string())]);
    }

    printer.blank();
    if dry_run {
        printer.info(&format!(
            "  Dry run: {} agent{} would be configured.",
            installed,
            if installed != 1 { "s" } else { "" }
        ));
    } else if installed > 0 {
        printer.hint("Next: treeship session start --name \"my task\"");
    } else {
        printer.dim_info("  All agents already configured.");
    }
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// install_via_profile drives JSON-merge MCP installs against a tmp HOME.
    /// Asserts: file contents have mcpServers.treeship; second run is a no-op.
    #[test]
    fn json_mcp_installs_then_idempotent() {
        let home_dir = tempfile::tempdir().unwrap();
        // macOS' /var/folders tempdir lives under /var, which is a symlink to
        // /private/var. is_safe_path rejects symlinked ancestors (correct in
        // production), so canonicalize for tests.
        let home = home_dir.path().canonicalize().unwrap();
        let home = home.as_path();
    std::fs::create_dir_all(home.join(".claude")).unwrap();
        let printer = Printer::new(Format::Text, true /* quiet */, true /* no_color */);
        let profile = templates::for_surface(AgentSurface::ClaudeCode).unwrap();

        let did_install = install_via_profile(profile, home, false, &printer).unwrap();
        assert!(did_install);

        let written = home.join(".claude").join("mcp.json");
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&written).unwrap()).unwrap();
        assert!(
            json["mcpServers"]["treeship"]["command"]
                .as_str()
                .unwrap_or("")
                .contains("npx"),
            "treeship MCP entry should be present"
        );

        // Second run -- idempotency check returns true; nothing happens.
        let did_install_again = install_via_profile(profile, home, false, &printer).unwrap();
        assert!(!did_install_again);
    }

    #[test]
    fn json_mcp_uses_kind_in_actor_uri() {
        // Cursor's snippet should land with "agent://cursor", not the
        // generic placeholder.
        let home_dir = tempfile::tempdir().unwrap();
        // macOS' /var/folders tempdir lives under /var, which is a symlink to
        // /private/var. is_safe_path rejects symlinked ancestors (correct in
        // production), so canonicalize for tests.
        let home = home_dir.path().canonicalize().unwrap();
        let home = home.as_path();
    std::fs::create_dir_all(home.join(".cursor")).unwrap();
        let printer = Printer::new(Format::Text, true, true);
        let profile = templates::for_surface(AgentSurface::CursorAgent).unwrap();
        install_via_profile(profile, home, false, &printer).unwrap();

        let json: serde_json::Value = serde_json::from_slice(
            &std::fs::read(home.join(".cursor").join("mcp.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            json["mcpServers"]["treeship"]["env"]["TREESHIP_ACTOR"],
            "agent://cursor"
        );
    }

    #[test]
    fn toml_mcp_appends_block() {
        let home_dir = tempfile::tempdir().unwrap();
        // macOS' /var/folders tempdir lives under /var, which is a symlink to
        // /private/var. is_safe_path rejects symlinked ancestors (correct in
        // production), so canonicalize for tests.
        let home = home_dir.path().canonicalize().unwrap();
        let home = home.as_path();
    std::fs::create_dir_all(home.join(".codex")).unwrap();
        // Pre-existing file with comments -- append must preserve it.
        let path = home.join(".codex").join("config.toml");
        std::fs::write(&path, "# user note\nmodel = \"o4\"").unwrap();

        let printer = Printer::new(Format::Text, true, true);
        let profile = templates::for_surface(AgentSurface::Codex).unwrap();
        let did = install_via_profile(profile, home, false, &printer).unwrap();
        assert!(did);

        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("# user note"), "preserves user comments");
        assert!(after.contains("[mcp_servers.treeship]"), "appends treeship block");

        // Idempotency: second run is a no-op.
        let again = install_via_profile(profile, home, false, &printer).unwrap();
        assert!(!again);
    }

    #[test]
    fn skill_file_writes_then_idempotent() {
        let home_dir = tempfile::tempdir().unwrap();
        // macOS' /var/folders tempdir lives under /var, which is a symlink to
        // /private/var. is_safe_path rejects symlinked ancestors (correct in
        // production), so canonicalize for tests.
        let home = home_dir.path().canonicalize().unwrap();
        let home = home.as_path();
    std::fs::create_dir_all(home.join(".hermes")).unwrap();
        let printer = Printer::new(Format::Text, true, true);
        let profile = templates::for_surface(AgentSurface::Hermes).unwrap();

        let did = install_via_profile(profile, home, false, &printer).unwrap();
        assert!(did);
        let skill = (profile.config_path)(home);
        assert!(skill.is_file(), "skill file should exist");

        // Idempotency: second run is a no-op.
        let again = install_via_profile(profile, home, false, &printer).unwrap();
        assert!(!again);
    }

    #[test]
    fn dry_run_reports_but_does_not_write() {
        let home_dir = tempfile::tempdir().unwrap();
        // macOS' /var/folders tempdir lives under /var, which is a symlink to
        // /private/var. is_safe_path rejects symlinked ancestors (correct in
        // production), so canonicalize for tests.
        let home = home_dir.path().canonicalize().unwrap();
        let home = home.as_path();
    std::fs::create_dir_all(home.join(".claude")).unwrap();
        let printer = Printer::new(Format::Text, true, true);
        let profile = templates::for_surface(AgentSurface::ClaudeCode).unwrap();
        let did = install_via_profile(profile, home, true /* dry_run */, &printer).unwrap();
        // Reports as "would do work" but doesn't write.
        assert!(did);
        assert!(!home.join(".claude").join("mcp.json").exists());
    }

    #[test]
    fn symlink_in_path_is_rejected() {
        let home_dir = tempfile::tempdir().unwrap();
        // macOS' /var/folders tempdir lives under /var, which is a symlink to
        // /private/var. is_safe_path rejects symlinked ancestors (correct in
        // production), so canonicalize for tests.
        let home = home_dir.path().canonicalize().unwrap();
        let home = home.as_path();
    // Make ~/.claude a symlink to /tmp; install must refuse rather
        // than write through it.
        let target = tempfile::tempdir().unwrap();
        let link = home.join(".claude");
        #[cfg(unix)]
        std::os::unix::fs::symlink(target.path(), &link).unwrap();
        #[cfg(not(unix))]
        return;

        let printer = Printer::new(Format::Text, true, true);
        let profile = templates::for_surface(AgentSurface::ClaudeCode).unwrap();
        let did = install_via_profile(profile, home, false, &printer).unwrap();
        assert!(!did, "symlinked path must be refused");
        // Nothing should have been written through the symlink.
        assert!(!target.path().join("mcp.json").exists());
        // Also nothing at the original target path.
        let _ = link; // keep `target` alive
    }

    #[test]
    fn install_candidates_skips_surfaces_without_templates() {
        // SuperNinja has no install template -- it should never appear as
        // an InstallCandidate even though discover always emits it.
        // We can't easily fake the discovery env from this test, but we
        // can prove the filter directly: every PROFILES surface is
        // instrumentable, no SuperNinja entry exists in PROFILES.
        for p in templates::PROFILES {
            assert_ne!(p.surface, AgentSurface::NinjatechSuperninja);
            assert_ne!(p.surface, AgentSurface::ShellWrap);
            assert_ne!(p.surface, AgentSurface::GenericMcp);
        }
    }

    /// Existing detect_agents PathBuf fields are gone; this is a compile-
    /// time check that templates::for_surface is the canonical lookup
    /// instead.
    #[test]
    fn template_paths_match_expected_layout() {
        let home = PathBuf::from("/h");
        let cases = [
            ("claude-code", "/h/.claude/mcp.json"),
            ("cursor",      "/h/.cursor/mcp.json"),
            ("cline",       "/h/.config/cline/mcp.json"),
            ("codex",       "/h/.codex/config.toml"),
            ("hermes",      "/h/.hermes/skills/treeship/SKILL.md"),
            ("openclaw",    "/h/.openclaw/skills/treeship/SKILL.md"),
        ];
        for (kind, expected) in cases {
            let p = templates::find(kind).unwrap();
            assert_eq!((p.config_path)(&home).to_str().unwrap(), expected, "{kind}");
        }
    }
}
