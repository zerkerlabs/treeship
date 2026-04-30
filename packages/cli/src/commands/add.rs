//! `treeship add` -- auto-detect and instrument installed agent frameworks.
//!
//! Reads from two data sources, both shared:
//!   * `commands::discovery` (PR 1)  detects which agents are on this machine
//!   * `commands::harnesses` (PR 5)   harness manifests + install rules per surface
//!
//! The PR 4 refactor pulled three separate install functions
//! (`install_mcp_config`, `install_skill`, `install_codex_mcp_config`) and
//! their hardcoded snippets/paths into `harnesses::HARNESSES`. Adding a new
//! surface is now one row in that table; this module just dispatches on
//! `Profile::install_method`.

use std::io::{self, Write};
use std::path::Path;

use crate::commands::discovery::{self, AgentSurface, DiscoveredAgent, Env};
use crate::commands::harnesses::{self, HarnessManifest, InstallMethod, InstallProfile};
use crate::printer::{Format, Printer};

// ---------------------------------------------------------------------------
// Detection -> install candidates
// ---------------------------------------------------------------------------

/// One agent we both detected on this machine AND have an installable
/// harness for. Manifests with `install: None` (SuperNinja remote, Ninja
/// Dev, GenericMcp, ShellWrap) are filtered out -- there's nothing
/// `install_via_manifest` could write for them.
struct InstallCandidate {
    manifest: &'static HarnessManifest,
    /// The DiscoveredAgent reference the candidate came from. Carried so
    /// future tooling can show evidence paths in the install log.
    #[allow(dead_code)]
    detected: DiscoveredAgent,
}

fn install_candidates(env: &Env) -> Vec<InstallCandidate> {
    discovery::discover(env)
        .into_iter()
        .filter_map(|d| {
            harnesses::for_surface(d.surface).and_then(|m| {
                m.install.as_ref().map(|_| InstallCandidate {
                    manifest: m,
                    detected: d,
                })
            })
        })
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

/// Install a harness against the given HOME. Manifests without
/// `install` are caller-filtered (see `install_candidates`); this function
/// asserts on that invariant rather than silently no-op'ing.
///
/// Returns true if work was performed (or would be performed under
/// `--dry-run`). False means "skipped because already installed."
pub fn install_via_manifest(
    manifest: &HarnessManifest,
    home: &Path,
    dry_run: bool,
    printer: &Printer,
) -> Result<bool, Box<dyn std::error::Error>> {
    let install = match manifest.install.as_ref() {
        Some(i) => i,
        None => {
            // Caller bug; report rather than silently doing nothing.
            return Err(format!(
                "{} has no install profile (manifest is metadata-only)",
                manifest.harness_id
            )
            .into());
        }
    };
    let path = (install.config_path)(home);

    if !is_safe_path(&path) {
        printer.warn(
            &format!("  {} config path contains a symlink, skipping for safety", manifest.display_name),
            &[],
        );
        return Ok(false);
    }

    if (install.idempotency)(&path) {
        printer.dim_info(&format!("  {} already configured, skipping", manifest.display_name));
        return Ok(false);
    }

    if dry_run {
        printer.info(&format!("  Would configure {} at {}", manifest.display_name, path.display()));
        return Ok(true);
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    match install.install_method {
        InstallMethod::JsonMcp   => install_json_mcp(manifest.harness_id, install.snippet, &path)?,
        InstallMethod::TomlMcp   => install_toml_mcp(install.snippet, &path)?,
        InstallMethod::SkillFile => install_skill_file(install.snippet, &path)?,
    }

    printer.success(&format!("{} configured", manifest.display_name), &[]);
    printer.dim_info(&format!("  {}", path.display()));
    if install.install_method == InstallMethod::TomlMcp {
        // Codex (and future TOML clients) need a restart to reload MCP
        // settings. Keep the existing UX hint.
        printer.dim_info("  Restart the agent so it reloads MCP settings.");
    }
    Ok(true)
}

/// JSON merge: read `path` (or start with `{"mcpServers": {}}`), insert
/// `mcpServers.treeship` from the snippet, atomic-write back. `kind` fills
/// the `__AGENT__` placeholder so receipts attribute activity correctly.
fn install_json_mcp(kind: &str, snippet: &str, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut config: serde_json::Value = if path.exists() {
        serde_json::from_str(&std::fs::read_to_string(path)?)?
    } else {
        serde_json::json!({"mcpServers": {}})
    };

    let entry_json = snippet.replace("__AGENT__", kind);
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
/// and formatting); concatenate the snippet at the end.
fn install_toml_mcp(snippet: &str, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let existing = if path.exists() {
        std::fs::read_to_string(path)?
    } else {
        String::new()
    };
    let mut new_content = existing.clone();
    if !new_content.is_empty() && !new_content.ends_with('\n') {
        new_content.push('\n');
    }
    new_content.push_str(snippet);
    let tmp_path = path.with_extension("toml.tmp");
    std::fs::write(&tmp_path, &new_content)?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Skill file: write the snippet (Markdown) to a fixed path. Idempotency
/// already short-circuited if the file exists.
fn install_skill_file(snippet: &str, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, snippet)?;
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
            // Include recommended_harness_id alongside each agent so PR 3's
            // setup orchestration and external tooling can read it
            // without re-deriving from surface.
            let enriched: Vec<serde_json::Value> = agents
                .iter()
                .map(|a| {
                    let mut v = serde_json::to_value(a).unwrap_or(serde_json::Value::Null);
                    if let Some(obj) = v.as_object_mut() {
                        obj.insert(
                            "recommended_harness_id".into(),
                            serde_json::Value::String(a.recommended_harness_id().into()),
                        );
                    }
                    v
                })
                .collect();
            let value = serde_json::json!({ "agents": enriched });
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
        printer.dim_info(&format!("    harness:    {}", agent.recommended_harness_id()));
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
        printer.info("  Treeship has harness manifests for:");
        for p in harnesses::HARNESSES {
            printer.info(&format!("    {}  ({})", p.display_name, p.harness_id));
        }
        printer.blank();
        printer.hint("Install an agent framework, then run treeship add again.");
        printer.blank();
        return Ok(());
    }

    let targets: Vec<&InstallCandidate> = if !specific_agents.is_empty() {
        candidates
            .iter()
            .filter(|c| specific_agents.iter().any(|s| s.eq_ignore_ascii_case(c.manifest.harness_id)))
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
            printer.info(&format!("    {}", c.manifest.display_name));
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
                c.manifest.display_name,
                c.manifest.install.as_ref().unwrap().install_method.label()
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
        match install_via_manifest(c.manifest, &home, dry_run, printer) {
            Ok(true)  => installed += 1,
            Ok(false) => {}
            Err(e)    => printer.warn(&format!("Failed to configure {}: {}", c.manifest.display_name, e), &[]),
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

    /// install_via_manifest drives JSON-merge MCP installs against a tmp HOME.
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
        let profile = harnesses::for_surface(AgentSurface::ClaudeCode).unwrap();

        let did_install = install_via_manifest(profile, home, false, &printer).unwrap();
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
        let did_install_again = install_via_manifest(profile, home, false, &printer).unwrap();
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
        let profile = harnesses::for_surface(AgentSurface::CursorAgent).unwrap();
        install_via_manifest(profile, home, false, &printer).unwrap();

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
        let profile = harnesses::for_surface(AgentSurface::Codex).unwrap();
        let did = install_via_manifest(profile, home, false, &printer).unwrap();
        assert!(did);

        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("# user note"), "preserves user comments");
        assert!(after.contains("[mcp_servers.treeship]"), "appends treeship block");

        // Idempotency: second run is a no-op.
        let again = install_via_manifest(profile, home, false, &printer).unwrap();
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
        let profile = harnesses::for_surface(AgentSurface::Hermes).unwrap();

        let did = install_via_manifest(profile, home, false, &printer).unwrap();
        assert!(did);
        let skill = (profile.install.as_ref().unwrap().config_path)(home);
        assert!(skill.is_file(), "skill file should exist");

        // Idempotency: second run is a no-op.
        let again = install_via_manifest(profile, home, false, &printer).unwrap();
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
        let profile = harnesses::for_surface(AgentSurface::ClaudeCode).unwrap();
        let did = install_via_manifest(profile, home, true /* dry_run */, &printer).unwrap();
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
        let profile = harnesses::for_surface(AgentSurface::ClaudeCode).unwrap();
        let did = install_via_manifest(profile, home, false, &printer).unwrap();
        assert!(!did, "symlinked path must be refused");
        // Nothing should have been written through the symlink.
        assert!(!target.path().join("mcp.json").exists());
        // Also nothing at the original target path.
        let _ = link; // keep `target` alive
    }

    #[test]
    fn install_candidates_skips_surfaces_without_install_profile() {
        // SuperNinja, Ninja Dev, GenericMcp, and ShellWrap have manifests
        // (so `harness inspect` can describe them honestly) but `install:
        // None`. The candidate filter must reject any manifest without
        // install rules so add::run never tries to instrument them.
        for h in harnesses::HARNESSES {
            let candidate_eligible = h.install.is_some();
            let is_remote_or_generic = matches!(
                h.surface,
                AgentSurface::NinjatechSuperninja
                | AgentSurface::NinjatechNinjaDev
                | AgentSurface::GenericMcp
                | AgentSurface::ShellWrap
            );
            assert_eq!(
                candidate_eligible, !is_remote_or_generic,
                "{} install presence must match its candidate eligibility",
                h.harness_id,
            );
        }
    }

    /// Existing detect_agents PathBuf fields are gone; this is a compile-
    /// time check that harnesses::for_surface is the canonical lookup
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
            let p = harnesses::find(kind).unwrap();
            assert_eq!((p.install.as_ref().unwrap().config_path)(&home).to_str().unwrap(), expected, "{kind}");
        }
    }
}
