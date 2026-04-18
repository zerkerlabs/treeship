//! treeship add -- auto-detect and instrument installed agent frameworks.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::printer::Printer;

// ---------------------------------------------------------------------------
// Agent detection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct DetectedAgent {
    name: &'static str,
    display: &'static str,
    method: &'static str,
    config_path: PathBuf,
}

fn home() -> Option<PathBuf> {
    home::home_dir()
}

fn detect_agents() -> Vec<DetectedAgent> {
    let mut agents = Vec::new();
    let h = match home() { Some(h) => h, None => return agents };
    let cwd = std::env::current_dir().unwrap_or_default();

    // Claude Code: ~/.claude/ or ./.claude/
    let claude_global = h.join(".claude");
    let claude_local = cwd.join(".claude");
    if claude_global.is_dir() || claude_local.is_dir() {
        let dir = if claude_local.is_dir() { claude_local } else { claude_global };
        agents.push(DetectedAgent {
            name: "claude-code",
            display: "Claude Code",
            method: "MCP server (.claude/mcp.json)",
            config_path: dir.join("mcp.json"),
        });
    }

    // Cursor: ~/.cursor/
    let cursor_dir = h.join(".cursor");
    if cursor_dir.is_dir() {
        agents.push(DetectedAgent {
            name: "cursor",
            display: "Cursor",
            method: "MCP server (.cursor/mcp.json)",
            config_path: cursor_dir.join("mcp.json"),
        });
    }

    // Cline: ~/.config/cline/
    let cline_dir = h.join(".config").join("cline");
    if cline_dir.is_dir() {
        agents.push(DetectedAgent {
            name: "cline",
            display: "Cline",
            method: "MCP server",
            config_path: cline_dir.join("mcp.json"),
        });
    }

    // Hermes: ~/.hermes/ or hermes in PATH
    let hermes_dir = h.join(".hermes");
    let hermes_in_path = which("hermes");
    if hermes_dir.is_dir() || hermes_in_path {
        agents.push(DetectedAgent {
            name: "hermes",
            display: "Hermes",
            method: "Skill file (~/.hermes/skills/treeship/)",
            config_path: hermes_dir.join("skills").join("treeship").join("SKILL.md"),
        });
    }

    // OpenClaw: ~/.openclaw/ or openclaw in PATH
    let openclaw_dir = h.join(".openclaw");
    let openclaw_in_path = which("openclaw");
    if openclaw_dir.is_dir() || openclaw_in_path {
        agents.push(DetectedAgent {
            name: "openclaw",
            display: "OpenClaw",
            method: "Skill file (~/.openclaw/skills/treeship/)",
            config_path: openclaw_dir.join("skills").join("treeship").join("SKILL.md"),
        });
    }

    agents
}

/// In-process PATH search (no shell-out to external `which`).
fn which(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths)
                .any(|dir| dir.join(name).is_file())
        })
        .unwrap_or(false)
}

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    io::stdout().flush().ok();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap_or_default();
    input.trim().to_string()
}

// ---------------------------------------------------------------------------
// MCP config writing
// ---------------------------------------------------------------------------

const TREESHIP_MCP_ENTRY: &str = r#"{
      "command": "npx",
      "args": ["-y", "@treeship/mcp"],
      "env": {
        "TREESHIP_ACTOR": "agent://__AGENT__",
        "TREESHIP_HUB_ENDPOINT": "https://api.treeship.dev"
      }
    }"#;

/// Reject paths that contain symlinks to prevent writing to unexpected locations.
fn is_safe_path(path: &Path) -> bool {
    // Check each ancestor for symlinks
    let mut check = path.to_path_buf();
    loop {
        if check.is_symlink() { return false; }
        if !check.pop() { break; }
        if check.as_os_str().is_empty() { break; }
    }
    true
}

fn install_mcp_config(agent: &DetectedAgent, dry_run: bool, printer: &Printer) -> Result<bool, Box<dyn std::error::Error>> {
    let config_path = &agent.config_path;

    // Reject symlinked directories to prevent arbitrary file writes
    if !is_safe_path(config_path) {
        printer.warn(&format!("  {} config path contains a symlink, skipping for safety", agent.display), &[]);
        return Ok(false);
    }

    // Read existing config or start fresh
    let mut config: serde_json::Value = if config_path.exists() {
        let data = std::fs::read_to_string(config_path)?;
        serde_json::from_str(&data)?
    } else {
        serde_json::json!({"mcpServers": {}})
    };

    // Check if treeship entry already exists
    if let Some(servers) = config.get("mcpServers").and_then(|s| s.as_object()) {
        if servers.contains_key("treeship") {
            printer.dim_info(&format!("  {} already configured, skipping", agent.display));
            return Ok(false);
        }
    }

    if dry_run {
        printer.info(&format!("  Would configure {} at {}", agent.display, config_path.display()));
        return Ok(true);
    }

    // Build the treeship entry
    let entry_json = TREESHIP_MCP_ENTRY.replace("__AGENT__", agent.name);
    let entry: serde_json::Value = serde_json::from_str(&entry_json)?;

    // Insert into mcpServers
    let servers = config
        .as_object_mut()
        .ok_or("invalid config format")?
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));
    servers.as_object_mut()
        .ok_or("mcpServers is not an object")?
        .insert("treeship".into(), entry);

    // Atomic write: temp file + rename to prevent data loss on interruption
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&config)?;
    let tmp_path = config_path.with_extension("tmp");
    std::fs::write(&tmp_path, &json)?;
    std::fs::rename(&tmp_path, config_path)?;

    printer.success(&format!("{} configured", agent.display), &[]);
    printer.dim_info(&format!("  {}", config_path.display()));
    Ok(true)
}

// ---------------------------------------------------------------------------
// Skill file installation
// ---------------------------------------------------------------------------

fn install_skill(agent: &DetectedAgent, dry_run: bool, printer: &Printer) -> Result<bool, Box<dyn std::error::Error>> {
    let skill_path = &agent.config_path;

    // Reject symlinked directories
    if !is_safe_path(skill_path) {
        printer.warn(&format!("  {} skill path contains a symlink, skipping for safety", agent.display), &[]);
        return Ok(false);
    }

    if skill_path.exists() {
        printer.dim_info(&format!("  {} skill already installed, skipping", agent.display));
        return Ok(false);
    }

    if dry_run {
        printer.info(&format!("  Would install {} skill at {}", agent.display, skill_path.display()));
        return Ok(true);
    }

    let skill_content = match agent.name {
        "hermes" => include_str!("../../../../integrations/hermes/treeship.skill/SKILL.md"),
        "openclaw" => include_str!("../../../../integrations/openclaw/treeship.skill/SKILL.md"),
        _ => return Err(format!("no skill template for {}", agent.name).into()),
    };

    if let Some(parent) = skill_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Atomic write via temp + rename
    let tmp_path = skill_path.with_extension("tmp");
    std::fs::write(&tmp_path, skill_content)?;
    std::fs::rename(&tmp_path, skill_path)?;

    printer.success(&format!("{} skill installed", agent.display), &[]);
    printer.dim_info(&format!("  {}", skill_path.display()));
    Ok(true)
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

fn install_agent(agent: &DetectedAgent, dry_run: bool, printer: &Printer) -> Result<bool, Box<dyn std::error::Error>> {
    match agent.name {
        "claude-code" | "cursor" | "cline" => install_mcp_config(agent, dry_run, printer),
        "hermes" | "openclaw" => install_skill(agent, dry_run, printer),
        _ => Err(format!("unknown agent: {}", agent.name).into()),
    }
}

pub fn run(
    specific_agents: Vec<String>,
    all: bool,
    dry_run: bool,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let detected = detect_agents();

    if detected.is_empty() {
        printer.blank();
        printer.dim_info("  No agent frameworks detected on this machine.");
        printer.blank();
        printer.info("  Treeship works with:");
        printer.info("    Claude Code   ~/.claude/");
        printer.info("    Cursor        ~/.cursor/");
        printer.info("    Hermes        ~/.hermes/ or hermes in PATH");
        printer.info("    OpenClaw      ~/.openclaw/ or openclaw in PATH");
        printer.info("    Cline         ~/.config/cline/");
        printer.blank();
        printer.hint("Install an agent framework, then run treeship add again.");
        printer.blank();
        return Ok(());
    }

    // Filter to specific agents if requested
    let targets: Vec<&DetectedAgent> = if !specific_agents.is_empty() {
        detected.iter()
            .filter(|a| specific_agents.iter().any(|s| s.eq_ignore_ascii_case(a.name)))
            .collect()
    } else {
        detected.iter().collect()
    };

    if targets.is_empty() && !specific_agents.is_empty() {
        printer.blank();
        printer.warn("None of the specified agents were detected on this machine.", &[]);
        printer.blank();
        printer.info("  Detected:");
        for a in &detected {
            printer.info(&format!("    {}", a.display));
        }
        printer.blank();
        return Ok(());
    }

    printer.blank();

    // Interactive confirmation unless --all or specific agents given
    if !all && specific_agents.is_empty() && crossterm::tty::IsTty::is_tty(&io::stdin()) {
        printer.info("  Detected:");
        for (i, a) in targets.iter().enumerate() {
            printer.info(&format!("    [{}] {}  -- {}", i + 1, a.display, a.method));
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

    let mut installed = 0usize;
    for agent in &targets {
        match install_agent(agent, dry_run, printer) {
            Ok(true) => installed += 1,
            Ok(false) => {} // skipped (already installed)
            Err(e) => printer.warn(&format!("Failed to configure {}: {}", agent.display, e), &[]),
        }
    }

    printer.blank();
    if dry_run {
        printer.info(&format!("  Dry run: {} agent{} would be configured.", installed, if installed != 1 { "s" } else { "" }));
    } else if installed > 0 {
        printer.hint("Next: treeship session start --name \"my task\"");
    } else {
        printer.dim_info("  All agents already configured.");
    }
    printer.blank();

    Ok(())
}
