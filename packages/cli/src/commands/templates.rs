//! Integration template profiles -- one row per agent surface.
//!
//! Until v0.9.8, every install rule lived as branching code in
//! `commands/add.rs`: `claude-code|cursor|cline` went one way,
//! `hermes|openclaw` another, `codex` a third. Adding a new surface meant
//! finding three different match arms, sometimes editing two snippets, and
//! hoping you didn't forget the idempotency guard.
//!
//! This module pulls every install rule into a single declarative
//! `Profile` struct so adding a new surface is one new `Profile` literal and
//! nothing else. PR 5's session report will read from the same table to
//! show "instrument with X, capture path Y" without duplicating the data.
//!
//! The `add` command keeps its public interface; only the install dispatch
//! moves here. There is intentionally no separate "agent kind plugin"
//! system -- this is the same data the old branches encoded, in one place.

use std::path::{Path, PathBuf};

use crate::commands::discovery::AgentSurface;

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

/// How the snippet for a surface gets onto disk. Each variant maps to one
/// of the three install styles we already supported pre-PR-4: a JSON merge
/// into an `mcpServers` map, a TOML block append, or writing a fresh skill
/// file at a fixed path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMethod {
    /// JSON file with an `mcpServers.<name>` object; idempotent if the
    /// `treeship` key already exists.
    JsonMcp,
    /// TOML config; idempotent if `[mcp_servers.treeship]` already appears
    /// anywhere in the file. Append-only so we never round-trip and lose
    /// the user's comments.
    TomlMcp,
    /// Skill file -- a Markdown blob written to a fixed path; idempotent
    /// if the file exists at all.
    SkillFile,
}

impl InstallMethod {
    pub fn label(self) -> &'static str {
        match self {
            Self::JsonMcp   => "json-mcp",
            Self::TomlMcp   => "toml-mcp",
            Self::SkillFile => "skill-file",
        }
    }
}

/// One integration template profile. Static for v0.9.8: every field is
/// known at compile time, so the whole table is `&'static [Profile]`.
pub struct Profile {
    pub surface:        AgentSurface,
    /// Stable kebab-case name passed by the user to `treeship add` and
    /// matched by the existing instrumenter. Same value as
    /// `AgentSurface::kind()` for surfaces that have one.
    pub kind:           &'static str,
    /// Human-friendly display name. Mirrors `AgentSurface::display`.
    pub display:        &'static str,
    pub install_method: InstallMethod,
    /// Snippet payload written to / merged into `config_path`. For
    /// `JsonMcp`, `__AGENT__` is replaced with `kind` to scope the
    /// `TREESHIP_ACTOR` env var. The other two methods use the snippet
    /// verbatim.
    pub snippet:        &'static str,
    /// Resolves the absolute file path the snippet should land at, given
    /// HOME. Each profile decides this itself instead of carrying a
    /// generic template -- some surfaces use `~/.foo/mcp.json`, others
    /// `~/.config/foo/...`, and Hermes/OpenClaw bury the skill several
    /// directories deep.
    pub config_path:    fn(&Path) -> PathBuf,
    /// Detects "already installed" without writing. Returns true when no
    /// further action is needed; the install function bails early.
    pub idempotency:    fn(&Path) -> bool,
}

// ---------------------------------------------------------------------------
// Snippets
// ---------------------------------------------------------------------------

/// JSON template merged into `mcpServers.treeship` for Claude Code, Cursor,
/// Cline. `__AGENT__` is replaced with the kind so receipts can attribute
/// activity to the right agent.
pub const JSON_MCP_SNIPPET: &str = r#"{
      "command": "npx",
      "args": ["-y", "@treeship/mcp"],
      "env": {
        "TREESHIP_ACTOR": "agent://__AGENT__",
        "TREESHIP_HUB_ENDPOINT": "https://api.treeship.dev"
      }
    }"#;

/// TOML block appended to `~/.codex/config.toml`.
pub const CODEX_MCP_SNIPPET: &str = r#"

[mcp_servers.treeship]
command = "npx"
args = ["-y", "@treeship/mcp"]

[mcp_servers.treeship.env]
TREESHIP_ACTOR = "agent://codex"
TREESHIP_HUB_ENDPOINT = "https://api.treeship.dev"
"#;

const HERMES_SKILL: &str = include_str!("../../../../integrations/hermes/treeship.skill/SKILL.md");
const OPENCLAW_SKILL: &str = include_str!("../../../../integrations/openclaw/treeship.skill/SKILL.md");

// ---------------------------------------------------------------------------
// Idempotency checks
// ---------------------------------------------------------------------------

/// `mcpServers.treeship` exists in the JSON file at `path`. Missing file or
/// unparseable file → returns false so we'll attempt the install.
fn json_has_treeship(path: &Path) -> bool {
    let Ok(data) = std::fs::read_to_string(path) else { return false };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&data) else { return false };
    value
        .get("mcpServers")
        .and_then(|s| s.as_object())
        .map(|m| m.contains_key("treeship"))
        .unwrap_or(false)
}

/// The `[mcp_servers.treeship]` heading appears anywhere in the TOML file.
/// Substring match is intentional: we want to recognize a previously-
/// installed block whether or not the user has reformatted it.
fn toml_has_treeship_block(path: &Path) -> bool {
    let Ok(data) = std::fs::read_to_string(path) else { return false };
    data.contains("[mcp_servers.treeship]")
}

/// Skill file exists at `path`. Skills are atomic (one file = installed)
/// so existence is sufficient.
fn skill_file_exists(path: &Path) -> bool {
    path.exists()
}

// ---------------------------------------------------------------------------
// config_path resolvers
// ---------------------------------------------------------------------------

fn claude_config_path(home: &Path) -> PathBuf { home.join(".claude").join("mcp.json") }
fn cursor_config_path(home: &Path) -> PathBuf { home.join(".cursor").join("mcp.json") }
fn cline_config_path(home: &Path)  -> PathBuf { home.join(".config").join("cline").join("mcp.json") }
fn codex_config_path(home: &Path)  -> PathBuf { home.join(".codex").join("config.toml") }
fn hermes_skill_path(home: &Path)  -> PathBuf {
    home.join(".hermes").join("skills").join("treeship").join("SKILL.md")
}
fn openclaw_skill_path(home: &Path) -> PathBuf {
    home.join(".openclaw").join("skills").join("treeship").join("SKILL.md")
}

// ---------------------------------------------------------------------------
// Table
// ---------------------------------------------------------------------------

/// Every supported integration template, in stable order. `find` looks up
/// by `kind` so the slice index isn't load-bearing.
pub const PROFILES: &[Profile] = &[
    Profile {
        surface:        AgentSurface::ClaudeCode,
        kind:           "claude-code",
        display:        "Claude Code",
        install_method: InstallMethod::JsonMcp,
        snippet:        JSON_MCP_SNIPPET,
        config_path:    claude_config_path,
        idempotency:    json_has_treeship,
    },
    Profile {
        surface:        AgentSurface::CursorAgent,
        kind:           "cursor",
        display:        "Cursor",
        install_method: InstallMethod::JsonMcp,
        snippet:        JSON_MCP_SNIPPET,
        config_path:    cursor_config_path,
        idempotency:    json_has_treeship,
    },
    Profile {
        surface:        AgentSurface::Cline,
        kind:           "cline",
        display:        "Cline",
        install_method: InstallMethod::JsonMcp,
        snippet:        JSON_MCP_SNIPPET,
        config_path:    cline_config_path,
        idempotency:    json_has_treeship,
    },
    Profile {
        surface:        AgentSurface::Codex,
        kind:           "codex",
        display:        "Codex CLI",
        install_method: InstallMethod::TomlMcp,
        snippet:        CODEX_MCP_SNIPPET,
        config_path:    codex_config_path,
        idempotency:    toml_has_treeship_block,
    },
    Profile {
        surface:        AgentSurface::Hermes,
        kind:           "hermes",
        display:        "Hermes",
        install_method: InstallMethod::SkillFile,
        snippet:        HERMES_SKILL,
        config_path:    hermes_skill_path,
        idempotency:    skill_file_exists,
    },
    Profile {
        surface:        AgentSurface::OpenClaw,
        kind:           "openclaw",
        display:        "OpenClaw",
        install_method: InstallMethod::SkillFile,
        snippet:        OPENCLAW_SKILL,
        config_path:    openclaw_skill_path,
        idempotency:    skill_file_exists,
    },
];

/// Look up a profile by user-supplied kind ("claude-code", "cursor", ...).
pub fn find(kind: &str) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.kind.eq_ignore_ascii_case(kind))
}

/// Look up a profile by AgentSurface. Returns None for surfaces we don't
/// auto-instrument (SuperNinja remote, Ninja Dev, GenericMcp, ShellWrap)
/// because those need user input to know what to attach to.
pub fn for_surface(surface: AgentSurface) -> Option<&'static Profile> {
    PROFILES.iter().find(|p| p.surface == surface)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supported_kind_resolves() {
        for kind in ["claude-code", "cursor", "cline", "codex", "hermes", "openclaw"] {
            assert!(find(kind).is_some(), "kind {kind} should resolve");
        }
    }

    #[test]
    fn unknown_kind_returns_none() {
        assert!(find("not-a-real-agent").is_none());
    }

    #[test]
    fn surface_lookup_matches_kind_lookup() {
        // Each profile's `for_surface` should agree with `find(kind)`.
        for p in PROFILES {
            let by_surface = for_surface(p.surface).unwrap();
            let by_kind    = find(p.kind).unwrap();
            assert_eq!(by_surface.kind, by_kind.kind);
        }
    }

    #[test]
    fn json_idempotency_recognizes_treeship_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mcp.json");

        // Missing file -> not installed.
        assert!(!json_has_treeship(&path));

        // File with no mcpServers -> not installed.
        std::fs::write(&path, r#"{"foo": "bar"}"#).unwrap();
        assert!(!json_has_treeship(&path));

        // File with mcpServers but no treeship -> not installed.
        std::fs::write(&path, r#"{"mcpServers": {"other": {}}}"#).unwrap();
        assert!(!json_has_treeship(&path));

        // File with mcpServers.treeship -> installed.
        std::fs::write(&path, r#"{"mcpServers": {"treeship": {"command": "npx"}}}"#).unwrap();
        assert!(json_has_treeship(&path));

        // Garbled JSON -> not installed (we should re-attempt and surface
        // the parse error there, not silently treat it as installed).
        std::fs::write(&path, "{not valid json").unwrap();
        assert!(!json_has_treeship(&path));
    }

    #[test]
    fn toml_idempotency_substring_match() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        assert!(!toml_has_treeship_block(&path));

        std::fs::write(&path, "model = \"o4\"\n").unwrap();
        assert!(!toml_has_treeship_block(&path));

        std::fs::write(&path, "[mcp_servers.treeship]\ncommand = \"npx\"\n").unwrap();
        assert!(toml_has_treeship_block(&path));

        // Different block name should not trip it.
        std::fs::write(&path, "[mcp_servers.other]\ncommand = \"npx\"\n").unwrap();
        assert!(!toml_has_treeship_block(&path));
    }

    #[test]
    fn skill_file_exists_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("SKILL.md");
        assert!(!skill_file_exists(&path));
        std::fs::write(&path, "# skill").unwrap();
        assert!(skill_file_exists(&path));
    }

    #[test]
    fn config_path_resolvers_use_home() {
        let home = Path::new("/home/u");
        assert_eq!(
            claude_config_path(home),
            PathBuf::from("/home/u/.claude/mcp.json")
        );
        assert_eq!(
            codex_config_path(home),
            PathBuf::from("/home/u/.codex/config.toml")
        );
        assert_eq!(
            hermes_skill_path(home),
            PathBuf::from("/home/u/.hermes/skills/treeship/SKILL.md")
        );
    }

    #[test]
    fn install_method_labels() {
        assert_eq!(InstallMethod::JsonMcp.label(),   "json-mcp");
        assert_eq!(InstallMethod::TomlMcp.label(),   "toml-mcp");
        assert_eq!(InstallMethod::SkillFile.label(), "skill-file");
    }
}
