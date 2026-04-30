//! Harness Manager: how Treeship attaches to and observes each agent surface.
//!
//! This module is the v0.9.8 "Harness Manager" core. It evolved from PR 4's
//! `templates::Profile` table by promoting it into a richer
//! `HarnessManifest` shape that makes harnesses first-class without
//! forking the install dispatch we already shipped.
//!
//! Design separations the rest of the codebase relies on:
//!
//!   Harness Manifest  -- static metadata (this file's HARNESSES table).
//!                        Describes what a harness IS: surface, supported
//!                        connection modes, coverage, captures, gaps,
//!                        privacy posture, optional install rules.
//!
//!   Harness State     -- per-workspace runtime state, lives at
//!                        .treeship/harnesses/<harness_id>.json. Tracks
//!                        whether the user has installed it, when it was
//!                        last smoked, current status.
//!
//!   Agent Card        -- who an agent is and what it's allowed to do.
//!                        Carries `active_harness_id` to point at the
//!                        harness it's attached through.
//!
//! "Harnesses make agents observable. Cards make agents accountable.
//!  Receipts make their work verifiable."

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::commands::discovery::{AgentSurface, ConnectionMode, CoverageLevel};

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// How the install snippet for a surface gets onto disk. None of these is
/// new in PR 5 -- they're carried forward from PR 4's `Profile`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// What a harness *could* capture if attached and working as designed.
/// This is a property of the harness manifest, not of any particular
/// installation -- consumers must read it as "potential coverage,"
/// distinct from `HarnessState.verified_captures` which records what a
/// harness-specific smoke actually proved on this machine.
///
/// Renamed from `Captures` in the v0.9.8 trust-semantics tightening:
/// PR 5's first cut showed manifest captures alongside a Verified status
/// without distinguishing "could capture" from "did capture in this
/// workspace." That conflated potential and verified coverage. The two
/// are kept on separate types so UI code physically can't print the
/// wrong one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PotentialCaptures {
    pub files_read:     bool,
    pub files_write:    bool,
    pub commands_run:   bool,
    pub mcp_call:       bool,
    pub model_provider: bool,
}

/// What a harness-specific smoke actually proved on THIS machine. Each
/// field is `Some(true)` when the relevant signal was observed during a
/// smoke that exercised this harness's own capture path; `Some(false)`
/// when a smoke ran but that signal didn't fire; `None` when no smoke
/// has ever asserted on it (the default).
///
/// v0.9.8's setup runs a generic init/session/wrap/close/verify smoke.
/// That smoke proves the trust-fabric pipeline works on this machine
/// but does NOT prove any harness's specific hook/MCP path captured a
/// real tool call. Setup therefore leaves every field `None` here,
/// promotes only to `HarnessStatus::Instrumented`, and reserves
/// `verified` for v0.9.9's per-harness smokes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VerifiedCaptures {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files_read:     Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub files_write:    Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commands_run:   Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_call:       Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_provider: Option<bool>,
}

impl VerifiedCaptures {
    pub fn is_empty(&self) -> bool {
        self.files_read.is_none()
            && self.files_write.is_none()
            && self.commands_run.is_none()
            && self.mcp_call.is_none()
            && self.model_provider.is_none()
    }
}

/// Optional install rules. Present iff Treeship can auto-instrument this
/// harness via `treeship add`; absent for harnesses that need user action
/// (remote VMs, generic MCP setups whose config path Treeship can't know).
pub struct InstallProfile {
    pub install_method: InstallMethod,
    pub snippet:        &'static str,
    /// Resolves the absolute path the snippet should land at given HOME.
    pub config_path:    fn(&Path) -> PathBuf,
    /// Detects "already installed" without writing.
    pub idempotency:    fn(&Path) -> bool,
}

/// Static description of one harness. Every supported surface has a
/// manifest, even surfaces Treeship can't auto-install (those have
/// `install: None`). The manifest answers "what would this harness
/// capture if attached, and what won't it?"
pub struct HarnessManifest {
    /// Stable kebab-case ID. Same value as `AgentSurface::kind()` for the
    /// 1:1 surface↔harness mapping in v0.9.8. Future surfaces with
    /// multiple harnesses (e.g. Cursor native vs MCP) will introduce
    /// suffixes here.
    pub harness_id:            &'static str,
    pub surface:               AgentSurface,
    pub display_name:          &'static str,
    /// All connection modes this harness uses or falls back to. The
    /// active modes for a given install are recorded in the per-workspace
    /// HarnessState.
    pub connection_modes:      &'static [ConnectionMode],
    pub coverage:              CoverageLevel,
    pub captures:              PotentialCaptures,
    /// Things this harness *can't* observe. Surfaced in `harness inspect`
    /// so users see honest gaps rather than discovering them at receipt
    /// time.
    pub known_gaps:            &'static [&'static str],
    /// One-line summary of what raw data the harness keeps and what it
    /// drops. Sourced from the v0.9.6 capture rules.
    pub privacy_posture:       &'static str,
    /// Connection modes that act as fallbacks if the primary capture
    /// path is missing. e.g. git-reconcile reconstructs files_written
    /// even when no hook fired.
    pub recommended_backstops: &'static [ConnectionMode],
    pub install:               Option<InstallProfile>,
}

// ---------------------------------------------------------------------------
// Snippets (carried forward from PR 4 templates.rs)
// ---------------------------------------------------------------------------

pub const JSON_MCP_SNIPPET: &str = r#"{
      "command": "npx",
      "args": ["-y", "@treeship/mcp"],
      "env": {
        "TREESHIP_ACTOR": "agent://__AGENT__",
        "TREESHIP_HUB_ENDPOINT": "https://api.treeship.dev"
      }
    }"#;

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

fn json_has_treeship(path: &Path) -> bool {
    let Ok(data) = std::fs::read_to_string(path) else { return false };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&data) else { return false };
    value
        .get("mcpServers")
        .and_then(|s| s.as_object())
        .map(|m| m.contains_key("treeship"))
        .unwrap_or(false)
}

fn toml_has_treeship_block(path: &Path) -> bool {
    let Ok(data) = std::fs::read_to_string(path) else { return false };
    data.contains("[mcp_servers.treeship]")
}

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
// Captures presets
// ---------------------------------------------------------------------------

const CAPTURES_FULL: PotentialCaptures = PotentialCaptures {
    files_read:     true,
    files_write:    true,
    commands_run:   true,
    mcp_call:       true,
    model_provider: true,
};

const CAPTURES_MCP_BACKED: PotentialCaptures = PotentialCaptures {
    files_read:     false,
    files_write:    true,
    commands_run:   true,
    mcp_call:       true,
    model_provider: false,
};

const CAPTURES_BACKSTOP_ONLY: PotentialCaptures = PotentialCaptures {
    files_read:     false,
    files_write:    true, // git-reconcile recovers writes
    commands_run:   false,
    mcp_call:       false,
    model_provider: false,
};

// ---------------------------------------------------------------------------
// HARNESSES table
// ---------------------------------------------------------------------------

pub const HARNESSES: &[HarnessManifest] = &[
    HarnessManifest {
        harness_id:            "claude-code",
        surface:               AgentSurface::ClaudeCode,
        display_name:          "Claude Code Native Hook Harness",
        connection_modes:      &[
            ConnectionMode::NativeHook,
            ConnectionMode::Mcp,
            ConnectionMode::GitReconcile,
        ],
        coverage:              CoverageLevel::High,
        captures:              CAPTURES_FULL,
        known_gaps:            &[
            "Built-in tools the user invokes outside hooks (manual sed inside Bash) rely on git-reconcile.",
        ],
        privacy_posture:       "Raw command stripped from receipts; tool inputs sanitized; only paths and tool name retained.",
        recommended_backstops: &[ConnectionMode::GitReconcile],
        install: Some(InstallProfile {
            install_method: InstallMethod::JsonMcp,
            snippet:        JSON_MCP_SNIPPET,
            config_path:    claude_config_path,
            idempotency:    json_has_treeship,
        }),
    },
    HarnessManifest {
        harness_id:            "cursor",
        surface:               AgentSurface::CursorAgent,
        display_name:          "Cursor MCP Harness",
        connection_modes:      &[ConnectionMode::Mcp, ConnectionMode::GitReconcile],
        coverage:              CoverageLevel::Medium,
        captures:              CAPTURES_MCP_BACKED,
        known_gaps:            &[
            "Cursor's built-in editor actions may not always carry tool attribution; fall back to git-reconcile for files_written.",
        ],
        privacy_posture:       "MCP-routed tool inputs sanitized; raw editor actions never leave the IDE.",
        recommended_backstops: &[ConnectionMode::GitReconcile],
        install: Some(InstallProfile {
            install_method: InstallMethod::JsonMcp,
            snippet:        JSON_MCP_SNIPPET,
            config_path:    cursor_config_path,
            idempotency:    json_has_treeship,
        }),
    },
    HarnessManifest {
        harness_id:            "cline",
        surface:               AgentSurface::Cline,
        display_name:          "Cline MCP Harness",
        connection_modes:      &[ConnectionMode::Mcp, ConnectionMode::GitReconcile],
        coverage:              CoverageLevel::Medium,
        captures:              CAPTURES_MCP_BACKED,
        known_gaps:            &[
            "Cline's autonomous loops can write files between MCP calls; git-reconcile picks those up.",
        ],
        privacy_posture:       "MCP-routed tool inputs sanitized.",
        recommended_backstops: &[ConnectionMode::GitReconcile],
        install: Some(InstallProfile {
            install_method: InstallMethod::JsonMcp,
            snippet:        JSON_MCP_SNIPPET,
            config_path:    cline_config_path,
            idempotency:    json_has_treeship,
        }),
    },
    HarnessManifest {
        harness_id:            "codex",
        surface:               AgentSurface::Codex,
        display_name:          "Codex CLI MCP Harness",
        connection_modes:      &[
            ConnectionMode::Mcp,
            ConnectionMode::ShellWrap,
            ConnectionMode::GitReconcile,
        ],
        coverage:              CoverageLevel::Medium,
        captures:              CAPTURES_MCP_BACKED,
        known_gaps:            &[
            "Codex CLI tool plugin surface evolves; new tools may need MCP plumbing per release.",
        ],
        privacy_posture:       "MCP-routed inputs sanitized; shell-wrap captures command boundary, not contents.",
        recommended_backstops: &[ConnectionMode::ShellWrap, ConnectionMode::GitReconcile],
        install: Some(InstallProfile {
            install_method: InstallMethod::TomlMcp,
            snippet:        CODEX_MCP_SNIPPET,
            config_path:    codex_config_path,
            idempotency:    toml_has_treeship_block,
        }),
    },
    HarnessManifest {
        harness_id:            "hermes",
        surface:               AgentSurface::Hermes,
        display_name:          "Hermes Skill Harness",
        connection_modes:      &[ConnectionMode::Skill, ConnectionMode::Mcp],
        coverage:              CoverageLevel::Medium,
        captures:              CAPTURES_MCP_BACKED,
        known_gaps:            &[
            "Skill harness depends on the agent reading TREESHIP.md; receipts will be thin if it doesn't.",
        ],
        privacy_posture:       "Skill instructions tell the agent what to capture; raw inputs not routed through Treeship.",
        recommended_backstops: &[ConnectionMode::GitReconcile],
        install: Some(InstallProfile {
            install_method: InstallMethod::SkillFile,
            snippet:        HERMES_SKILL,
            config_path:    hermes_skill_path,
            idempotency:    skill_file_exists,
        }),
    },
    HarnessManifest {
        harness_id:            "openclaw",
        surface:               AgentSurface::OpenClaw,
        display_name:          "OpenClaw Skill Harness",
        connection_modes:      &[ConnectionMode::Skill, ConnectionMode::Mcp],
        coverage:              CoverageLevel::Medium,
        captures:              CAPTURES_MCP_BACKED,
        known_gaps:            &[
            "Skill harness depends on the agent reading TREESHIP.md; receipts will be thin if it doesn't.",
        ],
        privacy_posture:       "Skill instructions tell the agent what to capture.",
        recommended_backstops: &[ConnectionMode::GitReconcile],
        install: Some(InstallProfile {
            install_method: InstallMethod::SkillFile,
            snippet:        OPENCLAW_SKILL,
            config_path:    openclaw_skill_path,
            idempotency:    skill_file_exists,
        }),
    },

    // ---- Manifests without an automated installer ------------------------
    //
    // These exist so `treeship harness list/inspect` is honest about what
    // Treeship knows it can attach to, even when there's no auto-install
    // path. Their `install` is None; `treeship add` filters them out, and
    // setup leaves their cards at draft.

    HarnessManifest {
        harness_id:            "ninjatech-superninja",
        surface:               AgentSurface::NinjatechSuperninja,
        display_name:          "NinjaTech / SuperNinja Remote Harness",
        connection_modes:      &[
            ConnectionMode::Mcp,
            ConnectionMode::ShellWrap,
            ConnectionMode::GitReconcile,
        ],
        coverage:              CoverageLevel::Basic,
        captures:              CAPTURES_BACKSTOP_ONLY,
        known_gaps:            &[
            "SuperNinja runs on a remote VM and is not auto-discoverable locally.",
            "Coverage stays at basic until Treeship runs inside the VM or routes through MCP.",
            "Use `treeship agent invite` to attach a remote host (deferred to v0.9.9).",
        ],
        privacy_posture:       "Until invite/join lands, only post-hoc git-reconcile evidence is captured locally.",
        recommended_backstops: &[ConnectionMode::GitReconcile],
        install: None,
    },
    HarnessManifest {
        harness_id:            "ninjatech-ninja-dev",
        surface:               AgentSurface::NinjatechNinjaDev,
        display_name:          "NinjaTech Ninja Dev IDE Harness",
        connection_modes:      &[
            ConnectionMode::Mcp,
            ConnectionMode::ShellWrap,
            ConnectionMode::GitReconcile,
        ],
        coverage:              CoverageLevel::Medium,
        captures:              CAPTURES_MCP_BACKED,
        known_gaps:            &[
            "MCP plumbing depends on the Ninja Dev extension version; older builds may not expose tool routing.",
        ],
        privacy_posture:       "MCP-routed inputs sanitized; shell-wrap captures command boundary.",
        recommended_backstops: &[ConnectionMode::ShellWrap, ConnectionMode::GitReconcile],
        install: None,
    },
    HarnessManifest {
        harness_id:            "generic-mcp",
        surface:               AgentSurface::GenericMcp,
        display_name:          "Generic MCP Client Harness",
        connection_modes:      &[ConnectionMode::Mcp, ConnectionMode::GitReconcile],
        coverage:              CoverageLevel::Medium,
        captures:              CAPTURES_MCP_BACKED,
        known_gaps:            &[
            "Treeship can't know the client's specific MCP config path; user must register manually with `treeship agent register`.",
        ],
        privacy_posture:       "MCP-routed inputs sanitized.",
        recommended_backstops: &[ConnectionMode::GitReconcile],
        install: None,
    },
    HarnessManifest {
        harness_id:            "shell-wrap",
        surface:               AgentSurface::ShellWrap,
        display_name:          "Shell-Wrap Custom Agent Harness",
        connection_modes:      &[ConnectionMode::ShellWrap, ConnectionMode::GitReconcile],
        coverage:              CoverageLevel::Basic,
        captures:              CAPTURES_BACKSTOP_ONLY,
        known_gaps:            &[
            "Shell-wrap captures only the command boundary (start/end + exit code); does not see tool calls or model decisions.",
            "Pair with git-reconcile for files_written; otherwise receipts are thin.",
        ],
        privacy_posture:       "Command line stripped from receipt; only argv0 and exit code retained.",
        recommended_backstops: &[ConnectionMode::GitReconcile],
        install: None,
    },
];

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

/// Look up a manifest by its stable harness_id (e.g. "claude-code").
pub fn find(harness_id: &str) -> Option<&'static HarnessManifest> {
    HARNESSES
        .iter()
        .find(|h| h.harness_id.eq_ignore_ascii_case(harness_id))
}

/// Look up the recommended manifest for a given AgentSurface. v0.9.8 has
/// one harness per surface so this is unambiguous; future surfaces with
/// multiple harnesses will need a separate "recommended" selector.
pub fn for_surface(surface: AgentSurface) -> Option<&'static HarnessManifest> {
    HARNESSES.iter().find(|h| h.surface == surface)
}

/// Recommended harness ID for a discovered surface. Used by
/// discovery::DiscoveredAgent::recommended_harness_id.
pub fn recommended_id(surface: AgentSurface) -> Option<&'static str> {
    for_surface(surface).map(|h| h.harness_id)
}

// ---------------------------------------------------------------------------
// HarnessState (per-workspace runtime state)
// ---------------------------------------------------------------------------

/// Runtime status of a harness in this workspace. Distinct from
/// CardStatus -- Cards describe agents, States describe how Treeship is
/// attached to them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HarnessStatus {
    /// Manifest exists; nothing on disk yet.
    Detected,
    /// Manifest has an install profile, but Treeship hasn't installed it
    /// in this workspace. Reserved for the case where setup proposes a
    /// harness but the user declines.
    Available,
    /// Treeship has installed the harness's snippet/config.
    Instrumented,
    /// A smoke session has proven Treeship can capture through this
    /// harness on this machine.
    Verified,
    /// The on-disk install no longer matches what Treeship would write
    /// (config snippet edited, file moved). Reserved for a future
    /// drift-check command.
    Drifted,
    /// Capture is incomplete (some `captures` entry came back false in
    /// smoke). Reserved.
    Degraded,
    /// User explicitly opted out -- harness manifest is recognized but
    /// Treeship will not attach.
    Disabled,
}

impl HarnessStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Detected     => "detected",
            Self::Available    => "available",
            Self::Instrumented => "instrumented",
            Self::Verified     => "verified",
            Self::Drifted      => "drifted",
            Self::Degraded     => "degraded",
            Self::Disabled     => "disabled",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmokeResult {
    pub at:      String,
    pub passed:  bool,
    /// One-line summary -- e.g. "captured init+session+wrap+close+verify"
    /// or "session close failed: <reason>".
    pub summary: String,
}

/// Per-workspace harness runtime record. Mirrors AgentCard's role for
/// agents: it's the trust object Treeship persists about how it's
/// attached, so report code and `harness inspect` can read it back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessState {
    pub harness_id:              String,
    pub status:                  HarnessStatus,
    pub coverage:                CoverageLevel,
    pub active_connection_modes: Vec<ConnectionMode>,
    /// Path that the install snippet landed at (if installed). Useful for
    /// drift detection later.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_path:             Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_at:            Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_smoke_result:       Option<SmokeResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified_at:        Option<String>,
    /// Snapshot of the manifest's known_gaps frozen at install time, so
    /// drift in the manifest doesn't silently change the gaps the user
    /// approved.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_gaps:              Vec<String>,
    /// Agent IDs whose cards point at this harness via active_harness_id.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub linked_agent_ids:        Vec<String>,
    /// Captures actually proven by a harness-specific smoke. Empty (all
    /// fields `None`) until a smoke that exercises this harness's own
    /// capture path runs and asserts on each signal. Setup's generic
    /// session round-trip does NOT populate this.
    #[serde(default, skip_serializing_if = "VerifiedCaptures::is_empty")]
    pub verified_captures:       VerifiedCaptures,
}

impl HarnessState {
    pub fn from_manifest(m: &HarnessManifest, now: &str) -> Self {
        Self {
            harness_id:              m.harness_id.to_string(),
            status:                  HarnessStatus::Detected,
            coverage:                m.coverage,
            active_connection_modes: m.connection_modes.to_vec(),
            config_path:             None,
            installed_at:            Some(now.to_string()),
            last_smoke_result:       None,
            last_verified_at:        None,
            known_gaps:              m.known_gaps.iter().map(|s| s.to_string()).collect(),
            linked_agent_ids:        Vec::new(),
            verified_captures:       VerifiedCaptures::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// State store (project-local at .treeship/harnesses/)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum StateError {
    Io(std::io::Error),
    Json(serde_json::Error),
    NotFound(String),
}

impl std::fmt::Display for StateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e)        => write!(f, "harness io: {e}"),
            Self::Json(e)      => write!(f, "harness json: {e}"),
            Self::NotFound(id) => write!(f, "no harness state for {id:?}"),
        }
    }
}

impl std::error::Error for StateError {}
impl From<std::io::Error>    for StateError { fn from(e: std::io::Error)    -> Self { Self::Io(e) } }
impl From<serde_json::Error> for StateError { fn from(e: serde_json::Error) -> Self { Self::Json(e) } }

/// Resolve `<config_dir>/harnesses/`. Pairs harness state with the same
/// keystore the cards live next to.
pub fn harnesses_dir_for(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("harnesses")
}

pub fn state_path(harnesses_dir: &Path, harness_id: &str) -> PathBuf {
    harnesses_dir.join(format!("{harness_id}.json"))
}

pub fn list_states(harnesses_dir: &Path) -> Result<Vec<HarnessState>, StateError> {
    if !harnesses_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(harnesses_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let state: HarnessState = serde_json::from_slice(&bytes)?;
        out.push(state);
    }
    out.sort_by(|a, b| a.harness_id.cmp(&b.harness_id));
    Ok(out)
}

pub fn load_state(harnesses_dir: &Path, harness_id: &str) -> Result<HarnessState, StateError> {
    let path = state_path(harnesses_dir, harness_id);
    if !path.exists() {
        return Err(StateError::NotFound(harness_id.to_string()));
    }
    let bytes = std::fs::read(&path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn save_state(harnesses_dir: &Path, state: &HarnessState) -> Result<(), StateError> {
    std::fs::create_dir_all(harnesses_dir)?;
    let path = state_path(harnesses_dir, &state.harness_id);
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(state)?;
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Create-or-merge a harness state record. Preserves on-disk timestamps
/// and last_smoke_result if the incoming record doesn't set them, so
/// re-instrumenting doesn't erase prior verification history.
pub fn upsert_state(
    harnesses_dir: &Path,
    incoming: HarnessState,
) -> Result<HarnessState, StateError> {
    let merged = match load_state(harnesses_dir, &incoming.harness_id) {
        Ok(existing) => HarnessState {
            installed_at:      incoming.installed_at.clone().or(existing.installed_at),
            last_smoke_result: incoming.last_smoke_result.clone().or(existing.last_smoke_result),
            last_verified_at:  incoming.last_verified_at.clone().or(existing.last_verified_at),
            // Verified captures only ever grow: a harness-specific smoke
            // that proves files_read=true should not erase a previously
            // proven mcp_call=true. Per-field merge with incoming taking
            // precedence when set.
            verified_captures: VerifiedCaptures {
                files_read:     incoming.verified_captures.files_read.or(existing.verified_captures.files_read),
                files_write:    incoming.verified_captures.files_write.or(existing.verified_captures.files_write),
                commands_run:   incoming.verified_captures.commands_run.or(existing.verified_captures.commands_run),
                mcp_call:       incoming.verified_captures.mcp_call.or(existing.verified_captures.mcp_call),
                model_provider: incoming.verified_captures.model_provider.or(existing.verified_captures.model_provider),
            },
            // Merge linked agent IDs (deduped) so previously-linked cards
            // don't disappear when a new install runs.
            linked_agent_ids:  {
                let mut combined: Vec<String> = existing
                    .linked_agent_ids
                    .into_iter()
                    .chain(incoming.linked_agent_ids.iter().cloned())
                    .collect();
                combined.sort();
                combined.dedup();
                combined
            },
            ..incoming
        },
        Err(StateError::NotFound(_)) => incoming,
        Err(e) => return Err(e),
    };
    save_state(harnesses_dir, &merged)?;
    Ok(merged)
}

/// Add `agent_id` to `linked_agent_ids` for a harness state, creating the
/// state from manifest if it didn't exist. Used by `agent register` and
/// `setup` to record which cards point at this harness.
pub fn link_agent(
    harnesses_dir: &Path,
    harness_id: &str,
    agent_id: &str,
    now: &str,
) -> Result<HarnessState, StateError> {
    let manifest = find(harness_id).ok_or_else(|| StateError::NotFound(harness_id.into()))?;
    let mut state = match load_state(harnesses_dir, harness_id) {
        Ok(s)                        => s,
        Err(StateError::NotFound(_)) => HarnessState::from_manifest(manifest, now),
        Err(e)                       => return Err(e),
    };
    if !state.linked_agent_ids.iter().any(|s| s == agent_id) {
        state.linked_agent_ids.push(agent_id.to_string());
        state.linked_agent_ids.sort();
    }
    save_state(harnesses_dir, &state)?;
    Ok(state)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn every_surface_has_a_manifest() {
        for surface in [
            AgentSurface::ClaudeCode,
            AgentSurface::CursorAgent,
            AgentSurface::Cline,
            AgentSurface::Codex,
            AgentSurface::Hermes,
            AgentSurface::OpenClaw,
            AgentSurface::NinjatechSuperninja,
            AgentSurface::NinjatechNinjaDev,
            AgentSurface::GenericMcp,
            AgentSurface::ShellWrap,
        ] {
            assert!(
                for_surface(surface).is_some(),
                "every AgentSurface needs a HarnessManifest: missing {:?}",
                surface
            );
        }
    }

    #[test]
    fn instrumentable_harnesses_have_install_profiles() {
        let installable: &[&str] = &[
            "claude-code", "cursor", "cline", "codex", "hermes", "openclaw",
        ];
        for h in HARNESSES {
            let want_install = installable.contains(&h.harness_id);
            let has_install  = h.install.is_some();
            assert_eq!(
                want_install, has_install,
                "{} install presence must match instrumentable list", h.harness_id,
            );
        }
    }

    #[test]
    fn superninja_is_honest_about_being_remote() {
        let h = find("ninjatech-superninja").unwrap();
        assert!(h.install.is_none(), "SuperNinja has no local installer");
        assert_eq!(h.coverage, CoverageLevel::Basic);
        let gaps = h.known_gaps.join(" ");
        assert!(gaps.contains("remote VM"), "gaps must mention remote VM");
        assert!(gaps.contains("invite"),    "gaps must point at invite/join");
    }

    #[test]
    fn recommended_id_round_trips_through_for_surface() {
        for h in HARNESSES {
            let id = recommended_id(h.surface).unwrap();
            assert_eq!(id, h.harness_id);
        }
    }

    #[test]
    fn state_round_trip() {
        let dir = tempdir().unwrap();
        let m = find("claude-code").unwrap();
        let mut state = HarnessState::from_manifest(m, "2026-04-29T22:00:00Z");
        state.status = HarnessStatus::Verified;
        state.last_verified_at = Some("2026-04-29T22:00:00Z".into());
        save_state(dir.path(), &state).unwrap();
        let loaded = load_state(dir.path(), "claude-code").unwrap();
        assert_eq!(loaded.status, HarnessStatus::Verified);
        assert_eq!(loaded.coverage, CoverageLevel::High);
    }

    #[test]
    fn upsert_preserves_history() {
        let dir = tempdir().unwrap();
        let m = find("claude-code").unwrap();
        let mut existing = HarnessState::from_manifest(m, "2026-04-29T22:00:00Z");
        existing.status = HarnessStatus::Verified;
        existing.last_smoke_result = Some(SmokeResult {
            at:      "2026-04-29T22:00:00Z".into(),
            passed:  true,
            summary: "captured init+session+wrap+close+verify".into(),
        });
        existing.linked_agent_ids = vec!["agent_aaa".into()];
        save_state(dir.path(), &existing).unwrap();

        let mut incoming = HarnessState::from_manifest(m, "2026-04-30T10:00:00Z");
        incoming.status = HarnessStatus::Instrumented;
        incoming.linked_agent_ids = vec!["agent_bbb".into()];

        let merged = upsert_state(dir.path(), incoming).unwrap();
        assert_eq!(merged.status, HarnessStatus::Instrumented);
        assert!(merged.last_smoke_result.is_some(), "smoke result must survive upsert");
        assert_eq!(merged.linked_agent_ids, vec!["agent_aaa", "agent_bbb"]);
    }

    #[test]
    fn link_agent_is_idempotent_and_creates_state_on_first_call() {
        let dir = tempdir().unwrap();
        link_agent(dir.path(), "claude-code", "agent_x", "t").unwrap();
        link_agent(dir.path(), "claude-code", "agent_y", "t").unwrap();
        link_agent(dir.path(), "claude-code", "agent_x", "t").unwrap(); // duplicate
        let s = load_state(dir.path(), "claude-code").unwrap();
        assert_eq!(s.linked_agent_ids, vec!["agent_x", "agent_y"]);
    }

    #[test]
    fn list_returns_sorted_and_empty_dir_is_ok() {
        let dir = tempdir().unwrap();
        assert!(list_states(dir.path()).unwrap().is_empty());
        let m1 = find("claude-code").unwrap();
        let m2 = find("cursor").unwrap();
        save_state(dir.path(), &HarnessState::from_manifest(m1, "t")).unwrap();
        save_state(dir.path(), &HarnessState::from_manifest(m2, "t")).unwrap();
        let listed = list_states(dir.path()).unwrap();
        assert_eq!(listed.len(), 2);
        assert!(listed[0].harness_id <= listed[1].harness_id);
    }

    #[test]
    fn fresh_state_has_empty_verified_captures() {
        // Trust invariant: a freshly-created HarnessState (the only kind
        // setup writes today) MUST report no proven captures. The UI
        // should never say "verified: yes" for a signal nothing has
        // asserted on yet.
        let m = find("claude-code").unwrap();
        let s = HarnessState::from_manifest(m, "t");
        assert!(s.verified_captures.is_empty());
        assert_eq!(s.verified_captures.files_read,     None);
        assert_eq!(s.verified_captures.files_write,    None);
        assert_eq!(s.verified_captures.commands_run,   None);
        assert_eq!(s.verified_captures.mcp_call,       None);
        assert_eq!(s.verified_captures.model_provider, None);
    }

    #[test]
    fn upsert_grows_verified_captures_monotonically() {
        // Trust invariant: a per-harness smoke that proves files_read
        // must not erase a previous run that proved mcp_call.
        let dir = tempdir().unwrap();
        let m = find("claude-code").unwrap();

        let mut first = HarnessState::from_manifest(m, "t1");
        first.verified_captures.mcp_call = Some(true);
        save_state(dir.path(), &first).unwrap();

        let mut second = HarnessState::from_manifest(m, "t2");
        second.verified_captures.files_read = Some(true);
        let merged = upsert_state(dir.path(), second).unwrap();

        assert_eq!(merged.verified_captures.mcp_call,   Some(true));
        assert_eq!(merged.verified_captures.files_read, Some(true));
    }

    #[test]
    fn captures_for_full_coverage_mark_everything() {
        let claude = find("claude-code").unwrap();
        assert!(claude.captures.files_read);
        assert!(claude.captures.files_write);
        assert!(claude.captures.commands_run);
        assert!(claude.captures.mcp_call);
        assert!(claude.captures.model_provider);
    }

    #[test]
    fn captures_for_shell_wrap_are_minimal() {
        let sw = find("shell-wrap").unwrap();
        assert!(!sw.captures.files_read);
        assert!(!sw.captures.commands_run);
        assert!(!sw.captures.mcp_call);
        assert!(!sw.captures.model_provider);
        assert!(sw.captures.files_write);
    }
}
