//! Agent discovery model.
//!
//! Read-only inventory of agent frameworks present on the local machine. Built
//! to be safe to call from anywhere -- it never mutates config, never installs
//! hooks, never asks the user a question. `treeship add --discover` and PR 3's
//! `treeship setup` consume the same `DiscoveredAgent` shape.
//!
//! Detection strategy: filesystem hints over PATH probing wherever both
//! signal the same thing, because filesystem hints are stable across PATH
//! changes inside CI sandboxes and inside `treeship wrap`.
//!
//! Why this lives next to `add` instead of as a new top-level command:
//! `treeship add` already has an opinionated detector and instrumenter. A
//! parallel `treeship discover` would fork the detection rules in a release
//! and we'd own two of them. Instead we extract a clean model from `add`,
//! teach `add` to expose a `--discover` mode that emits it without any
//! instrumentation side-effects, and let the v0.9.8 `setup` command call
//! into the same module. One detector, one schema.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

/// A specific agent runtime/framework. Distinct from the model/provider
/// (Anthropic, OpenAI, Moonshot/Kimi etc.) -- a surface is the *thing that
/// runs the agent loop*, not the model behind it. Kimi is not a surface; it
/// is a model that any number of surfaces can drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentSurface {
    ClaudeCode,
    CursorAgent,
    Cline,
    Codex,
    Hermes,
    OpenClaw,
    NinjatechSuperninja,
    NinjatechNinjaDev,
    GenericMcp,
    ShellWrap,
}

impl AgentSurface {
    /// Stable kebab-case identifier. Used in JSON output and as the kind
    /// users pass to `treeship add` / `treeship agent add`.
    pub fn kind(self) -> &'static str {
        match self {
            Self::ClaudeCode          => "claude-code",
            Self::CursorAgent         => "cursor-agent",
            Self::Cline               => "cline",
            Self::Codex               => "codex",
            Self::Hermes              => "hermes",
            Self::OpenClaw            => "openclaw",
            Self::NinjatechSuperninja => "ninjatech-superninja",
            Self::NinjatechNinjaDev   => "ninjatech-ninja-dev",
            Self::GenericMcp          => "generic-mcp",
            Self::ShellWrap           => "shell-wrap",
        }
    }

    pub fn display(self) -> &'static str {
        match self {
            Self::ClaudeCode          => "Claude Code",
            Self::CursorAgent         => "Cursor",
            Self::Cline               => "Cline",
            Self::Codex               => "Codex CLI",
            Self::Hermes              => "Hermes",
            Self::OpenClaw            => "OpenClaw",
            Self::NinjatechSuperninja => "SuperNinja",
            Self::NinjatechNinjaDev   => "Ninja Dev",
            Self::GenericMcp          => "Generic MCP client",
            Self::ShellWrap           => "Shell-wrap custom agent",
        }
    }
}

/// How Treeship can attach to this agent. Multiple modes can apply --
/// Claude Code supports both native hooks and an MCP server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionMode {
    NativeHook,
    Mcp,
    Skill,
    ShellWrap,
    GitReconcile,
}

impl ConnectionMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::NativeHook   => "native-hook",
            Self::Mcp          => "mcp",
            Self::Skill        => "skill",
            Self::ShellWrap    => "shell-wrap",
            Self::GitReconcile => "git-reconcile",
        }
    }
}

/// How much of the agent's behavior Treeship can observe. Documented as a
/// promise: "high" means we expect to capture every Read/Write/Bash; "basic"
/// means we'll see the wrapped command boundary plus whatever git reconcile
/// finds afterward.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoverageLevel {
    High,
    Medium,
    Basic,
    BackstopOnly,
}

impl CoverageLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::High         => "high",
            Self::Medium       => "medium",
            Self::Basic        => "basic",
            Self::BackstopOnly => "backstop-only",
        }
    }
}

/// How sure detection is. `Low` is reserved for hints that *suggest* an
/// agent without proof -- a TREESHIP.md mentioning Codex with no `~/.codex`
/// dir, for example.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Self::High   => "high",
            Self::Medium => "medium",
            Self::Low    => "low",
        }
    }
}

/// One discovered agent. Output of detection only -- no trust decision is
/// implied. Setup turns these into draft Agent Cards in PR 2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredAgent {
    pub surface:          AgentSurface,
    pub display_name:     String,
    pub connection_modes: Vec<ConnectionMode>,
    pub coverage:         CoverageLevel,
    pub confidence:       Confidence,
    /// Filesystem evidence the detector matched on. Useful for explaining
    /// why an agent showed up; also lets the eventual `treeship agents
    /// review` command point at the file the user might want to inspect.
    pub evidence:         Vec<PathBuf>,
    /// Notes worth showing alongside the row -- e.g. "remote VM, use
    /// `treeship agent invite` to attach". Free-form.
    pub note:             Option<String>,
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Inputs to detection. Defaults to the real environment; tests pass a
/// constructed env to drive synthetic homes / cwds without touching the
/// machine.
pub struct Env {
    pub home: Option<PathBuf>,
    pub cwd:  PathBuf,
    pub path: Option<std::ffi::OsString>,
}

impl Env {
    pub fn current() -> Self {
        Self {
            home: home::home_dir(),
            cwd:  std::env::current_dir().unwrap_or_default(),
            path: std::env::var_os("PATH"),
        }
    }
}

fn path_has(env: &Env, name: &str) -> bool {
    env.path
        .as_ref()
        .map(|paths| std::env::split_paths(paths).any(|dir| dir.join(name).is_file()))
        .unwrap_or(false)
}

/// Walk the env and produce every plausible agent. Order is stable:
/// detected agents come first, then "likely-but-not-here" hints (low
/// confidence) so JSON consumers can rely on it.
pub fn discover(env: &Env) -> Vec<DiscoveredAgent> {
    let mut agents: Vec<DiscoveredAgent> = Vec::new();

    let home = match env.home.as_ref() {
        Some(h) => h.as_path(),
        None    => return agents,
    };
    let cwd = env.cwd.as_path();

    detect_claude_code(&mut agents, home, cwd);
    detect_cursor(&mut agents, home);
    detect_cline(&mut agents, home);
    detect_codex(&mut agents, home);
    detect_hermes(&mut agents, env, home);
    detect_openclaw(&mut agents, env, home);
    detect_ninja_dev(&mut agents, env, home);
    // SuperNinja is intentionally a hint, not a hit -- it runs on a remote
    // VM, so we surface it as a low-confidence pointer to invite/join.
    hint_superninja(&mut agents);
    // Generic MCP is best-effort: it scans for ~/.mcp/ or any mcp.json that
    // we haven't already attributed to a known surface.
    detect_generic_mcp(&mut agents, home);

    agents
}

fn detect_claude_code(agents: &mut Vec<DiscoveredAgent>, home: &Path, cwd: &Path) {
    let global = home.join(".claude");
    let local  = cwd.join(".claude");
    let evidence: Vec<PathBuf> = [&global, &local]
        .iter()
        .filter(|p| p.is_dir())
        .map(|p| (*p).clone())
        .collect();
    if evidence.is_empty() {
        return;
    }
    agents.push(DiscoveredAgent {
        surface:          AgentSurface::ClaudeCode,
        display_name:     AgentSurface::ClaudeCode.display().to_string(),
        connection_modes: vec![ConnectionMode::NativeHook, ConnectionMode::Mcp],
        coverage:         CoverageLevel::High,
        confidence:       Confidence::High,
        evidence,
        note:             None,
    });
}

fn detect_cursor(agents: &mut Vec<DiscoveredAgent>, home: &Path) {
    let dir = home.join(".cursor");
    if !dir.is_dir() {
        return;
    }
    agents.push(DiscoveredAgent {
        surface:          AgentSurface::CursorAgent,
        display_name:     AgentSurface::CursorAgent.display().to_string(),
        connection_modes: vec![ConnectionMode::Mcp],
        coverage:         CoverageLevel::Medium,
        confidence:       Confidence::High,
        evidence:         vec![dir],
        note:             None,
    });
}

fn detect_cline(agents: &mut Vec<DiscoveredAgent>, home: &Path) {
    let dir = home.join(".config").join("cline");
    if !dir.is_dir() {
        return;
    }
    agents.push(DiscoveredAgent {
        surface:          AgentSurface::Cline,
        display_name:     AgentSurface::Cline.display().to_string(),
        connection_modes: vec![ConnectionMode::Mcp],
        coverage:         CoverageLevel::Medium,
        confidence:       Confidence::High,
        evidence:         vec![dir],
        note:             None,
    });
}

fn detect_codex(agents: &mut Vec<DiscoveredAgent>, home: &Path) {
    let dir = home.join(".codex");
    if !dir.is_dir() {
        return;
    }
    agents.push(DiscoveredAgent {
        surface:          AgentSurface::Codex,
        display_name:     AgentSurface::Codex.display().to_string(),
        connection_modes: vec![ConnectionMode::Mcp, ConnectionMode::ShellWrap],
        coverage:         CoverageLevel::Medium,
        confidence:       Confidence::High,
        evidence:         vec![dir],
        note:             None,
    });
}

fn detect_hermes(agents: &mut Vec<DiscoveredAgent>, env: &Env, home: &Path) {
    let dir = home.join(".hermes");
    let on_path = path_has(env, "hermes");
    if !dir.is_dir() && !on_path {
        return;
    }
    let mut evidence = Vec::new();
    if dir.is_dir() {
        evidence.push(dir.clone());
    }
    agents.push(DiscoveredAgent {
        surface:          AgentSurface::Hermes,
        display_name:     AgentSurface::Hermes.display().to_string(),
        connection_modes: vec![ConnectionMode::Skill, ConnectionMode::Mcp],
        coverage:         CoverageLevel::Medium,
        confidence:       if dir.is_dir() { Confidence::High } else { Confidence::Medium },
        evidence,
        note:             None,
    });
}

fn detect_openclaw(agents: &mut Vec<DiscoveredAgent>, env: &Env, home: &Path) {
    let dir = home.join(".openclaw");
    let on_path = path_has(env, "openclaw");
    if !dir.is_dir() && !on_path {
        return;
    }
    let mut evidence = Vec::new();
    if dir.is_dir() {
        evidence.push(dir.clone());
    }
    agents.push(DiscoveredAgent {
        surface:          AgentSurface::OpenClaw,
        display_name:     AgentSurface::OpenClaw.display().to_string(),
        connection_modes: vec![ConnectionMode::Skill, ConnectionMode::Mcp],
        coverage:         CoverageLevel::Medium,
        confidence:       if dir.is_dir() { Confidence::High } else { Confidence::Medium },
        evidence,
        note:             None,
    });
}

/// Ninja Dev: the local IDE/VS Code-style NinjaTech surface. Distinct from
/// the SuperNinja remote VM (which can't be detected locally and gets a
/// hint instead).
///
/// Detection inputs are intentionally permissive because NinjaTech ships
/// across multiple IDE extensions:
///   - `~/.ninja-dev/` or `~/.config/ninjatech/`
///   - any of those dirs with an mcp.json inside
///   - a Ninja-Dev / NinjaTech VS Code extension hint
fn detect_ninja_dev(agents: &mut Vec<DiscoveredAgent>, env: &Env, home: &Path) {
    let candidates: [PathBuf; 3] = [
        home.join(".ninja-dev"),
        home.join(".config").join("ninjatech"),
        home.join(".vscode").join("extensions"),
    ];

    let mut evidence: Vec<PathBuf> = Vec::new();
    for c in &candidates[..2] {
        if c.is_dir() {
            evidence.push(c.clone());
        }
    }

    // VS Code extensions dir is huge -- only count it if a Ninja extension
    // is actually present. Cheap glob: filename starts with "ninjatech" or
    // "ninja-dev".
    let vscode_ext = &candidates[2];
    if vscode_ext.is_dir() {
        if let Ok(rd) = std::fs::read_dir(vscode_ext) {
            for entry in rd.flatten() {
                let name = entry.file_name();
                let name_lossy = name.to_string_lossy();
                let lower = name_lossy.to_ascii_lowercase();
                if lower.starts_with("ninjatech") || lower.starts_with("ninja-dev") {
                    evidence.push(entry.path());
                    break;
                }
            }
        }
    }

    let on_path = path_has(env, "ninja-dev") || path_has(env, "ninjatech");
    if evidence.is_empty() && !on_path {
        return;
    }

    agents.push(DiscoveredAgent {
        surface:          AgentSurface::NinjatechNinjaDev,
        display_name:     AgentSurface::NinjatechNinjaDev.display().to_string(),
        connection_modes: vec![ConnectionMode::Mcp, ConnectionMode::ShellWrap],
        coverage:         CoverageLevel::Medium,
        confidence:       if !evidence.is_empty() { Confidence::Medium } else { Confidence::Low },
        evidence,
        note:             Some("Local NinjaTech IDE surface. For remote SuperNinja VMs, use `treeship agent invite`.".to_string()),
    });
}

/// Always-on hint pointing at SuperNinja remote VMs. This is the right
/// behavior because the SuperNinja runtime is by definition not on the
/// local machine -- discovery showing nothing would let users think
/// Treeship can't attach to it. The note nudges them toward the
/// invite/join flow that v0.9.9 will implement.
fn hint_superninja(agents: &mut Vec<DiscoveredAgent>) {
    agents.push(DiscoveredAgent {
        surface:          AgentSurface::NinjatechSuperninja,
        display_name:     AgentSurface::NinjatechSuperninja.display().to_string(),
        connection_modes: vec![ConnectionMode::Mcp, ConnectionMode::GitReconcile],
        coverage:         CoverageLevel::Basic,
        confidence:       Confidence::Low,
        evidence:         Vec::new(),
        note:             Some("SuperNinja runs on a remote VM and is not auto-discoverable locally. Use `treeship agent invite --kind ninjatech-superninja` to attach.".to_string()),
    });
}

/// Generic MCP fallback: catches any user with a `~/.mcp/` setup or a
/// project-local `.mcp.json` that doesn't belong to an already-detected
/// surface. Keeps confidence at Low so the user reads it as "we noticed
/// this, you tell us what it is."
fn detect_generic_mcp(agents: &mut Vec<DiscoveredAgent>, home: &Path) {
    let mut evidence = Vec::new();
    for c in [home.join(".mcp"), home.join(".config").join("mcp")] {
        if c.is_dir() {
            evidence.push(c);
        }
    }
    if evidence.is_empty() {
        return;
    }
    agents.push(DiscoveredAgent {
        surface:          AgentSurface::GenericMcp,
        display_name:     AgentSurface::GenericMcp.display().to_string(),
        connection_modes: vec![ConnectionMode::Mcp],
        coverage:         CoverageLevel::Medium,
        confidence:       Confidence::Low,
        evidence,
        note:             Some("Generic MCP client config detected. Use `treeship agent add --kind generic-mcp` to register.".to_string()),
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn fake_env(home: PathBuf, cwd: PathBuf) -> Env {
        Env { home: Some(home), cwd, path: Some(std::ffi::OsString::new()) }
    }

    #[test]
    fn empty_home_has_only_remote_hints() {
        let h = tempdir().unwrap();
        let c = tempdir().unwrap();
        let agents = discover(&fake_env(h.path().into(), c.path().into()));
        // SuperNinja hint always present; nothing else.
        let kinds: Vec<&str> = agents.iter().map(|a| a.surface.kind()).collect();
        assert_eq!(kinds, vec!["ninjatech-superninja"]);
    }

    #[test]
    fn claude_code_detected_at_home() {
        let h = tempdir().unwrap();
        let c = tempdir().unwrap();
        fs::create_dir_all(h.path().join(".claude")).unwrap();

        let agents = discover(&fake_env(h.path().into(), c.path().into()));
        let claude = agents.iter().find(|a| a.surface == AgentSurface::ClaudeCode).expect("claude detected");
        assert_eq!(claude.coverage, CoverageLevel::High);
        assert_eq!(claude.confidence, Confidence::High);
        assert!(claude.connection_modes.contains(&ConnectionMode::NativeHook));
        assert!(claude.connection_modes.contains(&ConnectionMode::Mcp));
        assert!(!claude.evidence.is_empty());
    }

    #[test]
    fn claude_code_detected_at_project_local() {
        let h = tempdir().unwrap();
        let c = tempdir().unwrap();
        fs::create_dir_all(c.path().join(".claude")).unwrap();
        let agents = discover(&fake_env(h.path().into(), c.path().into()));
        assert!(agents.iter().any(|a| a.surface == AgentSurface::ClaudeCode));
    }

    #[test]
    fn cursor_codex_cline_hermes_openclaw() {
        let h = tempdir().unwrap();
        let c = tempdir().unwrap();
        fs::create_dir_all(h.path().join(".cursor")).unwrap();
        fs::create_dir_all(h.path().join(".codex")).unwrap();
        fs::create_dir_all(h.path().join(".config").join("cline")).unwrap();
        fs::create_dir_all(h.path().join(".hermes")).unwrap();
        fs::create_dir_all(h.path().join(".openclaw")).unwrap();

        let agents = discover(&fake_env(h.path().into(), c.path().into()));
        let kinds: Vec<&str> = agents.iter().map(|a| a.surface.kind()).collect();
        for expected in &[
            "cursor-agent", "cline", "codex", "hermes", "openclaw", "ninjatech-superninja",
        ] {
            assert!(kinds.contains(expected), "missing {expected} in {:?}", kinds);
        }
    }

    #[test]
    fn ninja_dev_detected_via_config_dir() {
        let h = tempdir().unwrap();
        let c = tempdir().unwrap();
        fs::create_dir_all(h.path().join(".config").join("ninjatech")).unwrap();

        let agents = discover(&fake_env(h.path().into(), c.path().into()));
        let nd = agents
            .iter()
            .find(|a| a.surface == AgentSurface::NinjatechNinjaDev)
            .expect("ninja-dev detected");
        assert_eq!(nd.coverage, CoverageLevel::Medium);
        // Got real evidence; should be Medium confidence, not Low.
        assert_eq!(nd.confidence, Confidence::Medium);
    }

    #[test]
    fn ninja_dev_detected_via_vscode_extension() {
        let h = tempdir().unwrap();
        let c = tempdir().unwrap();
        let ext = h.path().join(".vscode").join("extensions").join("ninjatech.ninja-dev-1.2.3");
        fs::create_dir_all(&ext).unwrap();

        let agents = discover(&fake_env(h.path().into(), c.path().into()));
        assert!(agents.iter().any(|a| a.surface == AgentSurface::NinjatechNinjaDev));
    }

    #[test]
    fn generic_mcp_falls_through_to_low_confidence() {
        let h = tempdir().unwrap();
        let c = tempdir().unwrap();
        fs::create_dir_all(h.path().join(".mcp")).unwrap();

        let agents = discover(&fake_env(h.path().into(), c.path().into()));
        let g = agents
            .iter()
            .find(|a| a.surface == AgentSurface::GenericMcp)
            .expect("generic-mcp detected");
        assert_eq!(g.confidence, Confidence::Low);
    }

    #[test]
    fn json_serialization_is_stable() {
        // The setup command in PR 3 will pipe `treeship add --discover --format json`
        // through to its own logic. Lock the field shape so a downstream
        // bump doesn't silently change the contract.
        let agent = DiscoveredAgent {
            surface:          AgentSurface::ClaudeCode,
            display_name:     "Claude Code".to_string(),
            connection_modes: vec![ConnectionMode::NativeHook, ConnectionMode::Mcp],
            coverage:         CoverageLevel::High,
            confidence:       Confidence::High,
            evidence:         vec![PathBuf::from("/tmp/.claude")],
            note:             None,
        };
        let json = serde_json::to_value(&agent).unwrap();
        assert_eq!(json["surface"], "claude-code");
        assert_eq!(json["coverage"], "high");
        assert_eq!(json["confidence"], "high");
        assert_eq!(json["connection_modes"][0], "native-hook");
        assert_eq!(json["connection_modes"][1], "mcp");
    }
}
