//! Persistent Agent Card store.
//!
//! An Agent Card is the local trust object Treeship keeps about a specific
//! agent in this workspace: who it is, where it runs, how Treeship is
//! attached, what coverage to expect, and what the user has decided to do
//! with it (draft / needs-review / active / verified). Distinct from the
//! .agent package produced by `treeship agent register`, which is a signed
//! certificate -- the certificate is what gets shipped/embedded into
//! receipts; the card is the workspace inventory.
//!
//! Cards live at `.treeship/agents/<id>.json`. The id is deterministic from
//! (surface, host, workspace) so re-running `treeship setup` doesn't
//! duplicate entries.
//!
//! v0.9.8 scope:
//!   - persistent JSON store
//!   - card_status lifecycle: draft -> needs-review -> active -> verified
//!   - load/save/list/find/upsert
//!
//! Out of scope here: the CLI surface (`treeship agents`) and the wiring
//! that has `agent register` populate the store. Those land alongside this
//! module in the same PR but live in their own files.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::commands::discovery::{
    AgentSurface, ConnectionMode, CoverageLevel, DiscoveredAgent,
};

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// Lifecycle of an Agent Card. Movement is one-directional in the happy path
/// (draft -> needs-review -> active -> verified) but the user can demote
/// (active -> needs-review) when something changes -- e.g. they re-run
/// discovery and a coverage level drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CardStatus {
    /// Discovered but not yet acknowledged. Treeship made this card without
    /// asking. The user has not approved attaching to this agent.
    Draft,
    /// User has registered an Agent Identity Certificate but has not yet
    /// reviewed the resulting card. `treeship agents review <id>` clears
    /// this. Distinct from Draft because a needs-review card carries a real
    /// signed certificate; Draft cards do not.
    NeedsReview,
    /// User has reviewed and approved. Active cards are visible in session
    /// reports and used to bind tool authorization.
    Active,
    /// Active AND a smoke session has proven Treeship can capture this
    /// agent's events end-to-end. The strongest available status in v0.9.8
    /// (no global identity verification yet).
    Verified,
}

impl CardStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Draft       => "draft",
            Self::NeedsReview => "needs-review",
            Self::Active      => "active",
            Self::Verified    => "verified",
        }
    }
}

/// Snapshot of what an agent is allowed to do. Mirrors the v0.9.6
/// `treeship attest approval` model so the same vocabulary works at both
/// authorization and verification time. Empty vectors mean "unscoped" which
/// the verify pass already labels honestly.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CardCapabilities {
    /// Tools the agent is authorized to call (canonical names; e.g.
    /// "read_file", "write_file", "bash").
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bounded_tools: Vec<String>,
    /// Tools that, if invoked, require human approval before execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalation_required: Vec<String>,
    /// Tools the agent must never invoke. Listed for documentation and to
    /// drive future hard-block hooks; v0.9.8 only records, does not enforce.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden: Vec<String>,
}

/// Provenance of a card -- where the data behind it came from. Helps later
/// commands explain "this card was generated automatically, you have not
/// approved it" vs "you registered this with `agent register`."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CardProvenance {
    /// Created by discovery (`treeship add --discover` / `treeship setup`).
    Discovered,
    /// Created by `treeship agent register`. Carries a signed certificate.
    Registered,
    /// Created via `treeship agent add --kind <kind>` for kinds that
    /// discovery cannot detect (remote VMs, generic wrappers).
    Manual,
}

impl CardProvenance {
    pub fn label(self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::Registered => "registered",
            Self::Manual     => "manual",
        }
    }
}

/// One Agent Card on disk. Designed to round-trip through `serde_json` and
/// to be human-readable so a user inspecting `.treeship/agents/<id>.json`
/// understands what each field means.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    /// Stable identifier derived from (surface, host, workspace). Filename
    /// stem in `.treeship/agents/`. Persistent across re-runs.
    pub agent_id: String,
    /// Free-form display name. User-editable; defaults to surface display.
    pub agent_name: String,
    /// The runtime surface (Claude Code, Cursor, Codex, ...). One of the
    /// shared discovery enum values.
    pub surface: AgentSurface,
    /// Connection modes Treeship intends to use to attach. Multiple modes
    /// are valid -- Claude Code uses both native-hook and mcp.
    pub connection_modes: Vec<ConnectionMode>,
    /// Expected coverage level given the chosen connection modes.
    pub coverage: CoverageLevel,
    /// The capabilities that bound this agent's actions.
    #[serde(default)]
    pub capabilities: CardCapabilities,
    /// Where this card came from.
    pub provenance: CardProvenance,
    /// Lifecycle status. Drives whether sessions accept this agent.
    pub status: CardStatus,
    /// Hostname where this card was created. Stops a card created on a
    /// laptop from accidentally being used on a remote VM with the same
    /// surface.
    pub host: String,
    /// Workspace this card belongs to. The path of the .treeship dir that
    /// owned the card when it was created.
    pub workspace: String,
    /// Optional model/provider attribution. Distinct from surface --
    /// Claude Code is a surface, "Anthropic Claude Opus 4.6" is a model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Free-form description / notes. Editable by the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// SHA-256 digest of the matching `.agent/certificate.json`, if a
    /// certificate has been registered. Lets `treeship agents review`
    /// confirm the on-disk cert hasn't drifted from the card's claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_digest: Option<String>,
    /// ID of the most recent session that involved this agent. None until
    /// a session closes referencing the card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_session_id: Option<String>,
    /// Receipt digest from the latest session involving this agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_receipt_digest: Option<String>,
    /// Creation timestamp (RFC3339).
    pub created_at: String,
    /// Last-modified timestamp (RFC3339). Updated on every write.
    pub updated_at: String,
}

impl AgentCard {
    /// Build a draft card from discovery output. Status is always Draft;
    /// promotion happens through `treeship agents review`.
    pub fn from_discovery(
        agent: &DiscoveredAgent,
        host: &str,
        workspace: &Path,
        now: &str,
    ) -> Self {
        Self {
            agent_id:               derive_agent_id(agent.surface, host, workspace),
            agent_name:             agent.display_name.clone(),
            surface:                agent.surface,
            connection_modes:       agent.connection_modes.clone(),
            coverage:               agent.coverage,
            capabilities:           CardCapabilities::default(),
            provenance:             CardProvenance::Discovered,
            status:                 CardStatus::Draft,
            host:                   host.to_string(),
            workspace:              workspace.to_string_lossy().into_owned(),
            model:                  None,
            description:            agent.note.clone(),
            certificate_digest:     None,
            latest_session_id:      None,
            latest_receipt_digest:  None,
            created_at:             now.to_string(),
            updated_at:             now.to_string(),
        }
    }
}

/// Stable derivation: SHA-256 of "<surface>|<host>|<workspace>", first 16
/// hex chars prefixed with `agent_`. Same surface on the same host+workspace
/// always collapses to the same ID, which is what makes idempotent
/// re-discovery possible.
pub fn derive_agent_id(surface: AgentSurface, host: &str, workspace: &Path) -> String {
    let workspace_canon = workspace.to_string_lossy();
    let mut hasher = Sha256::new();
    hasher.update(surface.kind().as_bytes());
    hasher.update(b"|");
    hasher.update(host.as_bytes());
    hasher.update(b"|");
    hasher.update(workspace_canon.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(2 * 16);
    for byte in &digest[..8] {
        use std::fmt::Write;
        write!(hex, "{byte:02x}").unwrap();
    }
    format!("agent_{hex}")
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Path resolution: the cards directory lives at `<config_dir>/agents/`
/// where `<config_dir>` is the directory holding the active config.json.
/// This pairs cards with the keystore they were created against, so a
/// project-local Treeship gets its own card store and a global one gets
/// another.
pub fn agents_dir_for(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("agents")
}

/// Filename for a card's id. Centralized so callers can't accidentally pick
/// inconsistent suffixes.
pub fn card_path(agents_dir: &Path, agent_id: &str) -> PathBuf {
    agents_dir.join(format!("{agent_id}.json"))
}

#[derive(Debug)]
pub enum CardError {
    Io(std::io::Error),
    Json(serde_json::Error),
    NotFound(String),
}

impl std::fmt::Display for CardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e)        => write!(f, "card io: {e}"),
            Self::Json(e)      => write!(f, "card json: {e}"),
            Self::NotFound(id) => write!(f, "no agent card with id {id:?}"),
        }
    }
}

impl std::error::Error for CardError {}
impl From<std::io::Error>    for CardError { fn from(e: std::io::Error) -> Self { Self::Io(e) } }
impl From<serde_json::Error> for CardError { fn from(e: serde_json::Error) -> Self { Self::Json(e) } }

/// Read every `.json` in the cards directory. Returns an empty Vec if the
/// dir doesn't exist yet -- a fresh Treeship project has no cards.
pub fn list(agents_dir: &Path) -> Result<Vec<AgentCard>, CardError> {
    if !agents_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(agents_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let card: AgentCard = serde_json::from_slice(&bytes)?;
        out.push(card);
    }
    out.sort_by(|a, b| a.agent_id.cmp(&b.agent_id));
    Ok(out)
}

/// Load one card by ID.
pub fn load(agents_dir: &Path, agent_id: &str) -> Result<AgentCard, CardError> {
    let path = card_path(agents_dir, agent_id);
    if !path.exists() {
        return Err(CardError::NotFound(agent_id.to_string()));
    }
    let bytes = std::fs::read(&path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Atomic write: temp file + rename. Permissions stay default (0644) -- the
/// card itself contains no secrets, only public attribution. The signing
/// keys behind any registered cert are still in `.treeship/keys/` at 0600.
pub fn save(agents_dir: &Path, card: &AgentCard) -> Result<(), CardError> {
    std::fs::create_dir_all(agents_dir)?;
    let path = card_path(agents_dir, &card.agent_id);
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(card)?;
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Insert-or-update by `agent_id`. If a card exists, fields are merged with
/// the new values winning; `created_at` is preserved from the existing
/// record so a re-discovered card doesn't lose its original creation time.
/// Returns the resulting card.
pub fn upsert(
    agents_dir: &Path,
    incoming: AgentCard,
    now: &str,
) -> Result<AgentCard, CardError> {
    let merged = match load(agents_dir, &incoming.agent_id) {
        Ok(existing) => AgentCard {
            created_at:             existing.created_at,
            updated_at:             now.to_string(),
            // Preserve user-meaningful state across re-discovery: don't
            // demote an Active card back to Draft just because a fresh
            // detection ran.
            status:                 keep_higher_status(existing.status, incoming.status),
            // Preserve session linkage: the new card from discovery has
            // none, but the existing record might.
            latest_session_id:      existing.latest_session_id.or(incoming.latest_session_id.clone()),
            latest_receipt_digest:  existing.latest_receipt_digest.or(incoming.latest_receipt_digest.clone()),
            certificate_digest:     incoming.certificate_digest.clone().or(existing.certificate_digest),
            ..incoming
        },
        Err(CardError::NotFound(_)) => incoming,
        Err(e) => return Err(e),
    };
    save(agents_dir, &merged)?;
    Ok(merged)
}

/// Promote a card's status. Returns `Err(CardError::NotFound)` if the card
/// doesn't exist.
pub fn set_status(
    agents_dir: &Path,
    agent_id: &str,
    new_status: CardStatus,
    now: &str,
) -> Result<AgentCard, CardError> {
    let mut card = load(agents_dir, agent_id)?;
    card.status = new_status;
    card.updated_at = now.to_string();
    save(agents_dir, &card)?;
    Ok(card)
}

/// Delete a card. Returns `Ok(())` even if the file didn't exist -- the
/// caller's intent is "this card should be gone," and we honor that
/// idempotently.
pub fn remove(agents_dir: &Path, agent_id: &str) -> Result<(), CardError> {
    let path = card_path(agents_dir, agent_id);
    match std::fs::remove_file(&path) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Pick the higher of two statuses. Used by `upsert` so re-discovery never
/// demotes a card.
fn keep_higher_status(existing: CardStatus, incoming: CardStatus) -> CardStatus {
    fn rank(s: CardStatus) -> u8 {
        match s {
            CardStatus::Draft       => 0,
            CardStatus::NeedsReview => 1,
            CardStatus::Active      => 2,
            CardStatus::Verified    => 3,
        }
    }
    if rank(existing) >= rank(incoming) { existing } else { incoming }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::discovery::{Confidence, ConnectionMode};
    use tempfile::tempdir;

    fn now() -> &'static str {
        "2026-04-29T20:00:00Z"
    }

    fn sample_discovery(surface: AgentSurface) -> DiscoveredAgent {
        DiscoveredAgent {
            surface,
            display_name:     surface.display().to_string(),
            connection_modes: vec![ConnectionMode::NativeHook, ConnectionMode::Mcp],
            coverage:         CoverageLevel::High,
            confidence:       Confidence::High,
            evidence:         vec![],
            note:             None,
        }
    }

    #[test]
    fn agent_id_is_stable() {
        let workspace = Path::new("/home/u/projects/proj-a");
        let id1 = derive_agent_id(AgentSurface::ClaudeCode, "machine-1", workspace);
        let id2 = derive_agent_id(AgentSurface::ClaudeCode, "machine-1", workspace);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("agent_"));
    }

    #[test]
    fn agent_id_changes_with_inputs() {
        let ws = Path::new("/home/u/projects/proj-a");
        let base = derive_agent_id(AgentSurface::ClaudeCode, "host", ws);
        // surface change
        assert_ne!(base, derive_agent_id(AgentSurface::CursorAgent, "host", ws));
        // host change
        assert_ne!(base, derive_agent_id(AgentSurface::ClaudeCode, "other", ws));
        // workspace change
        assert_ne!(base, derive_agent_id(AgentSurface::ClaudeCode, "host", Path::new("/elsewhere")));
    }

    #[test]
    fn save_load_round_trip() {
        let dir = tempdir().unwrap();
        let card = AgentCard::from_discovery(
            &sample_discovery(AgentSurface::ClaudeCode),
            "test-host",
            Path::new("/tmp/proj"),
            now(),
        );
        save(dir.path(), &card).unwrap();
        let loaded = load(dir.path(), &card.agent_id).unwrap();
        assert_eq!(loaded.agent_id, card.agent_id);
        assert_eq!(loaded.status, CardStatus::Draft);
        assert_eq!(loaded.surface, AgentSurface::ClaudeCode);
    }

    #[test]
    fn list_returns_sorted() {
        let dir = tempdir().unwrap();
        let a = AgentCard::from_discovery(
            &sample_discovery(AgentSurface::CursorAgent),
            "h",
            Path::new("/tmp/p"),
            now(),
        );
        let b = AgentCard::from_discovery(
            &sample_discovery(AgentSurface::ClaudeCode),
            "h",
            Path::new("/tmp/p"),
            now(),
        );
        save(dir.path(), &a).unwrap();
        save(dir.path(), &b).unwrap();
        let listed = list(dir.path()).unwrap();
        assert_eq!(listed.len(), 2);
        // Sorted by id (sha-derived order, but deterministic).
        assert!(listed[0].agent_id < listed[1].agent_id);
    }

    #[test]
    fn list_on_missing_dir_is_empty() {
        let dir = tempdir().unwrap();
        let absent = dir.path().join("nope");
        assert!(list(&absent).unwrap().is_empty());
    }

    #[test]
    fn upsert_does_not_demote_status() {
        let dir = tempdir().unwrap();
        // Plant an Active card.
        let mut active = AgentCard::from_discovery(
            &sample_discovery(AgentSurface::ClaudeCode),
            "h",
            Path::new("/tmp/p"),
            now(),
        );
        active.status = CardStatus::Active;
        save(dir.path(), &active).unwrap();

        // Discovery comes back with Draft (the default).
        let fresh_discovery = AgentCard::from_discovery(
            &sample_discovery(AgentSurface::ClaudeCode),
            "h",
            Path::new("/tmp/p"),
            "2026-04-30T10:00:00Z",
        );
        let merged = upsert(dir.path(), fresh_discovery, "2026-04-30T10:00:00Z").unwrap();

        assert_eq!(merged.status, CardStatus::Active);
        // created_at preserved from the original.
        assert_eq!(merged.created_at, now());
        // updated_at advanced.
        assert_eq!(merged.updated_at, "2026-04-30T10:00:00Z");
    }

    #[test]
    fn upsert_promotes_when_incoming_is_higher() {
        let dir = tempdir().unwrap();
        let draft = AgentCard::from_discovery(
            &sample_discovery(AgentSurface::ClaudeCode),
            "h",
            Path::new("/tmp/p"),
            now(),
        );
        save(dir.path(), &draft).unwrap();

        let mut incoming = draft.clone();
        incoming.status = CardStatus::NeedsReview;
        let merged = upsert(dir.path(), incoming, now()).unwrap();
        assert_eq!(merged.status, CardStatus::NeedsReview);
    }

    #[test]
    fn upsert_preserves_session_linkage() {
        let dir = tempdir().unwrap();
        let mut active = AgentCard::from_discovery(
            &sample_discovery(AgentSurface::ClaudeCode),
            "h",
            Path::new("/tmp/p"),
            now(),
        );
        active.latest_session_id = Some("ssn_abc".into());
        active.latest_receipt_digest = Some("sha256:deadbeef".into());
        save(dir.path(), &active).unwrap();

        let fresh = AgentCard::from_discovery(
            &sample_discovery(AgentSurface::ClaudeCode),
            "h",
            Path::new("/tmp/p"),
            now(),
        );
        let merged = upsert(dir.path(), fresh, now()).unwrap();
        assert_eq!(merged.latest_session_id.as_deref(), Some("ssn_abc"));
        assert_eq!(merged.latest_receipt_digest.as_deref(), Some("sha256:deadbeef"));
    }

    #[test]
    fn set_status_promotes() {
        let dir = tempdir().unwrap();
        let card = AgentCard::from_discovery(
            &sample_discovery(AgentSurface::ClaudeCode),
            "h",
            Path::new("/tmp/p"),
            now(),
        );
        save(dir.path(), &card).unwrap();
        let promoted = set_status(dir.path(), &card.agent_id, CardStatus::Active, "2026-05-01T00:00:00Z").unwrap();
        assert_eq!(promoted.status, CardStatus::Active);
        assert_eq!(promoted.updated_at, "2026-05-01T00:00:00Z");
    }

    #[test]
    fn set_status_unknown_id_returns_not_found() {
        let dir = tempdir().unwrap();
        let err = set_status(dir.path(), "agent_does_not_exist", CardStatus::Active, now())
            .err()
            .unwrap();
        assert!(matches!(err, CardError::NotFound(_)));
    }

    #[test]
    fn remove_idempotent() {
        let dir = tempdir().unwrap();
        let card = AgentCard::from_discovery(
            &sample_discovery(AgentSurface::ClaudeCode),
            "h",
            Path::new("/tmp/p"),
            now(),
        );
        save(dir.path(), &card).unwrap();
        remove(dir.path(), &card.agent_id).unwrap();
        // Second call must not error.
        remove(dir.path(), &card.agent_id).unwrap();
        // And the file is actually gone.
        assert!(!card_path(dir.path(), &card.agent_id).exists());
    }

    #[test]
    fn agents_dir_is_sibling_of_config() {
        let cfg = Path::new("/var/data/.treeship/config.json");
        assert_eq!(agents_dir_for(cfg), Path::new("/var/data/.treeship/agents"));
    }
}
