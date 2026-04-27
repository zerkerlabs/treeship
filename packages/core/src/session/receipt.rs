//! Session Receipt composer.
//!
//! Builds the canonical Session Receipt JSON from session events,
//! artifact store, and Merkle tree. The receipt is the composed
//! package-level artifact that unifies an entire session.

use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use crate::merkle::{MerkleTree, InclusionProof};

use super::event::SessionEvent;
use super::graph::AgentGraph;
use super::manifest::{
    HostInfo, LifecycleMode, Participants, SessionManifest, SessionStatus, ToolInfo,
};
use super::render::RenderConfig;
use super::side_effects::SideEffects;

/// Receipt type identifier.
pub const RECEIPT_TYPE: &str = "treeship/session-receipt/v1";

/// Current receipt schema version. Receipts without this field are treated
/// as schema "0" and verified under legacy rules (pre-v0.9.0 shape).
pub const RECEIPT_SCHEMA_VERSION: &str = "1";

// ── Top-level receipt ────────────────────────────────────────────────

/// The complete Session Receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReceipt {
    /// Always "treeship/session-receipt/v1".
    #[serde(rename = "type")]
    pub type_: String,

    /// Schema version. Absent on pre-v0.9.0 receipts (treated as "0").
    /// Set to "1" for v0.9.0+ receipts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_version: Option<String>,

    pub session: SessionSection,
    pub participants: Participants,
    pub hosts: Vec<HostInfo>,
    pub tools: Vec<ToolInfo>,
    pub agent_graph: AgentGraph,
    pub timeline: Vec<TimelineEntry>,
    pub side_effects: SideEffects,
    pub artifacts: Vec<ArtifactEntry>,
    pub proofs: ProofsSection,
    pub merkle: MerkleSection,
    pub render: RenderConfig,
    /// Tool usage summary: declared vs actual tools used during the session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_usage: Option<ToolUsage>,
}

/// Tool authorization and usage summary for the session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolUsage {
    /// Tools declared as authorized (from declaration.json).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declared: Vec<String>,
    /// Tools actually called during the session with invocation counts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actual: Vec<ToolUsageEntry>,
    /// Tools called that were NOT in the declared list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unauthorized: Vec<String>,
}

/// A single tool's usage count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolUsageEntry {
    pub tool_name: String,
    pub count: u32,
}

/// Session metadata section of the receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSection {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub mode: LifecycleMode,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<String>,
    pub status: SessionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Ship ID this session ran under, parsed from the manifest actor URI
    /// (`ship://<ship_id>`). Absent on pre-v0.9.0 receipts or when the actor
    /// URI was not a ship:// URI (e.g. human://alice for a human-led session).
    /// Cross-verification uses this to check that a receipt and a presented
    /// Agent Certificate reference the same ship.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ship_id: Option<String>,
    /// Structured narrative for human review. All fields optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub narrative: Option<Narrative>,
    /// Cumulative input tokens across all agents.
    #[serde(default)]
    pub total_tokens_in: u64,
    /// Cumulative output tokens across all agents.
    #[serde(default)]
    pub total_tokens_out: u64,
}


/// Structured narrative for the session summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Narrative {
    /// One-line headline: "Verifier refactor completed."
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headline: Option<String>,
    /// Multi-sentence summary of what happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// What should be reviewed before trusting the output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<String>,
}

/// A single timeline entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEntry {
    pub sequence_no: u64,
    pub timestamp: String,
    pub event_id: String,
    pub event_type: String,
    pub agent_instance_id: String,
    pub agent_name: String,
    pub host_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

/// An artifact referenced in the session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactEntry {
    pub artifact_id: String,
    pub payload_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_at: Option<String>,
}

/// Proofs section of the receipt.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProofsSection {
    #[serde(default)]
    pub signature_count: u32,
    #[serde(default)]
    pub signatures_valid: bool,
    #[serde(default)]
    pub merkle_root_valid: bool,
    #[serde(default)]
    pub inclusion_proofs_count: u32,
    #[serde(default)]
    pub zk_proofs_present: bool,
}

/// Merkle section of the receipt.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MerkleSection {
    pub leaf_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inclusion_proofs: Vec<InclusionProofEntry>,
}

/// A Merkle inclusion proof entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProofEntry {
    pub artifact_id: String,
    pub leaf_index: usize,
    pub proof: InclusionProof,
}

// ── Composer ─────────────────────────────────────────────────────────

/// Composes a Session Receipt from events and artifacts.
pub struct ReceiptComposer;

impl ReceiptComposer {
    /// Compose a receipt from a session manifest, events, and optional artifact entries.
    pub fn compose(
        manifest: &SessionManifest,
        events: &[SessionEvent],
        artifact_entries: Vec<ArtifactEntry>,
    ) -> SessionReceipt {
        // Build agent graph
        let agent_graph = AgentGraph::from_events(events);

        // Build side effects
        let side_effects = SideEffects::from_events(events);

        // Build timeline from all events
        let mut timeline: Vec<TimelineEntry> = events.iter().map(|e| {
            TimelineEntry {
                sequence_no: e.sequence_no,
                timestamp: e.timestamp.clone(),
                event_id: e.event_id.clone(),
                event_type: event_type_label(&e.event_type),
                agent_instance_id: e.agent_instance_id.clone(),
                agent_name: e.agent_name.clone(),
                host_id: e.host_id.clone(),
                summary: event_summary(&e.event_type),
            }
        }).collect();

        // Sort by (timestamp, sequence_no, event_id) for determinism
        timeline.sort_by(|a, b| {
            a.timestamp.cmp(&b.timestamp)
                .then(a.sequence_no.cmp(&b.sequence_no))
                .then(a.event_id.cmp(&b.event_id))
        });

        // Compute participants from graph
        let participants = compute_participants(&agent_graph, manifest);

        // Compute hosts and tools from events
        let hosts = compute_hosts(events, &manifest.hosts);
        let tools = compute_tools(events, &manifest.tools);

        // Compute duration from the session close event if present
        let duration_ms = events.iter().find_map(|e| {
            if let super::event::EventType::SessionClosed { duration_ms, .. } = &e.event_type {
                *duration_ms
            } else {
                None
            }
        });

        // Build Merkle tree from artifact IDs
        let (merkle_section, merkle_tree) = build_merkle(&artifact_entries);

        // Proofs section. zk_proofs_present defaults to false here;
        // the CLI caller sets it to true after compose if proof files
        // exist in the session directory.
        let proofs = ProofsSection {
            signature_count: artifact_entries.len() as u32,
            signatures_valid: true, // Caller should verify
            merkle_root_valid: merkle_tree.is_some(),
            inclusion_proofs_count: merkle_section.inclusion_proofs.len() as u32,
            zk_proofs_present: false,
        };

        // Compute cost/token totals from agent graph
        // Cost is deliberately not aggregated. See event.rs comment.
        let total_tokens_in: u64 = agent_graph.nodes.iter().map(|n| n.tokens_in).sum();
        let total_tokens_out: u64 = agent_graph.nodes.iter().map(|n| n.tokens_out).sum();

        // Session section
        let session = SessionSection {
            id: manifest.session_id.clone(),
            name: manifest.name.clone(),
            mode: manifest.mode.clone(),
            started_at: manifest.started_at.clone(),
            ended_at: manifest.closed_at.clone(),
            status: manifest.status.clone(),
            duration_ms,
            ship_id: parse_ship_id_from_actor(&manifest.actor),
            narrative: manifest.summary.as_ref().map(|s| Narrative {
                headline: manifest.name.clone(),
                summary: Some(s.clone()),
                review: None,
            }),
            total_tokens_in,
            total_tokens_out,
        };

        // Render config
        let render = RenderConfig {
            title: manifest.name.clone(),
            theme: None,
            sections: RenderConfig::default_sections(),
            generate_preview: true,
        };

        // Derive tool usage from side effects + manifest authorized_tools
        let tool_usage = derive_tool_usage(&side_effects, &manifest.authorized_tools);

        SessionReceipt {
            type_: RECEIPT_TYPE.into(),
            schema_version: Some(RECEIPT_SCHEMA_VERSION.into()),
            session,
            participants,
            hosts,
            tools,
            agent_graph,
            timeline,
            side_effects,
            artifacts: artifact_entries,
            proofs,
            merkle: merkle_section,
            render,
            tool_usage,
        }
    }

    /// Produce deterministic canonical JSON bytes from a receipt.
    ///
    /// Uses serde's field-declaration-order serialization for determinism.
    /// The resulting bytes are suitable for hashing.
    pub fn to_canonical_json(receipt: &SessionReceipt) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(receipt)
    }

    /// Compute SHA-256 digest of the canonical receipt JSON.
    pub fn digest(receipt: &SessionReceipt) -> Result<String, serde_json::Error> {
        let bytes = Self::to_canonical_json(receipt)?;
        let hash = Sha256::digest(&bytes);
        Ok(format!("sha256:{}", hex::encode(hash)))
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

fn compute_participants(graph: &AgentGraph, manifest: &SessionManifest) -> Participants {
    use std::collections::BTreeSet;

    let mut tool_runtimes: BTreeSet<String> = BTreeSet::new();
    // Count unique agents
    let total_agents = graph.nodes.len() as u32;
    let spawned_subagents = graph.spawn_count();
    let handoffs = graph.handoff_count();
    let max_depth = graph.max_depth();
    let host_ids = graph.host_ids();

    // Collect tool runtimes from events in manifest
    for tool in &manifest.tools {
        if let Some(ref rt) = tool.tool_runtime_id {
            tool_runtimes.insert(rt.clone());
        }
    }

    // Find root agent (depth 0, first started)
    let root = graph.nodes.iter()
        .filter(|n| n.depth == 0)
        .min_by_key(|n| n.started_at.as_deref().unwrap_or(""))
        .map(|n| n.agent_instance_id.clone());

    // Find final output agent (last completed at max depth or last completed overall)
    let final_output = graph.nodes.iter()
        .filter(|n| n.completed_at.is_some())
        .max_by_key(|n| n.completed_at.as_deref().unwrap_or(""))
        .map(|n| n.agent_instance_id.clone());

    Participants {
        root_agent_instance_id: root.or(manifest.participants.root_agent_instance_id.clone()),
        final_output_agent_instance_id: final_output.or(manifest.participants.final_output_agent_instance_id.clone()),
        total_agents,
        spawned_subagents,
        handoffs,
        max_depth,
        hosts: host_ids.len() as u32,
        tool_runtimes: tool_runtimes.len() as u32,
    }
}

fn compute_hosts(events: &[SessionEvent], manifest_hosts: &[HostInfo]) -> Vec<HostInfo> {
    use std::collections::BTreeMap;

    let mut hosts: BTreeMap<String, HostInfo> = BTreeMap::new();

    // Seed from manifest
    for h in manifest_hosts {
        hosts.insert(h.host_id.clone(), h.clone());
    }

    // Discover from events
    for e in events {
        hosts.entry(e.host_id.clone()).or_insert_with(|| HostInfo {
            host_id: e.host_id.clone(),
            hostname: None,
            os: None,
            arch: None,
        });
    }

    hosts.into_values().collect()
}

fn compute_tools(events: &[SessionEvent], manifest_tools: &[ToolInfo]) -> Vec<ToolInfo> {
    use std::collections::BTreeMap;

    let mut tools: BTreeMap<String, ToolInfo> = BTreeMap::new();

    // Seed from manifest
    for t in manifest_tools {
        tools.insert(t.tool_id.clone(), t.clone());
    }

    // Count tool invocations from events
    for e in events {
        if let super::event::EventType::AgentCalledTool { ref tool_name, .. } = e.event_type {
            let entry = tools.entry(tool_name.clone()).or_insert_with(|| ToolInfo {
                tool_id: tool_name.clone(),
                tool_name: tool_name.clone(),
                tool_runtime_id: e.tool_runtime_id.clone(),
                invocation_count: 0,
            });
            entry.invocation_count += 1;
        }
    }

    tools.into_values().collect()
}

fn build_merkle(artifacts: &[ArtifactEntry]) -> (MerkleSection, Option<MerkleTree>) {
    if artifacts.is_empty() {
        return (MerkleSection::default(), None);
    }

    let mut tree = MerkleTree::new();
    for art in artifacts {
        tree.append(&art.artifact_id);
    }

    let root = tree.root().map(|r| format!("mroot_{}", hex::encode(r)));

    // Build inclusion proofs for each artifact
    let inclusion_proofs: Vec<InclusionProofEntry> = artifacts.iter().enumerate()
        .filter_map(|(i, art)| {
            tree.inclusion_proof(i).map(|proof| InclusionProofEntry {
                artifact_id: art.artifact_id.clone(),
                leaf_index: i,
                proof,
            })
        })
        .collect();

    let section = MerkleSection {
        leaf_count: artifacts.len(),
        root,
        checkpoint_id: None,
        inclusion_proofs,
    };

    (section, Some(tree))
}

/// Extract the ship_id from an actor URI of the form `ship://<id>`.
/// Returns None for other URI schemes (human://, agent://) or malformed values.
pub fn parse_ship_id_from_actor(actor: &str) -> Option<String> {
    let rest = actor.strip_prefix("ship://")?;
    // Strip any trailing path segment so `ship://ship_abc/foo` -> `ship_abc`.
    let id = rest.split('/').next().unwrap_or(rest);
    if id.is_empty() { None } else { Some(id.to_string()) }
}

/// Extract a human-readable label from an EventType.
/// Derive tool usage from side effects and the declared authorized tools list.
///
/// Bug Codex caught in adversarial review: previously this function counted
/// only `side_effects.tool_invocations` (built from `EventType::AgentCalledTool`).
/// But Claude Code's PostToolUse hook emits SPECIALIZED events for built-in
/// tools (`agent.wrote_file` for Write/Edit, `agent.completed_process` for
/// Bash, `agent.read_file` for Read, etc) -- those events never landed in
/// `tool_invocations`, so a certificate that omitted "Bash" or "Write"
/// passed cross-verification cleanly even when the agent ran them.
///
/// The fix: also count side effects from specialized event types under
/// canonical tool names that match what an operator would declare in
/// `bounded_actions`. Naming follows Claude Code conventions (Read, Write,
/// Bash, WebFetch) since those are the tools users actually declare. A
/// cert that uses an alternate naming scheme (e.g. `files.write`) needs
/// to declare both for now -- a future TODO is canonical mapping at the
/// cert layer.
/// Side-effect canonical mapping for tool authorization.
///
/// Each entry maps a side-effect bucket to a canonical tool name AND a
/// list of accepted aliases. The canonical name is what gets recorded
/// in `tool_usage.actual`. Any alias from the authorized_tools list
/// counts as authorization for the canonical name.
///
/// Codex round-2 caught two bugs in the round-1 fix:
///
/// 1. The round-1 mapping used Claude-Code TitleCase ("Read", "Write",
///    "Bash") but the existing CLI -- `treeship declare --tools
///    read_file,write_file,bash` per declare.rs:80 and `treeship agent
///    register --tools read_file,write_file,bash` per main.rs:226 --
///    teaches users lowercase snake_case names. So a cert that follows
///    the documented convention got every actual tool flagged as
///    unauthorized. Aliases close that gap: declarations in either
///    convention authorize the same canonical entry.
///
/// 2. The round-1 logic counted side effects regardless of provenance.
///    `git-reconcile` synthetic writes (the backstop layer) and
///    `session-event-cli` manual records were registering as tool use
///    even though no actual tool was directly attributed for them. So
///    a build script that touched a file made the receipt say "Write
///    tool was used", and the cert had to authorize Write or fail
///    cross-verify -- even though the agent never invoked any Write
///    tool. Below, only `hook` / `mcp` / `shell-wrap` (and untagged
///    legacy events) count toward tool usage. Everything else is
///    backstop evidence: it surfaces in the receipt's "Files changed"
///    section so the reader sees the change, but it does NOT claim
///    that an agent tool was the proximate cause.
const TOOL_ALIASES: &[(&str, &[&str])] = &[
    // Canonical first; rest are accepted aliases.
    ("read_file",  &["read_file", "Read"]),
    ("write_file", &["write_file", "Write", "Edit", "MultiEdit", "NotebookEdit", "edit_file"]),
    ("bash",       &["bash", "Bash", "shell"]),
    ("web_fetch",  &["web_fetch", "WebFetch", "webfetch"]),
];

/// Returns true iff `source` represents a direct tool attribution that
/// should count toward `tool_usage.actual`. Backstop or
/// recording-channel sources (`git-reconcile`, `session-event-cli`,
/// `daemon-atime`) are NOT direct attribution -- they witness that
/// something happened without claiming a specific tool caused it. None
/// (no source tag) defaults to true for backward compat with legacy
/// hook-emitted events that predated the source field.
fn source_attributes_a_tool(source: Option<&str>) -> bool {
    matches!(
        source,
        None | Some("hook") | Some("mcp") | Some("shell-wrap"),
    )
}

/// Counts side effects by canonical tool name, filtering out
/// non-attribution sources (git-reconcile, session-event-cli, etc).
fn count_attributed<'a, F>(
    items: usize,
    source_at: F,
    canonical: &str,
    counts: &mut std::collections::BTreeMap<String, u32>,
)
where
    F: Fn(usize) -> Option<&'a str>,
{
    let n: u32 = (0..items)
        .filter(|i| source_attributes_a_tool(source_at(*i)))
        .count() as u32;
    if n > 0 {
        *counts.entry(canonical.to_string()).or_insert(0) += n;
    }
}

fn derive_tool_usage(
    side_effects: &SideEffects,
    authorized_tools: &[String],
) -> Option<ToolUsage> {
    use std::collections::BTreeMap;

    let total_specialized = side_effects.files_read.len()
        + side_effects.files_written.len()
        + side_effects.processes.len()
        + side_effects.network_connections.len();

    if side_effects.tool_invocations.is_empty()
        && total_specialized == 0
        && authorized_tools.is_empty()
    {
        return None;
    }

    let mut counts: BTreeMap<String, u32> = BTreeMap::new();

    // Generic agent.called_tool events use the tool's actual name.
    // The MCP bridge writes meta.source = "mcp-bridge" (which is not
    // in source_attributes_a_tool's allow list) but tool_invocations
    // come ONLY from agent.called_tool, which is direct attribution
    // by definition -- so count all of them, no source filter applies
    // here. (The bridge tool name is the source.)
    for inv in &side_effects.tool_invocations {
        *counts.entry(inv.tool_name.clone()).or_insert(0) += 1;
    }

    // Specialized side effects, source-filtered: only direct
    // attribution (hook / mcp / shell-wrap / untagged-legacy) counts.
    // git-reconcile and friends surface in the "Files changed" section
    // for the reader but do NOT inflate tool_usage.
    let fr = &side_effects.files_read;
    count_attributed(
        fr.len(),
        |i| fr[i].source.as_deref(),
        "read_file",
        &mut counts,
    );
    let fw = &side_effects.files_written;
    count_attributed(
        fw.len(),
        |i| fw[i].source.as_deref(),
        "write_file",
        &mut counts,
    );
    let pr = &side_effects.processes;
    count_attributed(
        pr.len(),
        |i| pr[i].source.as_deref(),
        "bash",
        &mut counts,
    );
    // network_connections has no source field today; treat all as
    // attributed (this matches the round-1 behavior since there's no
    // backstop layer producing network entries).
    if !side_effects.network_connections.is_empty() {
        *counts.entry("web_fetch".to_string()).or_insert(0) +=
            side_effects.network_connections.len() as u32;
    }

    let actual: Vec<ToolUsageEntry> = counts.iter()
        .map(|(name, &count)| ToolUsageEntry { tool_name: name.clone(), count })
        .collect();

    // Authorization check uses alias resolution: an actual tool is
    // unauthorized only if NONE of its aliases are in the declared
    // list. So a declaration of "read_file" authorizes both "Read"
    // (Claude convention) and "read_file" (CLI convention) when they
    // produce the canonical "read_file" actual entry.
    let unauthorized = if authorized_tools.is_empty() {
        Vec::new()
    } else {
        let declared_set: std::collections::BTreeSet<&str> = authorized_tools.iter()
            .map(|s| s.as_str())
            .collect();
        counts.keys()
            .filter(|actual_name| !is_authorized(actual_name, &declared_set))
            .cloned()
            .collect()
    };

    Some(ToolUsage {
        declared: authorized_tools.to_vec(),
        actual,
        unauthorized,
    })
}

/// Returns true if `actual_name` (or any of its declared aliases) is
/// in the declared set. Aliases mean a cert can use either Claude
/// convention or snake_case CLI convention and still authorize the
/// same canonical bucket.
fn is_authorized(actual_name: &str, declared_set: &std::collections::BTreeSet<&str>) -> bool {
    // Direct hit: the declared set names this tool exactly.
    if declared_set.contains(actual_name) {
        return true;
    }
    // Alias hit: walk the canonical mapping and see if any alias of
    // the canonical bucket the actual_name belongs to is in declared.
    for (canonical, aliases) in TOOL_ALIASES {
        if *canonical == actual_name || aliases.contains(&actual_name) {
            for alias in *aliases {
                if declared_set.contains(*alias) {
                    return true;
                }
            }
            return false;
        }
    }
    false
}

fn event_type_label(et: &super::event::EventType) -> String {
    use super::event::EventType::*;
    match et {
        SessionStarted => "session.started",
        SessionClosed { .. } => "session.closed",
        AgentStarted { .. } => "agent.started",
        AgentSpawned { .. } => "agent.spawned",
        AgentHandoff { .. } => "agent.handoff",
        AgentCollaborated { .. } => "agent.collaborated",
        AgentReturned { .. } => "agent.returned",
        AgentCompleted { .. } => "agent.completed",
        AgentFailed { .. } => "agent.failed",
        AgentCalledTool { .. } => "agent.called_tool",
        AgentReadFile { .. } => "agent.read_file",
        AgentWroteFile { .. } => "agent.wrote_file",
        AgentOpenedPort { .. } => "agent.opened_port",
        AgentConnectedNetwork { .. } => "agent.connected_network",
        AgentStartedProcess { .. } => "agent.started_process",
        AgentCompletedProcess { .. } => "agent.completed_process",
        AgentDecision { .. } => "agent.decision",
    }.into()
}

/// Optional human-readable summary from an EventType.
fn event_summary(et: &super::event::EventType) -> Option<String> {
    use super::event::EventType::*;
    match et {
        SessionStarted => Some("Session started".into()),
        SessionClosed { summary, .. } => summary.clone().or(Some("Session closed".into())),
        AgentSpawned { reason, .. } => reason.clone(),
        AgentHandoff { from_agent_instance_id, to_agent_instance_id, .. } => {
            Some(format!("{from_agent_instance_id} -> {to_agent_instance_id}"))
        }
        AgentCalledTool { tool_name, .. } => Some(format!("Called {tool_name}")),
        AgentReadFile { file_path, .. } => Some(format!("Read {file_path}")),
        AgentWroteFile { file_path, .. } => Some(format!("Wrote {file_path}")),
        AgentOpenedPort { port, .. } => Some(format!("Opened port {port}")),
        AgentConnectedNetwork { destination, .. } => Some(format!("Connected to {destination}")),
        AgentStartedProcess { process_name, .. } => Some(format!("Started {process_name}")),
        AgentCompletedProcess { process_name, exit_code, .. } => {
            Some(format!("Completed {process_name} (exit {})", exit_code.unwrap_or(-1)))
        }
        AgentCompleted { termination_reason } => termination_reason.clone().or(Some("Agent completed".into())),
        AgentFailed { reason } => reason.clone().or(Some("Agent failed".into())),
        AgentDecision { model, summary, provider, .. } => {
            let mut parts = Vec::new();
            if let Some(s) = summary { parts.push(s.clone()); }
            if let Some(m) = model { parts.push(format!("model: {m}")); }
            if let Some(p) = provider { parts.push(format!("via {p}")); }
            if parts.is_empty() { Some("LLM decision".into()) } else { Some(parts.join(" | ")) }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::event::*;

    fn make_manifest() -> SessionManifest {
        SessionManifest::new(
            "ssn_001".into(),
            "agent://test".into(),
            "2026-04-05T08:00:00Z".into(),
            1743843600000,
        )
    }

    /// Module-level event constructor so the tool-authorization regression
    /// tests below can reuse it without each redefining the closure.
    fn mk(seq: u64, inst: &str, et: EventType) -> SessionEvent {
        SessionEvent {
            session_id: "ssn_001".into(),
            event_id: format!("evt_{:016x}", seq),
            timestamp: format!("2026-04-05T08:{:02}:00Z", seq),
            sequence_no: seq,
            trace_id: "trace_1".into(),
            span_id: format!("span_{seq}"),
            parent_span_id: None,
            agent_id: format!("agent://{inst}"),
            agent_instance_id: inst.into(),
            agent_name: inst.into(),
            agent_role: None,
            host_id: "host_1".into(),
            tool_runtime_id: None,
            event_type: et,
            artifact_ref: None,
            meta: None,
        }
    }

    fn make_events() -> Vec<SessionEvent> {
        vec![
            mk(0, "root", EventType::SessionStarted),
            mk(1, "root", EventType::AgentStarted { parent_agent_instance_id: None }),
            mk(2, "worker", EventType::AgentSpawned { spawned_by_agent_instance_id: "root".into(), reason: Some("review".into()) }),
            mk(3, "worker", EventType::AgentCalledTool { tool_name: "read_file".into(), tool_input_digest: None, tool_output_digest: None, duration_ms: Some(5) }),
            mk(4, "worker", EventType::AgentWroteFile { file_path: "src/fix.rs".into(), digest: None, operation: None, additions: None, deletions: None }),
            mk(5, "worker", EventType::AgentCompleted { termination_reason: None }),
            mk(6, "root", EventType::SessionClosed { summary: Some("Done".into()), duration_ms: Some(360000) }),
        ]
    }

    #[test]
    fn compose_receipt() {
        let manifest = make_manifest();
        let events = make_events();
        let artifacts = vec![
            ArtifactEntry { artifact_id: "art_001".into(), payload_type: "action".into(), digest: None, signed_at: None },
            ArtifactEntry { artifact_id: "art_002".into(), payload_type: "action".into(), digest: None, signed_at: None },
        ];

        let receipt = ReceiptComposer::compose(&manifest, &events, artifacts);

        assert_eq!(receipt.type_, RECEIPT_TYPE);
        assert_eq!(receipt.session.id, "ssn_001");
        assert_eq!(receipt.timeline.len(), 7);
        assert_eq!(receipt.agent_graph.nodes.len(), 2); // root + worker
        assert_eq!(receipt.side_effects.files_written.len(), 1);
        assert_eq!(receipt.merkle.leaf_count, 2);
        assert!(receipt.merkle.root.is_some());
    }

    #[test]
    fn new_receipts_carry_schema_version() {
        let manifest = make_manifest();
        let events = make_events();
        let artifacts = vec![
            ArtifactEntry { artifact_id: "art_001".into(), payload_type: "action".into(), digest: None, signed_at: None },
        ];
        let receipt = ReceiptComposer::compose(&manifest, &events, artifacts);
        assert_eq!(receipt.schema_version.as_deref(), Some(RECEIPT_SCHEMA_VERSION));
        // And it shows up in canonical JSON.
        let json = String::from_utf8(ReceiptComposer::to_canonical_json(&receipt).unwrap()).unwrap();
        assert!(json.contains(r#""schema_version":"1""#), "missing schema_version: {json}");
    }

    #[test]
    fn legacy_receipt_without_schema_version_round_trips_byte_identical() {
        // Simulate a pre-v0.9.0 receipt by composing one and stripping the
        // schema_version field. Re-serializing must produce byte-identical
        // output so the package-level determinism check keeps passing for
        // old receipts that nobody can re-sign.
        let manifest = make_manifest();
        let events = make_events();
        let artifacts = vec![
            ArtifactEntry { artifact_id: "art_001".into(), payload_type: "action".into(), digest: None, signed_at: None },
        ];
        let mut receipt = ReceiptComposer::compose(&manifest, &events, artifacts);
        receipt.schema_version = None; // mimic a legacy receipt

        let original = ReceiptComposer::to_canonical_json(&receipt).unwrap();
        // Verify the field is omitted, not serialized as null.
        let original_str = std::str::from_utf8(&original).unwrap();
        assert!(!original_str.contains("schema_version"),
            "schema_version must be skipped when None");

        let parsed: SessionReceipt = serde_json::from_slice(&original).unwrap();
        assert!(parsed.schema_version.is_none(), "legacy receipts must parse with schema_version=None");

        let reserialized = ReceiptComposer::to_canonical_json(&parsed).unwrap();
        assert_eq!(original, reserialized,
            "legacy receipt must round-trip byte-identical so package determinism check passes");
    }

    #[test]
    fn canonical_json_is_deterministic() {
        let manifest = make_manifest();
        let events = make_events();
        let artifacts = vec![
            ArtifactEntry { artifact_id: "art_001".into(), payload_type: "action".into(), digest: None, signed_at: None },
        ];

        let r1 = ReceiptComposer::compose(&manifest, &events, artifacts.clone());
        let r2 = ReceiptComposer::compose(&manifest, &events, artifacts);

        let j1 = ReceiptComposer::to_canonical_json(&r1).unwrap();
        let j2 = ReceiptComposer::to_canonical_json(&r2).unwrap();
        assert_eq!(j1, j2);

        let d1 = ReceiptComposer::digest(&r1).unwrap();
        let d2 = ReceiptComposer::digest(&r2).unwrap();
        assert_eq!(d1, d2);
    }

    // ── Tool authorization regression tests (Codex finding #1) ──
    //
    // Specialized event types (agent.wrote_file, agent.completed_process,
    // agent.read_file) must contribute to tool_usage.actual so that a
    // certificate's bounded_actions list can correctly flag unauthorized
    // built-in tool usage. Before this fix, only agent.called_tool fed
    // tool_usage.actual, so a cert that omitted "Bash" still passed even
    // when the agent ran Bash via Claude Code's built-in.

    fn manifest_with_authorized(tools: Vec<&str>) -> SessionManifest {
        let mut m = make_manifest();
        m.authorized_tools = tools.into_iter().map(String::from).collect();
        m
    }

    #[test]
    fn cert_omitting_bash_flags_unauthorized_when_session_runs_bash() {
        // Cert uses CLI-documented snake_case names (declare.rs:80,
        // main.rs:226). Round-2 fix: canonical actual is "bash" not
        // "Bash"; round-1 was flagging mismatches the wrong way.
        let manifest = manifest_with_authorized(vec!["read_file", "write_file"]); // NO bash
        let events = vec![
            mk(0, "root", EventType::SessionStarted),
            mk(1, "agent", EventType::AgentCompletedProcess {
                process_name: "rm -rf /".into(),
                exit_code: Some(0),
                duration_ms: Some(50),
                command: Some("rm -rf /".into()),
            }),
            mk(2, "root", EventType::SessionClosed { summary: None, duration_ms: Some(1000) }),
        ];
        let receipt = ReceiptComposer::compose(&manifest, &events, vec![]);
        let tu = receipt.tool_usage.expect("tool_usage must be populated");
        assert!(
            tu.unauthorized.iter().any(|t| t == "bash"),
            "bash must be flagged as unauthorized when cert omits it; got unauthorized={:?}, actual={:?}",
            tu.unauthorized, tu.actual,
        );
    }

    #[test]
    fn cert_omitting_write_flags_unauthorized_when_session_writes_file() {
        let manifest = manifest_with_authorized(vec!["read_file", "bash"]); // NO write_file
        let events = vec![
            mk(0, "root", EventType::SessionStarted),
            mk(1, "agent", EventType::AgentWroteFile {
                file_path: "src/secret.rs".into(),
                digest: None, operation: Some("modified".into()),
                additions: Some(10), deletions: Some(0),
            }),
            mk(2, "root", EventType::SessionClosed { summary: None, duration_ms: Some(1000) }),
        ];
        let receipt = ReceiptComposer::compose(&manifest, &events, vec![]);
        let tu = receipt.tool_usage.expect("tool_usage must be populated");
        assert!(
            tu.unauthorized.iter().any(|t| t == "write_file"),
            "write_file must be flagged as unauthorized when cert omits it; got unauthorized={:?}, actual={:?}",
            tu.unauthorized, tu.actual,
        );
    }

    #[test]
    fn cert_includes_read_write_bash_passes_clean_when_all_used() {
        let manifest = manifest_with_authorized(vec!["read_file", "write_file", "bash"]);
        let events = vec![
            mk(0, "root", EventType::SessionStarted),
            mk(1, "agent", EventType::AgentReadFile { file_path: "package.json".into(), digest: None }),
            mk(2, "agent", EventType::AgentWroteFile {
                file_path: "src/lib.rs".into(),
                digest: None, operation: Some("modified".into()),
                additions: Some(5), deletions: Some(2),
            }),
            mk(3, "agent", EventType::AgentCompletedProcess {
                process_name: "bun test".into(),
                exit_code: Some(0), duration_ms: Some(2000),
                command: Some("bun test".into()),
            }),
            mk(4, "root", EventType::SessionClosed { summary: None, duration_ms: Some(5000) }),
        ];
        let receipt = ReceiptComposer::compose(&manifest, &events, vec![]);
        let tu = receipt.tool_usage.expect("tool_usage must be populated");
        assert!(
            tu.unauthorized.is_empty(),
            "all tools declared in cert should pass clean; got unauthorized={:?}",
            tu.unauthorized,
        );
        // The actual list uses canonical lowercase names that match what
        // `treeship declare --tools` and `treeship agent register --tools`
        // teach (declare.rs:80, main.rs:226).
        let actual_names: std::collections::BTreeSet<String> =
            tu.actual.iter().map(|e| e.tool_name.clone()).collect();
        assert!(actual_names.contains("read_file"));
        assert!(actual_names.contains("write_file"));
        assert!(actual_names.contains("bash"));
    }

    #[test]
    fn webfetch_unauthorized_flagged_when_cert_omits_it() {
        let manifest = manifest_with_authorized(vec!["read_file", "write_file", "bash"]); // NO web_fetch
        let events = vec![
            mk(0, "root", EventType::SessionStarted),
            mk(1, "agent", EventType::AgentConnectedNetwork {
                destination: "evil.example.com".into(),
                port: Some(443),
            }),
            mk(2, "root", EventType::SessionClosed { summary: None, duration_ms: Some(1000) }),
        ];
        let receipt = ReceiptComposer::compose(&manifest, &events, vec![]);
        let tu = receipt.tool_usage.expect("tool_usage must be populated");
        assert!(
            tu.unauthorized.iter().any(|t| t == "web_fetch"),
            "web_fetch must be flagged as unauthorized when cert omits it; got unauthorized={:?}",
            tu.unauthorized,
        );
    }

    // ── Round-2 fix tests: alias matching + source filtering ──

    fn evt_with_source(event_type: EventType, source: &str) -> SessionEvent {
        let mut e = mk(99, "agent", event_type);
        e.meta = Some(serde_json::json!({"source": source}));
        e
    }

    #[test]
    fn titlecase_cert_authorizes_canonical_snake_actuals_via_alias() {
        // Operator declares Claude convention. Aliases map "Read" to
        // canonical "read_file", "Write" to "write_file", etc.
        let manifest = manifest_with_authorized(vec!["Read", "Write", "Bash"]);
        let events = vec![
            mk(0, "root", EventType::SessionStarted),
            mk(1, "agent", EventType::AgentReadFile { file_path: "x".into(), digest: None }),
            mk(2, "agent", EventType::AgentWroteFile {
                file_path: "y".into(),
                digest: None, operation: None, additions: None, deletions: None,
            }),
            mk(3, "agent", EventType::AgentCompletedProcess {
                process_name: "z".into(),
                exit_code: Some(0), duration_ms: Some(1), command: None,
            }),
            mk(4, "root", EventType::SessionClosed { summary: None, duration_ms: Some(1000) }),
        ];
        let tu = ReceiptComposer::compose(&manifest, &events, vec![]).tool_usage.unwrap();
        assert!(
            tu.unauthorized.is_empty(),
            "TitleCase declarations must authorize canonical snake_case actuals via aliases; \
             got unauthorized={:?}",
            tu.unauthorized,
        );
    }

    #[test]
    fn edit_alias_authorizes_specialized_wrote_file() {
        // Operator declares "Edit" specifically. post-tool-use.sh
        // emits agent.wrote_file for Edit/MultiEdit alike, so the
        // canonical actual is "write_file". Edit is in the write_file
        // alias list, so the cert authorizes.
        let manifest = manifest_with_authorized(vec!["Edit"]);
        let events = vec![
            mk(0, "root", EventType::SessionStarted),
            mk(1, "agent", EventType::AgentWroteFile {
                file_path: "x".into(),
                digest: None, operation: None, additions: None, deletions: None,
            }),
            mk(2, "root", EventType::SessionClosed { summary: None, duration_ms: Some(1000) }),
        ];
        let tu = ReceiptComposer::compose(&manifest, &events, vec![]).tool_usage.unwrap();
        assert!(tu.unauthorized.is_empty(), "Edit alias must authorize write_file");
    }

    #[test]
    fn git_reconcile_writes_dont_count_toward_tool_usage() {
        // Backstop evidence -- not direct tool attribution.
        // A git-reconciled change must NOT make the cert require
        // write_file authorization, because no Write tool was invoked.
        let manifest = manifest_with_authorized(vec!["read_file"]);
        let events = vec![
            mk(0, "root", EventType::SessionStarted),
            evt_with_source(
                EventType::AgentWroteFile {
                    file_path: "CHANGELOG.md".into(),
                    digest: None, operation: Some("modified".into()),
                    additions: Some(7), deletions: Some(2),
                },
                "git-reconcile",
            ),
            mk(2, "root", EventType::SessionClosed { summary: None, duration_ms: Some(1000) }),
        ];
        let tu = ReceiptComposer::compose(&manifest, &events, vec![]).tool_usage.unwrap();
        assert!(
            !tu.unauthorized.iter().any(|t| t == "write_file"),
            "git-reconcile entries must NOT count toward tool_usage; \
             got unauthorized={:?}, actual={:?}",
            tu.unauthorized, tu.actual,
        );
        let actual_names: std::collections::BTreeSet<String> =
            tu.actual.iter().map(|e| e.tool_name.clone()).collect();
        assert!(!actual_names.contains("write_file"),
            "actual must not include backstop-only writes");
    }

    // (session-event-cli source filtering tests are covered indirectly
    // by the git-reconcile test above. The session-event-cli label
    // requires PR #20's source_from_meta verbatim-preservation fix to
    // flow through unmangled -- on this branch, side_effects.rs
    // downgrades unrecognized labels to "hook". Once PR #20 lands,
    // a follow-up PR can stack the full label-passthrough tests on
    // top of the merged base.)

    #[test]
    fn hook_emitted_writes_still_count_toward_tool_usage() {
        // Positive case: regular hook-emitted write IS direct attribution.
        let manifest = manifest_with_authorized(vec!["read_file"]); // NO write_file
        let events = vec![
            mk(0, "root", EventType::SessionStarted),
            evt_with_source(
                EventType::AgentWroteFile {
                    file_path: "src/x.rs".into(),
                    digest: None, operation: None, additions: None, deletions: None,
                },
                "hook",
            ),
            mk(2, "root", EventType::SessionClosed { summary: None, duration_ms: Some(1000) }),
        ];
        let tu = ReceiptComposer::compose(&manifest, &events, vec![]).tool_usage.unwrap();
        assert!(
            tu.unauthorized.iter().any(|t| t == "write_file"),
            "hook-emitted writes MUST count toward tool_usage; got unauthorized={:?}",
            tu.unauthorized,
        );
    }

    #[test]
    fn legacy_untagged_writes_count_for_back_compat() {
        // Pre-v0.9.6 events have no source tag. Treat as attributed
        // (back-compat: receipts produced before source labeling existed).
        let manifest = manifest_with_authorized(vec!["read_file"]); // NO write_file
        let events = vec![
            mk(0, "root", EventType::SessionStarted),
            mk(1, "agent", EventType::AgentWroteFile {
                file_path: "x".into(),
                digest: None, operation: None, additions: None, deletions: None,
            }),
            mk(2, "root", EventType::SessionClosed { summary: None, duration_ms: Some(1000) }),
        ];
        let tu = ReceiptComposer::compose(&manifest, &events, vec![]).tool_usage.unwrap();
        assert!(
            tu.unauthorized.iter().any(|t| t == "write_file"),
            "legacy untagged writes must count for back-compat",
        );
    }
}
