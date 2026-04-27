//! Side-effect aggregation from session events.
//!
//! Groups file, network, port, and process side effects for the
//! side-effect ledger in the Session Report.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::event::{EventType, SessionEvent};

/// A file access event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAccess {
    pub file_path: String,
    pub agent_instance_id: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// "created", "modified", or "deleted". Absent for read events and legacy writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub additions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deletions: Option<u32>,
    /// Provenance: how the file change was witnessed.
    /// - `"hook"`        : structured event from a native hook (e.g.
    ///                     claude-code-plugin's PostToolUse → agent.wrote_file).
    ///                     Highest trust -- the integration hook saw the
    ///                     tool call directly with full input context.
    /// - `"mcp"`         : promoted from a generic agent.called_tool event
    ///                     by inspecting meta.tool_input.file_path. Medium
    ///                     trust -- the MCP bridge saw the tool fire but
    ///                     we inferred the direction (read vs write) from
    ///                     tool name heuristics.
    /// - `"git-reconcile"`: backstop -- collected from `git diff` at session
    ///                     close to catch files an agent edited outside any
    ///                     captured tool channel. Lowest direct trust but
    ///                     highest completeness guarantee.
    /// Absent on legacy receipts that predate this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// A port opened by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAccess {
    pub port: u16,
    pub agent_instance_id: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

/// A network connection made by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    pub destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub agent_instance_id: String,
    pub timestamp: String,
}

/// A process execution by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessExecution {
    pub process_name: String,
    pub agent_instance_id: String,
    pub started_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Full command string (e.g. "npm test --runInBand"). Absent in legacy events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Same provenance scheme as FileAccess::source. `"hook"`, `"mcp"`,
    /// `"shell-wrap"` (for treeship wrap'd commands), or absent on legacy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
}

/// A tool invocation by an agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInvocation {
    pub tool_name: String,
    pub agent_instance_id: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Aggregated side effects from a session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SideEffects {
    pub files_read: Vec<FileAccess>,
    pub files_written: Vec<FileAccess>,
    pub ports_opened: Vec<PortAccess>,
    pub network_connections: Vec<NetworkConnection>,
    pub processes: Vec<ProcessExecution>,
    pub tool_invocations: Vec<ToolInvocation>,
}

impl SideEffects {
    /// Build side effects from a sequence of session events.
    pub fn from_events(events: &[SessionEvent]) -> Self {
        let mut se = SideEffects::default();

        // Track started processes so we can match with completed events.
        // Key: (agent_instance_id, process_name)
        let mut started_processes: BTreeMap<(String, String), usize> = BTreeMap::new();

        for event in events {
            match &event.event_type {
                EventType::AgentReadFile { file_path, digest } => {
                    se.files_read.push(FileAccess {
                        file_path: file_path.clone(),
                        agent_instance_id: event.agent_instance_id.clone(),
                        timestamp: event.timestamp.clone(),
                        digest: digest.clone(),
                        operation: None,
                        additions: None,
                        deletions: None,
                        source: Some(source_from_meta(event, "hook")),
                    });
                }

                EventType::AgentWroteFile { file_path, digest, operation, additions, deletions } => {
                    se.files_written.push(FileAccess {
                        file_path: file_path.clone(),
                        agent_instance_id: event.agent_instance_id.clone(),
                        timestamp: event.timestamp.clone(),
                        digest: digest.clone(),
                        operation: operation.clone(),
                        additions: *additions,
                        deletions: *deletions,
                        source: Some(source_from_meta(event, "hook")),
                    });
                }

                EventType::AgentOpenedPort { port, protocol } => {
                    se.ports_opened.push(PortAccess {
                        port: *port,
                        agent_instance_id: event.agent_instance_id.clone(),
                        timestamp: event.timestamp.clone(),
                        protocol: protocol.clone(),
                    });
                }

                EventType::AgentConnectedNetwork { destination, port } => {
                    se.network_connections.push(NetworkConnection {
                        destination: destination.clone(),
                        port: *port,
                        agent_instance_id: event.agent_instance_id.clone(),
                        timestamp: event.timestamp.clone(),
                    });
                }

                EventType::AgentStartedProcess { process_name, pid: _, command } => {
                    let idx = se.processes.len();
                    se.processes.push(ProcessExecution {
                        process_name: process_name.clone(),
                        agent_instance_id: event.agent_instance_id.clone(),
                        started_at: event.timestamp.clone(),
                        exit_code: None,
                        duration_ms: None,
                        command: command.clone(),
                        source: Some(source_from_meta(event, "hook")),
                    });
                    started_processes.insert(
                        (event.agent_instance_id.clone(), process_name.clone()),
                        idx,
                    );
                }

                EventType::AgentCompletedProcess { process_name, exit_code, duration_ms, command } => {
                    let key = (event.agent_instance_id.clone(), process_name.clone());
                    if let Some(&idx) = started_processes.get(&key) {
                        if let Some(proc) = se.processes.get_mut(idx) {
                            proc.exit_code = *exit_code;
                            proc.duration_ms = *duration_ms;
                            if proc.command.is_none() {
                                proc.command = command.clone();
                            }
                        }
                    } else {
                        se.processes.push(ProcessExecution {
                            process_name: process_name.clone(),
                            agent_instance_id: event.agent_instance_id.clone(),
                            started_at: event.timestamp.clone(),
                            exit_code: *exit_code,
                            duration_ms: *duration_ms,
                            command: command.clone(),
                            source: Some(source_from_meta(event, "hook")),
                        });
                    }
                }

                EventType::AgentCalledTool { tool_name, duration_ms, .. } => {
                    se.tool_invocations.push(ToolInvocation {
                        tool_name: tool_name.clone(),
                        agent_instance_id: event.agent_instance_id.clone(),
                        timestamp: event.timestamp.clone(),
                        duration_ms: *duration_ms,
                    });

                    // ── MCP promotion path ───────────────────────────────
                    // Generic agent.called_tool events emitted by MCP
                    // bridges (or any tool channel that doesn't dispatch
                    // into specialized event types) carry their useful
                    // payload in meta. Inspect meta.tool_input.{file_path,
                    // path, command} and promote to files_read /
                    // files_written / processes so the receipt's "Files
                    // changed" and "Commands run" sections actually
                    // reflect the work, not just a count of tool calls.
                    //
                    // The bar (per the trust-fabric direction): if a file
                    // changed during the session, it must appear in the
                    // receipt. Without this promotion path, an agent
                    // editing files via MCP-routed tools shows up as
                    // "tool_invocations: N" with files_written empty --
                    // a confidently incomplete audit trail.
                    promote_mcp_called_tool(event, tool_name, &mut se);
                }

                _ => {}
            }
        }

        se
    }

    /// Summary counts for display.
    pub fn summary(&self) -> SideEffectSummary {
        SideEffectSummary {
            files_read: self.files_read.len() as u32,
            files_written: self.files_written.len() as u32,
            ports_opened: self.ports_opened.len() as u32,
            network_connections: self.network_connections.len() as u32,
            processes: self.processes.len() as u32,
            tool_invocations: self.tool_invocations.len() as u32,
        }
    }
}

/// Summary counts of side effects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SideEffectSummary {
    pub files_read: u32,
    pub files_written: u32,
    pub ports_opened: u32,
    pub network_connections: u32,
    pub processes: u32,
    pub tool_invocations: u32,
}

// ---------------------------------------------------------------------------
// MCP promotion helpers
//
// When an agent.called_tool event was emitted by an MCP bridge (or any
// tool channel that doesn't dispatch into specialized event types), the
// useful payload lives in `event.meta`. These helpers inspect known
// shapes (`meta.tool_input.file_path`, `meta.tool_input.command`, the
// flattened variants) and tool-name heuristics to promote the tool call
// into the right side-effects bucket with `source: "mcp"`.
//
// Heuristics are intentionally generous on the write side: when the
// tool name is ambiguous, we err toward files_written rather than
// dropping the path. The trust-fabric bar is "if a file changed, it
// must appear in the receipt" -- losing a real change is worse than
// classifying a read as a write.
// ---------------------------------------------------------------------------

/// Read a string from event.meta following a dotted path
/// (e.g. "tool_input.file_path"). Returns None if any segment is
/// absent or the leaf isn't a string.
fn meta_string(event: &SessionEvent, dotted_path: &str) -> Option<String> {
    let mut cur = event.meta.as_ref()?;
    for segment in dotted_path.split('.') {
        cur = cur.get(segment)?;
    }
    cur.as_str().map(|s| s.to_string())
}

/// Try a list of dotted paths in priority order; first non-empty wins.
fn first_meta_string(event: &SessionEvent, paths: &[&str]) -> Option<String> {
    for path in paths {
        if let Some(v) = meta_string(event, path) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Pull a known-good source label off event.meta if present, else
/// return the default. Lets emitters tag their provenance in meta
/// without each event variant needing a dedicated field. Recognized
/// values: `"hook"`, `"mcp"`, `"git-reconcile"`, `"shell-wrap"`.
/// Anything else falls back to the default (so a typo doesn't pollute
/// the receipt).
fn source_from_meta(event: &SessionEvent, default: &str) -> String {
    let raw = event
        .meta
        .as_ref()
        .and_then(|m| m.get("source"))
        .and_then(|v| v.as_str());
    match raw {
        Some(s @ ("hook" | "mcp" | "git-reconcile" | "shell-wrap")) => s.to_string(),
        _ => default.to_string(),
    }
}

/// Classify a tool name into a side-effects bucket using string contains
/// heuristics. Different agents call their file ops different things
/// (Read vs read_file vs view, Write vs write_file vs save, Bash vs
/// shell vs exec), so we match on substring rather than exact name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ToolCategory {
    Read,
    Write,
    Process,
    Unknown,
}

fn classify_tool(tool_name: &str) -> ToolCategory {
    let t = tool_name.to_lowercase();
    // Process / shell first -- "execute" matches before generic "exec".
    if t.contains("bash") || t.contains("shell") || t.contains("exec")
        || t.contains("run_command") || t.contains("ran_command")
    {
        return ToolCategory::Process;
    }
    // Writes: any mutation verb wins. Order matters because "edit" is a
    // strong signal even when the tool name also contains "file".
    if t.contains("write") || t.contains("edit") || t.contains("create_file")
        || t.contains("modify") || t.contains("patch") || t.contains("save_file")
        || t.contains("delete_file") || t.contains("remove_file") || t.contains("rename_file")
    {
        return ToolCategory::Write;
    }
    // Reads
    if t.contains("read") || t.contains("view_file") || t.contains("cat_file")
        || t.contains("open_file") || t.contains("get_file_contents")
    {
        return ToolCategory::Read;
    }
    ToolCategory::Unknown
}

fn promote_mcp_called_tool(
    event: &SessionEvent,
    tool_name: &str,
    se: &mut SideEffects,
) {
    let category = classify_tool(tool_name);

    // File path candidates -- check tool_input first (Claude Code +
    // most MCP servers), then flattened (some bridges flatten meta).
    let file_path = first_meta_string(event, &[
        "tool_input.file_path",
        "tool_input.path",
        "tool_input.notebook_path",
        "tool_input.target_file",
        "file_path",
        "path",
    ]);

    // Command candidates for shell-style tools.
    let command = first_meta_string(event, &[
        "tool_input.command",
        "command",
        "tool_input.cmd",
        "cmd",
    ]);

    match (category, file_path, command) {
        (ToolCategory::Read, Some(p), _) => {
            se.files_read.push(FileAccess {
                file_path: p,
                agent_instance_id: event.agent_instance_id.clone(),
                timestamp: event.timestamp.clone(),
                digest: None,
                operation: None,
                additions: None,
                deletions: None,
                source: Some("mcp".into()),
            });
        }
        (ToolCategory::Write, Some(p), _) => {
            se.files_written.push(FileAccess {
                file_path: p,
                agent_instance_id: event.agent_instance_id.clone(),
                timestamp: event.timestamp.clone(),
                digest: None,
                operation: None,
                additions: None,
                deletions: None,
                source: Some("mcp".into()),
            });
        }
        (ToolCategory::Process, _, Some(cmd)) => {
            // Trim long commands to a usable process_name; the full
            // command string is preserved in `command`.
            let short = cmd.chars().take(120).collect::<String>();
            se.processes.push(ProcessExecution {
                process_name: short,
                agent_instance_id: event.agent_instance_id.clone(),
                started_at: event.timestamp.clone(),
                exit_code: None,
                duration_ms: None,
                command: Some(cmd),
                source: Some("mcp".into()),
            });
        }
        (ToolCategory::Unknown, Some(p), _) => {
            // Tool name didn't match any known verb but a file path is
            // present in meta. Conservative call: record as a write so
            // the file at minimum surfaces in the receipt. The trust-
            // fabric bar is completeness; misclassifying a read as a
            // write is recoverable, dropping the path silently is not.
            se.files_written.push(FileAccess {
                file_path: p,
                agent_instance_id: event.agent_instance_id.clone(),
                timestamp: event.timestamp.clone(),
                digest: None,
                operation: None,
                additions: None,
                deletions: None,
                source: Some("mcp".into()),
            });
        }
        _ => {
            // No usable payload -- the tool_invocation entry written by
            // the caller above is the only record. Acceptable: this is
            // the "tool call we know happened but nothing to promote"
            // case (e.g. a search or list-files MCP tool).
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::event::*;

    fn evt(event_type: EventType) -> SessionEvent {
        SessionEvent {
            session_id: "ssn_001".into(),
            event_id: generate_event_id(),
            timestamp: "2026-04-05T08:00:00Z".into(),
            sequence_no: 0,
            trace_id: "t".into(),
            span_id: "s".into(),
            parent_span_id: None,
            agent_id: "agent://test".into(),
            agent_instance_id: "ai_1".into(),
            agent_name: "test".into(),
            agent_role: None,
            host_id: "h".into(),
            tool_runtime_id: None,
            event_type,
            artifact_ref: None,
            meta: None,
        }
    }

    #[test]
    fn aggregates_file_and_tool_events() {
        let events = vec![
            evt(EventType::AgentReadFile { file_path: "src/main.rs".into(), digest: None }),
            evt(EventType::AgentWroteFile { file_path: "src/lib.rs".into(), digest: Some("sha256:abc".into()), operation: Some("modified".into()), additions: Some(10), deletions: Some(3) }),
            evt(EventType::AgentCalledTool { tool_name: "read_file".into(), tool_input_digest: None, tool_output_digest: None, duration_ms: Some(10) }),
            evt(EventType::AgentCalledTool { tool_name: "write_file".into(), tool_input_digest: None, tool_output_digest: None, duration_ms: None }),
        ];

        let se = SideEffects::from_events(&events);
        assert_eq!(se.files_read.len(), 1);
        assert_eq!(se.files_written.len(), 1);
        assert_eq!(se.tool_invocations.len(), 2);
        let summary = se.summary();
        assert_eq!(summary.tool_invocations, 2);
    }

    #[test]
    fn matches_process_start_and_complete() {
        let events = vec![
            evt(EventType::AgentStartedProcess { process_name: "npm test".into(), pid: Some(1234), command: Some("npm test --runInBand".into()) }),
            evt(EventType::AgentCompletedProcess { process_name: "npm test".into(), exit_code: Some(0), duration_ms: Some(5000), command: None }),
        ];

        let se = SideEffects::from_events(&events);
        assert_eq!(se.processes.len(), 1);
        assert_eq!(se.processes[0].exit_code, Some(0));
        assert_eq!(se.processes[0].duration_ms, Some(5000));
    }

    /// Construct an agent.called_tool event with the given tool name and
    /// arbitrary meta JSON. Used by MCP promotion tests below.
    fn called_tool_with_meta(tool_name: &str, meta: serde_json::Value) -> SessionEvent {
        let mut e = evt(EventType::AgentCalledTool {
            tool_name: tool_name.into(),
            tool_input_digest: None,
            tool_output_digest: None,
            duration_ms: None,
        });
        e.meta = Some(meta);
        e
    }

    #[test]
    fn hook_file_events_carry_source_hook() {
        // Regression: every existing emission path must tag itself so the
        // receipt page can render provenance ("observed via hook") on
        // each file row.
        let events = vec![
            evt(EventType::AgentReadFile { file_path: "src/a.rs".into(), digest: None }),
            evt(EventType::AgentWroteFile { file_path: "src/b.rs".into(), digest: None, operation: None, additions: None, deletions: None }),
        ];
        let se = SideEffects::from_events(&events);
        assert_eq!(se.files_read[0].source.as_deref(), Some("hook"));
        assert_eq!(se.files_written[0].source.as_deref(), Some("hook"));
    }

    #[test]
    fn mcp_called_tool_with_file_path_promotes_to_files_written() {
        // The trust-fabric invariant: a file changed during the session
        // must appear in the receipt. Even when the only signal is a
        // generic agent.called_tool event with the path tucked inside
        // meta.tool_input.file_path (the shape the engineer's events.jsonl
        // had), the aggregator must surface it.
        let events = vec![
            called_tool_with_meta(
                "Edit",
                serde_json::json!({
                    "source": "mcp-bridge",
                    "tool_input": { "file_path": "src/api/receipt.ts" },
                }),
            ),
        ];
        let se = SideEffects::from_events(&events);
        assert_eq!(se.files_written.len(), 1, "Edit with file_path must promote to files_written");
        assert_eq!(se.files_written[0].file_path, "src/api/receipt.ts");
        assert_eq!(se.files_written[0].source.as_deref(), Some("mcp"));
        // tool_invocations also gets the entry -- the original record
        // is preserved alongside the promotion.
        assert_eq!(se.tool_invocations.len(), 1);
    }

    #[test]
    fn mcp_read_tool_promotes_to_files_read() {
        let events = vec![
            called_tool_with_meta(
                "Read",
                serde_json::json!({ "tool_input": { "file_path": "package.json" } }),
            ),
        ];
        let se = SideEffects::from_events(&events);
        assert_eq!(se.files_read.len(), 1);
        assert_eq!(se.files_read[0].file_path, "package.json");
        assert_eq!(se.files_read[0].source.as_deref(), Some("mcp"));
    }

    #[test]
    fn mcp_bash_tool_promotes_to_processes() {
        let events = vec![
            called_tool_with_meta(
                "Bash",
                serde_json::json!({ "tool_input": { "command": "bun test --run" } }),
            ),
        ];
        let se = SideEffects::from_events(&events);
        assert_eq!(se.processes.len(), 1);
        assert_eq!(se.processes[0].command.as_deref(), Some("bun test --run"));
        assert_eq!(se.processes[0].source.as_deref(), Some("mcp"));
    }

    #[test]
    fn mcp_unknown_tool_with_path_defaults_to_files_written() {
        // Trust-fabric bar: when the tool name doesn't match any known
        // verb but meta carries a file_path, record as files_written
        // rather than dropping the path. Misclassifying a read as a
        // write is recoverable; silently losing a real change is not.
        let events = vec![
            called_tool_with_meta(
                "mcp__weird-vendor__do_thing",
                serde_json::json!({ "tool_input": { "file_path": "config.toml" } }),
            ),
        ];
        let se = SideEffects::from_events(&events);
        assert_eq!(se.files_written.len(), 1);
        assert_eq!(se.files_written[0].file_path, "config.toml");
        assert_eq!(se.files_written[0].source.as_deref(), Some("mcp"));
    }

    #[test]
    fn mcp_called_tool_without_meta_does_not_promote() {
        // Plain agent.called_tool with no useful meta: the
        // tool_invocation entry is the only record. We do NOT invent a
        // file path or fail loudly -- this is the "search/list/info"
        // tool case that legitimately has no side effect.
        let events = vec![
            called_tool_with_meta("ls", serde_json::json!({"source": "mcp-bridge"})),
        ];
        let se = SideEffects::from_events(&events);
        assert_eq!(se.files_read.len(), 0);
        assert_eq!(se.files_written.len(), 0);
        assert_eq!(se.processes.len(), 0);
        assert_eq!(se.tool_invocations.len(), 1);
    }

    #[test]
    fn mcp_promotion_handles_alt_path_field_names() {
        // Different MCP servers use different conventions for the path
        // field. We try a list of common ones.
        for path_field in &["tool_input.path", "tool_input.target_file", "file_path", "path"] {
            let mut meta_obj = serde_json::Map::new();
            // Build a nested object matching the dotted path.
            let parts: Vec<&str> = path_field.split('.').collect();
            if parts.len() == 1 {
                meta_obj.insert(parts[0].into(), serde_json::json!("x.txt"));
            } else {
                let inner = serde_json::json!({ parts[1]: "x.txt" });
                meta_obj.insert(parts[0].into(), inner);
            }
            let events = vec![called_tool_with_meta("Edit", serde_json::Value::Object(meta_obj))];
            let se = SideEffects::from_events(&events);
            assert_eq!(
                se.files_written.len(), 1,
                "expected promotion via {} but got nothing", path_field,
            );
        }
    }
}
