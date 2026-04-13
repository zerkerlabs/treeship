//! Agent collaboration graph built from session events.
//!
//! Captures the full topology of agent relationships: parent-child spawning,
//! handoffs, and collaboration edges.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::event::{EventType, SessionEvent};

/// Type of relationship between two agents.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentEdgeType {
    /// Parent spawned a child agent.
    ParentChild,
    /// Work was handed off from one agent to another.
    Handoff,
    /// Agents collaborated on a shared task.
    Collaboration,
    /// Agent returned control to a parent.
    Return,
}

/// A node in the agent graph representing one agent instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentNode {
    pub agent_id: String,
    pub agent_instance_id: String,
    pub agent_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_role: Option<String>,
    pub host_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default)]
    pub depth: u32,
    /// Number of tool calls made by this agent.
    #[serde(default)]
    pub tool_calls: u32,
    /// Model identifier (e.g. "claude-opus-4-6"). Populated from decision events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Cumulative input tokens across all decisions by this agent.
    #[serde(default)]
    pub tokens_in: u64,
    /// Cumulative output tokens across all decisions by this agent.
    #[serde(default)]
    pub tokens_out: u64,
    /// Cumulative cost in USD across all decisions by this agent.
    #[serde(default, skip_serializing_if = "is_zero_f64")]
    pub cost_usd: f64,
}

fn is_zero_f64(v: &f64) -> bool { *v == 0.0 }

/// A directed edge in the agent graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEdge {
    pub from_instance_id: String,
    pub to_instance_id: String,
    pub edge_type: AgentEdgeType,
    pub timestamp: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<String>,
}

/// The complete agent collaboration graph for a session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentGraph {
    pub nodes: Vec<AgentNode>,
    pub edges: Vec<AgentEdge>,
}

impl AgentGraph {
    /// Build an agent graph from a sequence of session events.
    pub fn from_events(events: &[SessionEvent]) -> Self {
        let mut nodes_map: BTreeMap<String, AgentNode> = BTreeMap::new();
        let mut edges: Vec<AgentEdge> = Vec::new();
        let mut parent_map: BTreeMap<String, String> = BTreeMap::new(); // child -> parent instance

        for event in events {
            let instance_id = &event.agent_instance_id;

            // Ensure node exists
            let node = nodes_map.entry(instance_id.clone()).or_insert_with(|| AgentNode {
                agent_id: event.agent_id.clone(),
                agent_instance_id: instance_id.clone(),
                agent_name: event.agent_name.clone(),
                agent_role: event.agent_role.clone(),
                host_id: event.host_id.clone(),
                started_at: None,
                completed_at: None,
                status: None,
                depth: 0,
                tool_calls: 0,
                model: None,
                tokens_in: 0,
                tokens_out: 0,
                cost_usd: 0.0,
            });

            match &event.event_type {
                EventType::AgentStarted { parent_agent_instance_id } => {
                    node.started_at = Some(event.timestamp.clone());
                    if let Some(parent_id) = parent_agent_instance_id {
                        parent_map.insert(instance_id.clone(), parent_id.clone());
                    }
                }

                EventType::AgentSpawned { spawned_by_agent_instance_id, .. } => {
                    node.started_at = Some(event.timestamp.clone());
                    parent_map.insert(instance_id.clone(), spawned_by_agent_instance_id.clone());
                    edges.push(AgentEdge {
                        from_instance_id: spawned_by_agent_instance_id.clone(),
                        to_instance_id: instance_id.clone(),
                        edge_type: AgentEdgeType::ParentChild,
                        timestamp: event.timestamp.clone(),
                        artifacts: Vec::new(),
                    });
                }

                EventType::AgentHandoff { from_agent_instance_id, to_agent_instance_id, artifacts } => {
                    edges.push(AgentEdge {
                        from_instance_id: from_agent_instance_id.clone(),
                        to_instance_id: to_agent_instance_id.clone(),
                        edge_type: AgentEdgeType::Handoff,
                        timestamp: event.timestamp.clone(),
                        artifacts: artifacts.clone(),
                    });
                    // Ensure the target node exists
                    nodes_map.entry(to_agent_instance_id.clone()).or_insert_with(|| AgentNode {
                        agent_id: String::new(),
                        agent_instance_id: to_agent_instance_id.clone(),
                        agent_name: String::new(),
                        agent_role: None,
                        host_id: event.host_id.clone(),
                        started_at: None,
                        completed_at: None,
                        status: None,
                        depth: 0,
                        tool_calls: 0,
                        model: None,
                        tokens_in: 0,
                        tokens_out: 0,
                        cost_usd: 0.0,
                    });
                }

                EventType::AgentCollaborated { collaborator_agent_instance_ids } => {
                    for collab_id in collaborator_agent_instance_ids {
                        edges.push(AgentEdge {
                            from_instance_id: instance_id.clone(),
                            to_instance_id: collab_id.clone(),
                            edge_type: AgentEdgeType::Collaboration,
                            timestamp: event.timestamp.clone(),
                            artifacts: Vec::new(),
                        });
                    }
                }

                EventType::AgentReturned { returned_to_agent_instance_id } => {
                    edges.push(AgentEdge {
                        from_instance_id: instance_id.clone(),
                        to_instance_id: returned_to_agent_instance_id.clone(),
                        edge_type: AgentEdgeType::Return,
                        timestamp: event.timestamp.clone(),
                        artifacts: Vec::new(),
                    });
                }

                EventType::AgentCompleted { .. } => {
                    node.completed_at = Some(event.timestamp.clone());
                    node.status = Some("completed".into());
                }

                EventType::AgentFailed { .. } => {
                    node.completed_at = Some(event.timestamp.clone());
                    node.status = Some("failed".into());
                }

                EventType::AgentCalledTool { .. } => {
                    node.tool_calls += 1;
                }

                EventType::AgentDecision { ref model, tokens_in, tokens_out, cost_usd, .. } => {
                    if let Some(ref m) = model {
                        // Last model wins (agents may switch models mid-session).
                        node.model = Some(m.clone());
                    }
                    if let Some(t) = tokens_in { node.tokens_in += t; }
                    if let Some(t) = tokens_out { node.tokens_out += t; }
                    if let Some(c) = cost_usd { node.cost_usd += c; }
                }

                _ => {}
            }
        }

        // Compute depths from parent map
        let mut depth_cache: BTreeMap<String, u32> = BTreeMap::new();
        let instances: Vec<String> = nodes_map.keys().cloned().collect();
        for inst in &instances {
            let depth = compute_depth(inst, &parent_map, &mut depth_cache);
            if let Some(node) = nodes_map.get_mut(inst) {
                node.depth = depth;
            }
        }

        let nodes: Vec<AgentNode> = nodes_map.into_values().collect();

        AgentGraph { nodes, edges }
    }

    /// Return the maximum depth in the graph.
    pub fn max_depth(&self) -> u32 {
        self.nodes.iter().map(|n| n.depth).max().unwrap_or(0)
    }

    /// Return the set of unique host IDs across all agents.
    pub fn host_ids(&self) -> BTreeSet<String> {
        self.nodes.iter().map(|n| n.host_id.clone()).collect()
    }

    /// Total number of handoff edges.
    pub fn handoff_count(&self) -> u32 {
        self.edges.iter()
            .filter(|e| e.edge_type == AgentEdgeType::Handoff)
            .count() as u32
    }

    /// Total number of spawn (parent-child) edges.
    pub fn spawn_count(&self) -> u32 {
        self.edges.iter()
            .filter(|e| e.edge_type == AgentEdgeType::ParentChild)
            .count() as u32
    }
}

fn compute_depth(
    instance_id: &str,
    parent_map: &BTreeMap<String, String>,
    cache: &mut BTreeMap<String, u32>,
) -> u32 {
    if let Some(&d) = cache.get(instance_id) {
        return d;
    }
    let depth = match parent_map.get(instance_id) {
        Some(parent) => 1 + compute_depth(parent, parent_map, cache),
        None => 0,
    };
    cache.insert(instance_id.to_string(), depth);
    depth
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::event::*;

    fn evt(instance_id: &str, host: &str, event_type: EventType) -> SessionEvent {
        SessionEvent {
            session_id: "ssn_001".into(),
            event_id: generate_event_id(),
            timestamp: "2026-04-05T08:00:00Z".into(),
            sequence_no: 0,
            trace_id: "trace_1".into(),
            span_id: generate_span_id(),
            parent_span_id: None,
            agent_id: format!("agent://{instance_id}"),
            agent_instance_id: instance_id.into(),
            agent_name: instance_id.into(),
            agent_role: None,
            host_id: host.into(),
            tool_runtime_id: None,
            event_type,
            artifact_ref: None,
            meta: None,
        }
    }

    #[test]
    fn builds_graph_from_spawn_and_handoff() {
        let events = vec![
            evt("root", "host_a", EventType::AgentStarted {
                parent_agent_instance_id: None,
            }),
            evt("child1", "host_a", EventType::AgentSpawned {
                spawned_by_agent_instance_id: "root".into(),
                reason: Some("review code".into()),
            }),
            evt("child2", "host_b", EventType::AgentSpawned {
                spawned_by_agent_instance_id: "root".into(),
                reason: None,
            }),
            evt("root", "host_a", EventType::AgentHandoff {
                from_agent_instance_id: "root".into(),
                to_agent_instance_id: "child1".into(),
                artifacts: vec!["art_001".into()],
            }),
            evt("child1", "host_a", EventType::AgentCompleted {
                termination_reason: None,
            }),
        ];

        let graph = AgentGraph::from_events(&events);
        assert_eq!(graph.nodes.len(), 3);
        assert_eq!(graph.max_depth(), 1);
        assert_eq!(graph.handoff_count(), 1);
        assert_eq!(graph.spawn_count(), 2);
        assert_eq!(graph.host_ids().len(), 2);
    }

    #[test]
    fn nested_depth() {
        let events = vec![
            evt("root", "h", EventType::AgentStarted { parent_agent_instance_id: None }),
            evt("l1", "h", EventType::AgentSpawned { spawned_by_agent_instance_id: "root".into(), reason: None }),
            evt("l2", "h", EventType::AgentSpawned { spawned_by_agent_instance_id: "l1".into(), reason: None }),
            evt("l3", "h", EventType::AgentSpawned { spawned_by_agent_instance_id: "l2".into(), reason: None }),
        ];

        let graph = AgentGraph::from_events(&events);
        assert_eq!(graph.max_depth(), 3);
        let l3 = graph.nodes.iter().find(|n| n.agent_instance_id == "l3").unwrap();
        assert_eq!(l3.depth, 3);
    }
}
