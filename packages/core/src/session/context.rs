//! Cross-tool and cross-host context propagation.
//!
//! Propagates session identity through environment variables, HTTP headers,
//! and CLI wrappers so that spawned processes and remote agents inherit
//! session context.

use serde::{Deserialize, Serialize};

use super::event::{generate_span_id, generate_trace_id};

/// Environment variable prefix for Treeship context.
const ENV_PREFIX: &str = "TREESHIP_";

/// HTTP header prefix for Treeship context.
const HEADER_PREFIX: &str = "x-treeship-";

/// Field names used for both env vars and headers.
const FIELD_SESSION_ID: &str = "SESSION_ID";
const FIELD_TRACE_ID: &str = "TRACE_ID";
const FIELD_SPAN_ID: &str = "SPAN_ID";
const FIELD_PARENT_SPAN_ID: &str = "PARENT_SPAN_ID";
const FIELD_AGENT_ID: &str = "AGENT_ID";
const FIELD_AGENT_INSTANCE_ID: &str = "AGENT_INSTANCE_ID";
const FIELD_WORKSPACE_ID: &str = "WORKSPACE_ID";
const FIELD_MISSION_ID: &str = "MISSION_ID";
const FIELD_HOST_ID: &str = "HOST_ID";
const FIELD_TOOL_RUNTIME_ID: &str = "TOOL_RUNTIME_ID";

/// Context propagated across tool and host boundaries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationContext {
    pub session_id: String,
    pub trace_id: String,
    pub span_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    pub agent_id: String,
    pub agent_instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mission_id: Option<String>,
    pub host_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_runtime_id: Option<String>,
}

impl PropagationContext {
    /// Read context from environment variables.
    ///
    /// Returns `None` if required fields (`TREESHIP_SESSION_ID`, `TREESHIP_TRACE_ID`)
    /// are not present.
    pub fn from_env() -> Option<Self> {
        let session_id = std::env::var(format!("{ENV_PREFIX}{FIELD_SESSION_ID}")).ok()?;
        let trace_id = std::env::var(format!("{ENV_PREFIX}{FIELD_TRACE_ID}"))
            .unwrap_or_else(|_| generate_trace_id());

        Some(Self {
            session_id,
            trace_id,
            span_id: std::env::var(format!("{ENV_PREFIX}{FIELD_SPAN_ID}"))
                .unwrap_or_else(|_| generate_span_id()),
            parent_span_id: std::env::var(format!("{ENV_PREFIX}{FIELD_PARENT_SPAN_ID}")).ok(),
            agent_id: std::env::var(format!("{ENV_PREFIX}{FIELD_AGENT_ID}"))
                .unwrap_or_else(|_| "agent://unknown".into()),
            agent_instance_id: std::env::var(format!("{ENV_PREFIX}{FIELD_AGENT_INSTANCE_ID}"))
                .unwrap_or_else(|_| "ai_unknown".into()),
            workspace_id: std::env::var(format!("{ENV_PREFIX}{FIELD_WORKSPACE_ID}")).ok(),
            mission_id: std::env::var(format!("{ENV_PREFIX}{FIELD_MISSION_ID}")).ok(),
            host_id: std::env::var(format!("{ENV_PREFIX}{FIELD_HOST_ID}"))
                .unwrap_or_else(|_| default_host_id()),
            tool_runtime_id: std::env::var(format!("{ENV_PREFIX}{FIELD_TOOL_RUNTIME_ID}")).ok(),
        })
    }

    /// Inject context as environment variables on a Command builder.
    pub fn inject_env(&self, cmd: &mut std::process::Command) {
        cmd.env(format!("{ENV_PREFIX}{FIELD_SESSION_ID}"), &self.session_id);
        cmd.env(format!("{ENV_PREFIX}{FIELD_TRACE_ID}"), &self.trace_id);
        cmd.env(format!("{ENV_PREFIX}{FIELD_SPAN_ID}"), &self.span_id);
        if let Some(ref psid) = self.parent_span_id {
            cmd.env(format!("{ENV_PREFIX}{FIELD_PARENT_SPAN_ID}"), psid);
        }
        cmd.env(format!("{ENV_PREFIX}{FIELD_AGENT_ID}"), &self.agent_id);
        cmd.env(format!("{ENV_PREFIX}{FIELD_AGENT_INSTANCE_ID}"), &self.agent_instance_id);
        if let Some(ref wid) = self.workspace_id {
            cmd.env(format!("{ENV_PREFIX}{FIELD_WORKSPACE_ID}"), wid);
        }
        if let Some(ref mid) = self.mission_id {
            cmd.env(format!("{ENV_PREFIX}{FIELD_MISSION_ID}"), mid);
        }
        cmd.env(format!("{ENV_PREFIX}{FIELD_HOST_ID}"), &self.host_id);
        if let Some(ref trid) = self.tool_runtime_id {
            cmd.env(format!("{ENV_PREFIX}{FIELD_TOOL_RUNTIME_ID}"), trid);
        }
    }

    /// Produce HTTP header pairs for outbound requests.
    pub fn to_headers(&self) -> Vec<(String, String)> {
        let mut h = vec![
            (format!("{HEADER_PREFIX}session-id"), self.session_id.clone()),
            (format!("{HEADER_PREFIX}trace-id"), self.trace_id.clone()),
            (format!("{HEADER_PREFIX}span-id"), self.span_id.clone()),
            (format!("{HEADER_PREFIX}agent-id"), self.agent_id.clone()),
            (format!("{HEADER_PREFIX}agent-instance-id"), self.agent_instance_id.clone()),
            (format!("{HEADER_PREFIX}host-id"), self.host_id.clone()),
        ];
        if let Some(ref psid) = self.parent_span_id {
            h.push((format!("{HEADER_PREFIX}parent-span-id"), psid.clone()));
        }
        if let Some(ref wid) = self.workspace_id {
            h.push((format!("{HEADER_PREFIX}workspace-id"), wid.clone()));
        }
        if let Some(ref mid) = self.mission_id {
            h.push((format!("{HEADER_PREFIX}mission-id"), mid.clone()));
        }
        if let Some(ref trid) = self.tool_runtime_id {
            h.push((format!("{HEADER_PREFIX}tool-runtime-id"), trid.clone()));
        }
        h
    }

    /// Parse context from HTTP header pairs.
    pub fn from_headers(headers: &[(String, String)]) -> Option<Self> {
        let get = |name: &str| -> Option<String> {
            let key = format!("{HEADER_PREFIX}{name}");
            headers.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(&key))
                .map(|(_, v)| v.clone())
        };

        let session_id = get("session-id")?;
        let trace_id = get("trace-id").unwrap_or_else(generate_trace_id);

        Some(Self {
            session_id,
            trace_id,
            span_id: get("span-id").unwrap_or_else(generate_span_id),
            parent_span_id: get("parent-span-id"),
            agent_id: get("agent-id").unwrap_or_else(|| "agent://unknown".into()),
            agent_instance_id: get("agent-instance-id").unwrap_or_else(|| "ai_unknown".into()),
            workspace_id: get("workspace-id"),
            mission_id: get("mission-id"),
            host_id: get("host-id").unwrap_or_else(default_host_id),
            tool_runtime_id: get("tool-runtime-id"),
        })
    }

    /// Generate a child span context: new span_id, current span_id becomes parent.
    pub fn child_span(&self) -> Self {
        Self {
            session_id: self.session_id.clone(),
            trace_id: self.trace_id.clone(),
            span_id: generate_span_id(),
            parent_span_id: Some(self.span_id.clone()),
            agent_id: self.agent_id.clone(),
            agent_instance_id: self.agent_instance_id.clone(),
            workspace_id: self.workspace_id.clone(),
            mission_id: self.mission_id.clone(),
            host_id: self.host_id.clone(),
            tool_runtime_id: self.tool_runtime_id.clone(),
        }
    }

    /// Generate a W3C traceparent header value.
    pub fn to_traceparent(&self) -> String {
        // Pad trace_id to 32 chars, span_id to 16 chars
        let tid = format!("{:0>32}", &self.trace_id);
        let sid = format!("{:0>16}", &self.span_id);
        format!("00-{tid}-{sid}-01")
    }
}

/// Default host ID derived from hostname.
fn default_host_id() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .map(|h| format!("host_{}", h.replace('.', "_")))
        .unwrap_or_else(|| "host_unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_span_preserves_trace() {
        let ctx = PropagationContext {
            session_id: "ssn_001".into(),
            trace_id: "abcd1234abcd1234abcd1234abcd1234".into(),
            span_id: "1111222233334444".into(),
            parent_span_id: None,
            agent_id: "agent://test".into(),
            agent_instance_id: "ai_1".into(),
            workspace_id: None,
            mission_id: None,
            host_id: "host_local".into(),
            tool_runtime_id: None,
        };

        let child = ctx.child_span();
        assert_eq!(child.trace_id, ctx.trace_id);
        assert_eq!(child.parent_span_id.as_deref(), Some("1111222233334444"));
        assert_ne!(child.span_id, ctx.span_id);
    }

    #[test]
    fn headers_roundtrip() {
        let ctx = PropagationContext {
            session_id: "ssn_002".into(),
            trace_id: "abcd".into(),
            span_id: "ef01".into(),
            parent_span_id: Some("0000".into()),
            agent_id: "agent://claude".into(),
            agent_instance_id: "ai_cc_1".into(),
            workspace_id: Some("ws_1".into()),
            mission_id: None,
            host_id: "host_mac".into(),
            tool_runtime_id: Some("rt_1".into()),
        };

        let headers = ctx.to_headers();
        let back = PropagationContext::from_headers(&headers).unwrap();
        assert_eq!(back.session_id, "ssn_002");
        assert_eq!(back.parent_span_id.as_deref(), Some("0000"));
        assert_eq!(back.workspace_id.as_deref(), Some("ws_1"));
    }

    #[test]
    fn traceparent_format() {
        let ctx = PropagationContext {
            session_id: "ssn_001".into(),
            trace_id: "abcd1234abcd1234abcd1234abcd1234".into(),
            span_id: "1111222233334444".into(),
            parent_span_id: None,
            agent_id: "agent://test".into(),
            agent_instance_id: "ai_1".into(),
            workspace_id: None,
            mission_id: None,
            host_id: "host_local".into(),
            tool_runtime_id: None,
        };
        let tp = ctx.to_traceparent();
        assert_eq!(tp, "00-abcd1234abcd1234abcd1234abcd1234-1111222233334444-01");
    }
}
