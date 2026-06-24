//! Pure capability-card verification primitives, shared by the CLI
//! (`treeship verify-capability`) and the WASM verifier (browser receipt
//! viewer) so both agree by construction. No I/O: callers supply the parsed
//! card, the action statements, and the trust roots.
//!
//! See docs/specs/agent-capability-cards.md. The honest contract holds here
//! too: this checks consistency over *captured* evidence (the actions the
//! caller passes in), never completeness.

use crate::statements::ActionStatement;
use crate::trust::{TrustRootKind, TrustRootStore};

/// `family.*` matches `family.write`; otherwise an exact match. A bare `*`
/// matches anything.
pub fn tool_matches(declared: &str, actual: &str) -> bool {
    if let Some(prefix) = declared.strip_suffix('*') {
        actual.starts_with(prefix)
    } else {
        declared == actual
    }
}

/// A card is **key-bound** only when its `keyid` is the envelope signer AND
/// that key is pinned under `AgentCert`. Anything else is self-asserted.
pub fn is_key_bound(card_keyid: &str, signer_keyid: &str, trust: &TrustRootStore) -> bool {
    !card_keyid.is_empty()
        && signer_keyid == card_keyid
        && trust
            .roots()
            .iter()
            .any(|r| r.key_id == card_keyid && r.kind == TrustRootKind::AgentCert)
}

/// Is an action within a declared capability set? Checks the action label and
/// the optional `meta.tool` against each declared capability (exact, or a
/// `family.*` glob).
pub fn action_in_scope(action: &ActionStatement, declared_tools: &[String]) -> bool {
    let mut candidates: Vec<&str> = vec![action.action.as_str()];
    if let Some(tool) = action
        .meta
        .as_ref()
        .and_then(|m| m.get("tool"))
        .and_then(|v| v.as_str())
    {
        candidates.push(tool);
    }
    candidates
        .iter()
        .any(|c| declared_tools.iter().any(|d| tool_matches(d, c)))
}

/// Extract the declared `capabilities.tools` from an agent_card.v1 payload.
pub fn declared_tools(card_payload: &serde_json::Value) -> Vec<String> {
    card_payload
        .get("capabilities")
        .and_then(|c| c.get("tools"))
        .and_then(|t| t.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|t| t.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{TrustRoot, TrustRootKind, TrustRootStore};

    #[test]
    fn exact_and_glob_matching() {
        assert!(tool_matches("file.write", "file.write"));
        assert!(!tool_matches("file.write", "file.read"));
        assert!(tool_matches("file.*", "file.write"));
        assert!(!tool_matches("file.*", "db.query"));
        assert!(tool_matches("*", "anything.at.all"));
    }

    fn root(key_id: &str, kind: TrustRootKind) -> TrustRoot {
        TrustRoot {
            key_id: key_id.into(),
            public_key: "ed25519:AAAA".into(),
            kind,
            label: String::new(),
            added_at: String::new(),
        }
    }

    #[test]
    fn key_bound_needs_signer_match_and_agentcert() {
        let agentcert = TrustRootStore::with_roots(vec![root("key_x", TrustRootKind::AgentCert)]);
        assert!(is_key_bound("key_x", "key_x", &agentcert));
        assert!(!is_key_bound("key_x", "key_y", &agentcert));
        assert!(!is_key_bound("", "", &agentcert));
        let ship = TrustRootStore::with_roots(vec![root("key_x", TrustRootKind::Ship)]);
        assert!(!is_key_bound("key_x", "key_x", &ship));
        assert!(!is_key_bound("key_x", "key_x", &TrustRootStore::with_roots(vec![])));
    }

    #[test]
    fn in_scope_checks_action_and_meta_tool() {
        let mut a = ActionStatement::new("agent://x", "file.write");
        assert!(action_in_scope(&a, &["file.*".to_string()]));
        assert!(!action_in_scope(&a, &["db.query".to_string()]));
        // meta.tool also counts
        a.action = "tool.call".into();
        a.meta = Some(serde_json::json!({ "tool": "db.query" }));
        assert!(action_in_scope(&a, &["db.query".to_string()]));
    }
}
