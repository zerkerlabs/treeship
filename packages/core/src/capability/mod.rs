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
///
/// The `*` may sit anywhere in the pattern, not only at the end: harness
/// permission patterns captured by `attest card --from-harness` carry the
/// glob *inside* a delimiter — `Bash(git:*)` — where a trailing-`*`-only
/// matcher silently degrades to an exact match that can never fire, and a
/// card captured from a real config then reports every real action
/// out-of-scope. One wildcard is supported (the first, matching greedily);
/// the text before it must prefix the action and the text after it must
/// suffix the remainder, so `Bash(git:*)` matches `Bash(git:status)` but
/// not `Bash(gh:pr)` or a `Bash(git:` with the closing paren missing.
pub fn tool_matches(declared: &str, actual: &str) -> bool {
    match declared.split_once('*') {
        Some((prefix, suffix)) => {
            actual.len() >= prefix.len() + suffix.len()
                && actual.starts_with(prefix)
                && actual.ends_with(suffix)
        }
        None => declared == actual,
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

/// Generic dispatch labels: an `action` field whose value is one of these is a
/// placeholder ("the agent called *a* tool"), and the concrete tool name lives
/// in `meta.tool`. Only for these is `meta.tool` allowed to contribute scope.
///
/// This is the security boundary for the cross-check. `meta` is part of the
/// statement the audited agent signs itself; if `meta.tool` could match for an
/// action whose `action` field is already a CONCRETE label, a dishonest agent
/// would attach a benign `meta.tool` (e.g. `file.read`) to a concrete
/// out-of-scope action (e.g. `payments.charge`) and have it counted in-scope,
/// silently defeating the very check `verify-capability` exists to run.
const GENERIC_DISPATCH_LABELS: &[&str] =
    &["tool.call", "tool.use", "tool.invoke", "mcp.call", "mcp.tool"];

/// The scope-matching candidates for an action. The action label is always
/// authoritative. `meta.tool` is consulted ONLY when the action label is a
/// generic dispatch placeholder, so a concrete out-of-scope action cannot be
/// rescued by an attacker-supplied `meta.tool`.
fn scope_candidates(action: &ActionStatement) -> Vec<&str> {
    let label = action.action.as_str();
    let mut candidates: Vec<&str> = vec![label];
    if GENERIC_DISPATCH_LABELS.contains(&label) {
        if let Some(tool) = action
            .meta
            .as_ref()
            .and_then(|m| m.get("tool"))
            .and_then(|v| v.as_str())
        {
            candidates.push(tool);
        }
    }
    candidates
}

/// Is an action within a declared capability set? The action label is
/// authoritative; `meta.tool` counts only when the label is a generic
/// dispatch placeholder (see [`scope_candidates`]).
pub fn action_in_scope(action: &ActionStatement, declared_tools: &[String]) -> bool {
    scope_candidates(action)
        .iter()
        .any(|c| declared_tools.iter().any(|d| tool_matches(d, c)))
}

/// The first declared capability an action matches, if any. Same matching as
/// [`action_in_scope`], but returns *which* capability matched, so callers can
/// grade each declared capability by whether captured receipts exercise it.
pub fn matched_capability(action: &ActionStatement, declared_tools: &[String]) -> Option<String> {
    let candidates = scope_candidates(action);
    declared_tools
        .iter()
        .find(|decl| candidates.iter().any(|c| tool_matches(decl, c)))
        .cloned()
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

    #[test]
    fn harness_patterns_with_internal_glob_match() {
        // The shape `attest card --from-harness` captures from a Claude Code
        // settings.json permissions.allow list: the `*` sits inside the
        // parenthesized scope, not at the end of the pattern.
        assert!(tool_matches("Bash(git:*)", "Bash(git:status)"));
        assert!(tool_matches("Bash(git:*)", "Bash(git:log --oneline)"));
        assert!(tool_matches("Read(*)", "Read(/etc/hosts)"));
        // prefix and suffix must both hold — no cross-family bleed, no
        // matching a truncated action that drops the closing delimiter
        assert!(!tool_matches("Bash(git:*)", "Bash(gh:pr)"));
        assert!(!tool_matches("Bash(git:*)", "Bash(git:"));
        assert!(!tool_matches("Bash(git:*)", "payments.charge"));
        // the wildcard may match empty: the family root itself is in scope
        assert!(tool_matches("Bash(git:*)", "Bash(git:)"));
        // trailing-glob and exact behavior unchanged
        assert!(tool_matches("file.*", "file.*"));
        assert!(!tool_matches("Bash(git:status)", "Bash(git:log)"));
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
        // meta.tool counts ONLY when the action label is a generic dispatch
        // placeholder (the legitimate MCP case): tool.call + meta.tool=db.query.
        a.action = "tool.call".into();
        a.meta = Some(serde_json::json!({ "tool": "db.query" }));
        assert!(action_in_scope(&a, &["db.query".to_string()]));
    }

    #[test]
    fn meta_tool_cannot_rescue_a_concrete_out_of_scope_action() {
        // The audited-agent bypass: a CONCRETE out-of-scope action with a
        // benign meta.tool must still be out of scope. If this regresses, a
        // dishonest agent hides every off-card action behind meta.tool.
        let mut a = ActionStatement::new("agent://x", "payments.charge");
        a.meta = Some(serde_json::json!({ "tool": "file.read" }));
        let declared = vec!["file.*".to_string()]; // payments NOT declared
        assert!(
            !action_in_scope(&a, &declared),
            "meta.tool must not pull a concrete out-of-scope action in-scope"
        );
        assert_eq!(
            matched_capability(&a, &declared),
            None,
            "no declared capability should match the concrete out-of-scope action"
        );
        // And the concrete action IS matched when it is actually declared.
        assert!(action_in_scope(&a, &["payments.*".to_string()]));
    }

    #[test]
    fn matched_capability_returns_the_declared_glob() {
        let a = ActionStatement::new("agent://x", "file.write");
        let tools = vec!["db.query".to_string(), "file.*".to_string()];
        assert_eq!(matched_capability(&a, &tools).as_deref(), Some("file.*"));
        let b = ActionStatement::new("agent://x", "command.run");
        assert_eq!(matched_capability(&b, &tools), None);
    }
}
