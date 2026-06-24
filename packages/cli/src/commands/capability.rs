// `treeship verify-capability <card_id>` — the capability-card cross-check.
//
// An agent_card.v1 receipt declares an identity and a capability set. This
// command answers two questions a descriptor format (A2A, NANDA) cannot:
//   1. Is the card key-bound? (its keyid is the envelope signer AND that key is
//      pinned under AgentCert — otherwise it is merely self-asserted.)
//   2. Are the agent's captured actions within the declared capability set?
//
// The honest framing is load-bearing: this proves consistency over *captured*
// evidence. It does NOT prove the agent took no action outside its card — that
// completeness gap is Guard's runtime job, never a signature's. The output says
// so.

use crate::{ctx, printer::Printer};
use treeship_core::{
    statements::{payload_type, ActionStatement, ReceiptStatement},
    trust::{TrustRootKind, TrustRootStore},
};

type CmdResult = Result<(), Box<dyn std::error::Error>>;

pub fn verify_capability(card_id: &str, config: Option<&str>, printer: &Printer) -> CmdResult {
    let ctx = ctx::open(config)?;

    // --- Load and parse the card ------------------------------------------
    let record = ctx.storage.read(card_id)?;
    let card_stmt: ReceiptStatement = record.envelope.unmarshal_statement()?;
    if card_stmt.kind != "agent_card.v1" {
        return Err(format!(
            "{card_id} is kind `{}`, not an agent_card.v1 receipt",
            card_stmt.kind
        )
        .into());
    }
    let card = card_stmt
        .payload
        .ok_or("agent_card.v1 receipt has no payload")?;
    let card_keyid = card.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
    let card_agent = card.get("agent").and_then(|v| v.as_str()).unwrap_or("");
    let tools: Vec<String> = card
        .get("capabilities")
        .and_then(|c| c.get("tools"))
        .and_then(|t| t.as_array())
        .map(|a| a.iter().filter_map(|t| t.as_str().map(str::to_string)).collect())
        .unwrap_or_default();

    // --- Binding strength: key-bound vs self-asserted ----------------------
    // Key-bound iff the card's keyid is the envelope signer AND that key is
    // pinned under AgentCert. Anything else is self-asserted.
    let signer_keyid = record
        .envelope
        .signatures
        .first()
        .map(|s| s.keyid.as_str())
        .unwrap_or("");
    let keyid_is_signer = !card_keyid.is_empty() && signer_keyid == card_keyid;
    let trust = TrustRootStore::open_default_or_empty()?;
    let agentcert_pinned = trust
        .roots()
        .iter()
        .any(|r| r.key_id == card_keyid && r.kind == TrustRootKind::AgentCert);
    let key_bound = keyid_is_signer && agentcert_pinned;

    // --- Cross-check captured action receipts signed by this key -----------
    let action_pt = payload_type("action");
    let mut in_scope = 0usize;
    let mut total = 0usize;
    let mut violations: Vec<(String, String)> = Vec::new();
    for entry in ctx.storage.list_by_type(&action_pt) {
        let Ok(arec) = ctx.storage.read(&entry.id) else {
            continue;
        };
        let asigner = arec
            .envelope
            .signatures
            .first()
            .map(|s| s.keyid.as_str())
            .unwrap_or("");
        if asigner != card_keyid {
            continue; // only this key's actions count toward its card
        }
        let Ok(action): Result<ActionStatement, _> = arec.envelope.unmarshal_statement() else {
            continue;
        };
        total += 1;
        // A receipt is in scope if its action category OR its meta.tool matches
        // any declared capability (exact, or a `family.*` glob).
        let mut candidates = vec![action.action.clone()];
        if let Some(tool) = action
            .meta
            .as_ref()
            .and_then(|m| m.get("tool"))
            .and_then(|v| v.as_str())
        {
            candidates.push(tool.to_string());
        }
        let matched = candidates
            .iter()
            .any(|c| tools.iter().any(|decl| tool_matches(decl, c)));
        if matched {
            in_scope += 1;
        } else {
            violations.push((entry.id.clone(), candidates.join(" / ")));
        }
    }

    // --- evidence_anchor (optional): committed count vs observed ----------
    let anchor_note = card
        .get("evidence_anchor")
        .and_then(|a| a.get("receipt_count"))
        .and_then(|c| c.as_u64())
        .map(|claimed| {
            if claimed as usize == total {
                format!("anchor: claims {claimed} receipts, matches {total} observed")
            } else {
                format!("anchor: claims {claimed} receipts, observed {total} — MISMATCH (omission or backfill)")
            }
        });

    // --- Report ------------------------------------------------------------
    let status = if !key_bound {
        "self-asserted"
    } else if violations.is_empty() {
        "verified"
    } else {
        "violations"
    };
    let key_bound_str = if key_bound {
        "yes (AgentCert)"
    } else {
        "no (self-asserted)"
    };
    let tools_str = if tools.is_empty() {
        "(none declared)".to_string()
    } else {
        tools.join(", ")
    };
    let in_scope_str = in_scope.to_string();
    let oos_str = violations.len().to_string();
    printer.success(
        "capability card",
        &[
            ("card", card_id),
            ("agent", card_agent),
            ("key-bound", key_bound_str),
            ("declared tools", &tools_str),
            ("in-scope actions", &in_scope_str),
            ("out-of-scope", &oos_str),
            ("status", status),
        ],
    );
    if let Some(note) = &anchor_note {
        printer.hint(note);
    }
    // Show a bounded sample of violations; summarize the rest rather than
    // dumping an unbounded list. The count above is always exact.
    const MAX_SHOWN: usize = 10;
    for (id, tool) in violations.iter().take(MAX_SHOWN) {
        printer.warn(
            "out-of-scope action",
            &[("artifact", id), ("tool/action", tool)],
        );
    }
    if violations.len() > MAX_SHOWN {
        printer.hint(&format!(
            "... and {} more out-of-scope actions (see status above for the full count)",
            violations.len() - MAX_SHOWN
        ));
    }
    printer.blank();
    printer.hint(
        "consistency over captured evidence: proves in/out-of-scope for actions Treeship recorded, not that no off-card action occurred (that is Guard's runtime job).",
    );
    printer.blank();
    Ok(())
}

/// `family.*` matches `family.write`; otherwise an exact match. A bare `*`
/// matches anything.
fn tool_matches(declared: &str, actual: &str) -> bool {
    if let Some(prefix) = declared.strip_suffix('*') {
        actual.starts_with(prefix)
    } else {
        declared == actual
    }
}

#[cfg(test)]
mod tests {
    use super::tool_matches;

    #[test]
    fn exact_and_glob_matching() {
        assert!(tool_matches("file.write", "file.write"));
        assert!(!tool_matches("file.write", "file.read"));
        assert!(tool_matches("file.*", "file.write"));
        assert!(tool_matches("file.*", "file.read"));
        assert!(!tool_matches("file.*", "db.query"));
        assert!(tool_matches("*", "anything.at.all"));
    }
}
