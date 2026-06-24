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
use treeship_core::capability::action_in_scope;
// Re-exported: attest.rs (attest card) resolves is_key_bound through this path.
pub use treeship_core::capability::is_key_bound;
use treeship_core::{
    attestation::sign,
    statements::{payload_type, ActionStatement, ReceiptStatement},
    storage::Record,
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
    let trust = TrustRootStore::open_default_or_empty()?;
    let key_bound = is_key_bound(card_keyid, signer_keyid, &trust);

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
        // In scope if the action label OR meta.tool matches a declared
        // capability (exact or `family.*` glob). Shared with the WASM verifier
        // via treeship_core::capability so browser and CLI agree.
        if action_in_scope(&action, &tools) {
            in_scope += 1;
        } else {
            let mut label = action.action.clone();
            if let Some(tool) = action
                .meta
                .as_ref()
                .and_then(|m| m.get("tool"))
                .and_then(|v| v.as_str())
            {
                label = format!("{} / {tool}", action.action);
            }
            violations.push((entry.id.clone(), label));
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

    // --- Revocation: honor an authorized agent_card_revocation.v1 ----------
    // A revocation counts only when its signer is the card's own key
    // (self-revocation) or a Ship trust root (issuer revocation). A stranger
    // cannot revoke your card.
    let revocation = find_revocation(&ctx, card_id, card_keyid, &trust);

    // --- Report ------------------------------------------------------------
    let status = if revocation.is_some() {
        "REVOKED"
    } else if !key_bound {
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
    if let Some((reason, who)) = &revocation {
        printer.warn(
            "capability card REVOKED — do not honor",
            &[("by", who), ("reason", reason)],
        );
    }
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

/// `treeship revoke-capability <card_id>` — mint a signed revocation of a card.
///
/// The revocation is itself an `agent_card_revocation.v1` receipt, signed with
/// the agent's own key (self-revocation) when the card's actor has a registered
/// key, else the ship's default key. verify-capability honors it only when the
/// signer is authorized (the card's key, or a Ship root), so this is a real
/// authorization act, not a free-floating note.
pub fn revoke_capability(
    card_id: &str,
    reason: Option<&str>,
    config: Option<&str>,
    printer: &Printer,
) -> CmdResult {
    let ctx = ctx::open(config)?;

    // Read the card so the revocation records its keyid + actor.
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

    let revoked_at = crate::commands::verify::now_rfc3339();
    let mut payload = serde_json::Map::new();
    payload.insert("schema".into(), "agent_card_revocation.v1".into());
    payload.insert("card".into(), card_id.into());
    payload.insert("keyid".into(), card_keyid.into());
    if let Some(r) = reason {
        payload.insert("reason".into(), r.into());
    }
    payload.insert("revoked_at".into(), revoked_at.clone().into());
    let payload = serde_json::Value::Object(payload);

    treeship_core::predicates::validate("agent_card_revocation.v1", Some(&payload))
        .map_err(|e| format!("invalid revocation: {e}"))?;

    let mut stmt = ReceiptStatement::new("system://registry", "agent_card_revocation.v1");
    stmt.payload = Some(payload);

    // Sign as the agent (self-revocation) when the card's actor has a key.
    let signer = crate::commands::attest::resolve_actor_signer(&ctx, card_agent)?;
    let pt = payload_type("receipt");
    let result = sign(&pt, &stmt, signer.as_ref())?;
    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    Some(card_id.to_string()),
        envelope:     result.envelope,
        hub_url:      None,
    })?;

    let self_revoke = signer.key_id() == card_keyid;
    printer.success(
        "capability card revoked",
        &[
            ("revocation", &result.artifact_id),
            ("card", card_id),
            ("agent", card_agent),
            ("authority", if self_revoke { "self (agent key)" } else { "ship default key" }),
            ("reason", reason.unwrap_or("(none)")),
        ],
    );
    if !self_revoke {
        printer.hint(
            "signed with the ship's default key: verify-capability honors this only if that key is a Ship trust root; otherwise register the agent with --own-key and revoke as the agent.",
        );
    }
    printer.hint(&format!("treeship verify-capability {card_id}"));
    printer.blank();
    Ok(())
}

/// Find an authorized revocation of `card_id`, if any. Authorized = signed by
/// the card's own key (self-revocation) or a Ship trust root (issuer
/// revocation); a stranger's revocation is ignored. Returns (reason, who).
pub(crate) fn find_revocation(
    ctx: &ctx::Ctx,
    card_id: &str,
    card_keyid: &str,
    trust: &TrustRootStore,
) -> Option<(String, String)> {
    let receipt_pt = payload_type("receipt");
    for entry in ctx.storage.list_by_type(&receipt_pt) {
        let Ok(rec) = ctx.storage.read(&entry.id) else {
            continue;
        };
        let Ok(stmt) = rec.envelope.unmarshal_statement::<ReceiptStatement>() else {
            continue;
        };
        if stmt.kind != "agent_card_revocation.v1" {
            continue;
        }
        let Some(payload) = stmt.payload else { continue };
        if payload.get("card").and_then(|v| v.as_str()) != Some(card_id) {
            continue;
        }
        let rsigner = rec
            .envelope
            .signatures
            .first()
            .map(|s| s.keyid.as_str())
            .unwrap_or("");
        let self_revoke = !card_keyid.is_empty() && rsigner == card_keyid;
        let issuer_revoke = trust
            .roots()
            .iter()
            .any(|r| r.key_id == rsigner && r.kind == TrustRootKind::Ship);
        if self_revoke || issuer_revoke {
            let reason = payload
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("(no reason given)")
                .to_string();
            let who = if self_revoke {
                "self-revoked".to_string()
            } else {
                "issuer (ship) revoked".to_string()
            };
            return Some((reason, who));
        }
    }
    None
}

/// Is a receipt's `actor` cryptographically proven, i.e. signed by the actor's
/// registered, AgentCert-pinned per-agent key? Used by `verify` to label the
/// actor proven vs asserted. False for non-agent actors, unregistered agents,
/// a signer that isn't the registered key, or an unpinned key.
pub fn actor_proven(ctx: &crate::ctx::Ctx, actor: &str, signer_keyid: &str) -> bool {
    let agents_dir = crate::commands::cards::agents_dir_for(&ctx.config_path);
    let Some(registered) =
        crate::commands::cards::registered_key_for_actor(&agents_dir, actor)
    else {
        return false;
    };
    registered == signer_keyid
        && TrustRootStore::open_default_or_empty()
            .map(|t| is_key_bound(signer_keyid, signer_keyid, &t))
            .unwrap_or(false)
}

