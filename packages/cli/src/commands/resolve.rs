//! `treeship resolve <agent>` — resolve an agent URI to a verifiable bundle.
//!
//! The local, offline half of the agent resolver (docs/specs/agent-resolver.md):
//! given an agent URI, assemble its current capability card, revocation status,
//! and the provenance grade of each fact (captured / checked / asserted) from
//! locally-held artifacts, re-deriving every grade from the bytes rather than
//! trusting a stored verdict. The Hub endpoint will serve the same bundle; the
//! invariant is that the client, not the server, decides what to believe.

use crate::{ctx, printer::Printer};
use std::collections::{HashMap, HashSet};

use treeship_core::capability::{declared_tools, is_key_bound, matched_capability};
use treeship_core::statements::{payload_type, ActionStatement, ReceiptStatement};
use treeship_core::trust::TrustRootStore;

type CmdResult = Result<(), Box<dyn std::error::Error>>;

pub fn resolve(agent: &str, config: Option<&str>, printer: &Printer) -> CmdResult {
    let ctx = ctx::open(config)?;
    let trust = TrustRootStore::open_default_or_empty()?;

    // --- Identity: the agent's per-agent key --------------------------------
    let agents_dir = crate::commands::cards::agents_dir_for(&ctx.config_path);
    let key_id = crate::commands::cards::registered_key_for_actor(&agents_dir, agent);
    let key_bound = key_id
        .as_deref()
        .map(|k| is_key_bound(k, k, &trust))
        .unwrap_or(false);
    let key_grade = match (&key_id, key_bound) {
        (Some(_), true) => "captured (key-bound under AgentCert)",
        (Some(_), false) => "asserted (registered, not pinned)",
        (None, _) => "asserted (no per-agent key)",
    };

    // --- Current card: latest agent_card.v1 for this agent, signed by its key -
    let receipt_pt = payload_type("receipt");
    let mut current: Option<(String, serde_json::Value, String, String)> = None;
    for entry in ctx.storage.list_by_type(&receipt_pt) {
        let Ok(rec) = ctx.storage.read(&entry.id) else {
            continue;
        };
        let Ok(stmt) = rec.envelope.unmarshal_statement::<ReceiptStatement>() else {
            continue;
        };
        if stmt.kind != "agent_card.v1" {
            continue;
        }
        let Some(payload) = stmt.payload else { continue };
        if payload.get("agent").and_then(|v| v.as_str()) != Some(agent) {
            continue;
        }
        let signer = rec
            .envelope
            .signatures
            .first()
            .map(|s| s.keyid.clone())
            .unwrap_or_default();
        // If the agent has a registered key, only count cards it actually signed.
        if let Some(kid) = &key_id {
            if &signer != kid {
                continue;
            }
        }
        let newer = current
            .as_ref()
            .map(|(_, _, _, t)| entry.signed_at > *t)
            .unwrap_or(true);
        if newer {
            current = Some((entry.id.clone(), payload, signer, entry.signed_at.clone()));
        }
    }

    let Some((card_id, card, card_signer, _)) = current else {
        printer.warn("no capability card", &[("agent", agent)]);
        printer.hint(
            "this agent has no agent_card.v1 in the local store; mint one with `treeship attest card`.",
        );
        printer.blank();
        return Ok(());
    };

    let card_keyid = card.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
    let tools = declared_tools(&card);

    // --- Revocation (authorized only) ---------------------------------------
    let revocation = crate::commands::capability::find_revocation(&ctx, &card_id, card_keyid, &trust);

    // --- Capabilities grade: cross-check captured actions -------------------
    let action_pt = payload_type("action");
    let (mut in_scope, mut total) = (0usize, 0usize);
    let mut exercised: HashMap<String, usize> = HashMap::new();
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
            continue;
        }
        let Ok(action) = arec.envelope.unmarshal_statement::<ActionStatement>() else {
            continue;
        };
        total += 1;
        if let Some(matched) = matched_capability(&action, &tools) {
            in_scope += 1;
            *exercised.entry(matched).or_insert(0) += 1;
        }
    }
    let out_of_scope = total - in_scope;
    let card_key_bound = is_key_bound(card_keyid, &card_signer, &trust);

    // Capability provenance: captured (read off the card) vs exercised (from
    // captured receipts) vs declared-only. See docs/specs/capability-provenance.md.
    let captured: HashSet<String> = card
        .get("capability_provenance")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter(|(_, v)| v.get("grade").and_then(|g| g.as_str()) == Some("captured"))
                .map(|(k, _)| k.clone())
                .collect()
        })
        .unwrap_or_default();
    let (mut n_captured, mut n_exercised, mut n_declared) = (0usize, 0usize, 0usize);
    for tool in &tools {
        if captured.contains(tool) {
            n_captured += 1;
        } else if exercised.get(tool).copied().unwrap_or(0) > 0 {
            n_exercised += 1;
        } else {
            n_declared += 1;
        }
    }
    let provenance_str =
        format!("{n_captured} captured, {n_exercised} exercised, {n_declared} declared-only");

    let cap_grade = if revocation.is_some() {
        "revoked".to_string()
    } else if card_key_bound && out_of_scope == 0 {
        format!("checked ({in_scope}/{total} captured actions in scope)")
    } else if card_key_bound {
        format!("checked with violations ({out_of_scope} of {total} out of scope)")
    } else {
        "asserted (card not key-bound)".to_string()
    };
    let status = if revocation.is_some() {
        "REVOKED"
    } else if card_key_bound && out_of_scope == 0 {
        "resolved (verified)"
    } else if card_key_bound {
        "resolved (violations)"
    } else {
        "resolved (self-asserted)"
    };

    // --- Report --------------------------------------------------------------
    let key_str = key_id.as_deref().unwrap_or("(none)").to_string();
    let tools_str = if tools.is_empty() {
        "(none)".to_string()
    } else {
        tools.join(", ")
    };
    let behavior_str =
        format!("{total} captured actions ({in_scope} in scope, {out_of_scope} out)");
    printer.success(
        "agent resolved",
        &[
            ("agent", agent),
            ("key", &key_str),
            ("key provenance", key_grade),
            ("current card", &card_id),
            ("declared tools", &tools_str),
            ("capabilities", &cap_grade),
            ("capability mix", &provenance_str),
            ("behavior", &behavior_str),
            ("status", status),
        ],
    );
    if let Some((reason, who)) = &revocation {
        printer.warn(
            "card REVOKED — do not honor",
            &[("by", who), ("reason", reason)],
        );
    }
    printer.blank();
    printer.hint(
        "every field is re-derived from local artifacts, not a stored verdict. captured = the machine observed it; checked = a claim cross-verified against captured evidence; asserted = a bare claim.",
    );
    printer.blank();
    Ok(())
}
