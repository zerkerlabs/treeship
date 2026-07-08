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

use std::collections::{HashMap, HashSet};

use crate::{ctx, printer::Printer};
use treeship_core::capability::matched_capability;
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
    // Key-bound requires the card's OWN key to have produced a VALID signature
    // (re-verified here against pinned trust roots, never read from the
    // unverified `signatures[0].keyid` — a card could carry a forged first
    // signature naming a victim's AgentCert key alongside a second signature by
    // a locally-held key) AND that key pinned under AgentCert.
    let trust = TrustRootStore::open_default_or_empty()?;
    let verifier = crate::commands::resolve::verifier_from_trust(&trust);
    let card_verified_keys: Vec<String> = verifier
        .verify_any(&record.envelope)
        .map(|r| r.verified_key_ids)
        .unwrap_or_default();
    let key_bound = !card_keyid.is_empty()
        && card_verified_keys.iter().any(|k| k == card_keyid)
        && is_key_bound(card_keyid, card_keyid, &trust);

    // --- Cross-check captured action receipts signed by this key -----------
    let action_pt = payload_type("action");
    let mut in_scope = 0usize;
    let mut total = 0usize;
    let mut violations: Vec<(String, String)> = Vec::new();
    // Per-capability exercise counts: how many captured actions back each tool.
    let mut exercised: HashMap<String, usize> = HashMap::new();
    for entry in ctx.storage.list_by_type(&action_pt) {
        let Ok(arec) = ctx.storage.read(&entry.id) else {
            continue;
        };
        // Count an action toward the card only when the card's key produced a
        // VALID signature over it (re-verified against trust roots), never on
        // an unverified `signatures[0].keyid` match. A forged action naming
        // the card's key must not inflate the in-scope count.
        let averified: Vec<String> = verifier
            .verify_any(&arec.envelope)
            .map(|r| r.verified_key_ids)
            .unwrap_or_default();
        if !averified.iter().any(|k| k == card_keyid) {
            continue;
        }
        let Ok(action): Result<ActionStatement, _> = arec.envelope.unmarshal_statement() else {
            continue;
        };
        total += 1;
        // In scope if the action label OR meta.tool matches a declared
        // capability (exact or `family.*` glob). Shared with the WASM verifier
        // via treeship_core::capability so browser and CLI agree.
        if let Some(matched) = matched_capability(&action, &tools) {
            in_scope += 1;
            *exercised.entry(matched).or_insert(0) += 1;
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

    // --- Capability provenance: captured vs exercised vs declared-only ------
    // `captured` is read off the card (set at mint from harness config);
    // `exercised` is computed here from captured receipts; everything else is
    // `declared`. See docs/specs/capability-provenance.md.
    let grade_set = |grade: &str| -> HashSet<String> {
        card.get("capability_provenance")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .filter(|(_, v)| v.get("grade").and_then(|g| g.as_str()) == Some(grade))
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default()
    };
    let captured: HashSet<String> = grade_set("captured");
    // `discovered` (e.g. --from-a2a: the agent's own AgentCard skills) is a real
    // provenance source, weaker than receipt-backed `exercised` but stronger
    // than a bare `declared`. Counted in its own bucket so it is never silently
    // reported as operator-declared.
    let discovered: HashSet<String> = grade_set("discovered");
    let (mut n_captured, mut n_exercised, mut n_discovered, mut n_declared) =
        (0usize, 0usize, 0usize, 0usize);
    for tool in &tools {
        if captured.contains(tool) {
            n_captured += 1;
        } else if exercised.get(tool).copied().unwrap_or(0) > 0 {
            n_exercised += 1;
        } else if discovered.contains(tool) {
            n_discovered += 1;
        } else {
            n_declared += 1;
        }
    }
    let mut prov_parts = vec![
        format!("{n_captured} captured"),
        format!("{n_exercised} exercised"),
    ];
    if n_discovered > 0 {
        prov_parts.push(format!("{n_discovered} discovered"));
    }
    prov_parts.push(format!("{n_declared} declared-only"));
    let mut provenance_str = prov_parts.join(", ");
    // Provenance grades (`captured`, `discovered`) are read off the card's
    // signed payload — but a signed payload only means "someone asserted
    // this," not that the machine observed it, UNLESS the card is key-bound.
    // A self-asserted card can carry fabricated `captured`/`discovered` grades
    // that would otherwise print identically to real ones. Say so plainly, so
    // a reader (or a script) never mistakes a self-asserted grade for a
    // verified one. (`exercised` is computed here from re-verified receipts,
    // so it is trustworthy even when the card is not key-bound.)
    if !key_bound && (n_captured > 0 || n_discovered > 0) {
        provenance_str.push_str(" — captured/discovered are SELF-ASSERTED (card not key-bound; not machine-verified)");
    }

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

    // A hostile verdict must be machine-visible: nonzero exit and, in JSON
    // mode, one structured object carrying the full verdict (printer.info /
    // warn are suppressed or stream separate objects in JSON — useless to a
    // programmatic caller). A verifier that detects a revoked card or
    // out-of-scope actions and exits 0 is lying to every script gating on it.
    let hostile = revocation.is_some() || !violations.is_empty();
    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "verdict": status,
            "ok": !hostile,
            "card": card_id,
            "agent": card_agent,
            "key_bound": key_bound,
            "declared_tools": tools,
            "provenance": provenance_str,
            "in_scope": in_scope,
            "out_of_scope": violations.len(),
            "violations": violations
                .iter()
                .map(|(id, tool)| serde_json::json!({ "artifact": id, "action": tool }))
                .collect::<Vec<_>>(),
            "revocation": revocation
                .as_ref()
                .map(|(reason, who)| serde_json::json!({ "by": who, "reason": reason })),
        }));
        if hostile {
            std::process::exit(1);
        }
        return Ok(());
    }
    printer.success(
        "capability card",
        &[
            ("card", card_id),
            ("agent", card_agent),
            ("key-bound", key_bound_str),
            ("declared tools", &tools_str),
            ("provenance", &provenance_str),
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
    if hostile {
        std::process::exit(1);
    }
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

    // A revocation is honored by verify-capability ONLY when its signer is the
    // card's own key (self-revoke) or a pinned Ship root. If the resolved
    // signer is neither — e.g. the agent's per-agent key was rotated or
    // de-registered after a key-bound card was minted, so resolve_actor_signer
    // fell back to the shared ship key, which is not pinned as a Ship root
    // locally — then this revocation will be silently IGNORED by every
    // verifier. Refuse to mint it rather than print a success banner for a
    // revocation nobody will honor (fail-open masquerading as done).
    let will_be_honored = {
        let signer_kid = signer.key_id();
        let self_revoke = !card_keyid.is_empty() && signer_kid == card_keyid;
        let trust = TrustRootStore::open_default_or_empty()?;
        // Batch 5: issuer revocation is now scoped to the `Revoker` kind.
        let issuer_revoke = trust
            .roots()
            .iter()
            .any(|r| r.key_id == signer_kid && r.kind == TrustRootKind::Revoker);
        self_revoke || issuer_revoke
    };
    if !will_be_honored {
        return Err(format!(
            "revocation would be IGNORED by verifiers: the resolved signer ({}) is \
             neither the card's key ({}) nor a pinned `revoker` root.\n\n  This usually \
             means the agent's per-agent key was rotated or removed after the card \
             was minted. Re-register the agent's key, or pin a `revoker` trust root \
             (treeship trust add <key_id> <pubkey> --kind revoker) that is authorized \
             to revoke, then retry — do not rely on a revocation that will not be \
             honored.",
            signer.key_id(),
            if card_keyid.is_empty() { "(none)" } else { card_keyid },
        )
        .into());
    }

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
            "signed with the ship's default key: verify-capability honors this only if that key is pinned as a `revoker` trust root; otherwise register the agent with --own-key and revoke as the agent.",
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
        // The revoker's key must have produced a VALID signature over the
        // revocation, re-verified against trust roots — not read from the
        // unverified `signatures[0].keyid`. Otherwise a revocation carrying a
        // forged first keyid (the card's key, or a Ship root) plus a garbage
        // signature would be honored, letting a stranger revoke a card (DoS).
        let verified: Vec<String> = crate::commands::resolve::verifier_from_trust(trust)
            .verify_any(&rec.envelope)
            .map(|r| r.verified_key_ids)
            .unwrap_or_default();
        let self_revoke = !card_keyid.is_empty() && verified.iter().any(|k| k == card_keyid);
        // Batch 5: issuer revocation is now scoped to the `Revoker` kind.
        let issuer_revoke = verified.iter().any(|rk| {
            trust
                .roots()
                .iter()
                .any(|r| &r.key_id == rk && r.kind == TrustRootKind::Revoker)
        });
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

