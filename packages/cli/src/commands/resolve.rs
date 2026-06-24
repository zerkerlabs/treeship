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

use ed25519_dalek::VerifyingKey;
use treeship_core::attestation::{Envelope, Verifier};
use treeship_core::capability::{declared_tools, is_key_bound, matched_capability};
use treeship_core::statements::{payload_type, ActionStatement, ReceiptStatement};
use treeship_core::trust::{decode_ed25519_pubkey, TrustRootKind, TrustRootStore};

type CmdResult = Result<(), Box<dyn std::error::Error>>;

pub fn resolve(
    agent: &str,
    hub: Option<&str>,
    config: Option<&str>,
    printer: &Printer,
) -> CmdResult {
    let ctx = ctx::open(config)?;
    let trust = TrustRootStore::open_default_or_empty()?;

    // Remote resolution: pull the bundle from a Hub and re-verify it against
    // OUR trust roots. The Hub's word is never trusted; the client decides.
    if let Some(hub_url) = hub {
        return resolve_remote(hub_url, agent, &trust, printer);
    }

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

/// Build an offline Verifier from the client's pinned trust roots. An agent
/// whose key the client has not pinned simply will not verify, which is the
/// honest answer, not an error.
fn verifier_from_trust(trust: &TrustRootStore) -> Verifier {
    let mut map: HashMap<String, VerifyingKey> = HashMap::new();
    for r in trust.roots() {
        if let Ok(vk) = decode_ed25519_pubkey(&r.public_key) {
            map.insert(r.key_id.clone(), vk);
        }
    }
    Verifier::new(map)
}

/// Resolve an agent over the network: pull the bundle from `hub`, then
/// re-verify and grade it locally. The Hub serves raw signed envelopes; this
/// function, against the client's own trust roots, decides what to believe.
/// The exercised grade is local-only (the bundle carries no action receipts).
fn resolve_remote(hub: &str, agent: &str, trust: &TrustRootStore, printer: &Printer) -> CmdResult {
    let base = hub.trim_end_matches('/');
    let bundle: serde_json::Value = ureq::get(&format!("{base}/v1/agents"))
        .query("agent", agent)
        .call()
        .map_err(|e| format!("could not reach hub {base}: {e}"))?
        .into_json()
        .map_err(|e| format!("hub returned invalid JSON: {e}"))?;

    let verifier = verifier_from_trust(trust);

    let Some(card_entry) = bundle.get("current_card").filter(|v| !v.is_null()) else {
        printer.warn("no capability card", &[("agent", agent), ("hub", base)]);
        printer.hint("the hub holds no agent_card.v1 for this agent.");
        printer.blank();
        return Ok(());
    };
    let card_id = card_entry
        .get("artifact_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let env_json = card_entry
        .get("envelope_json")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let env: Envelope = serde_json::from_str(env_json)
        .map_err(|e| format!("hub returned an unparseable card envelope: {e}"))?;

    // Re-verify the signature against OUR trust roots.
    let sig_ok = verifier.verify_any(&env).is_ok();
    let stmt: ReceiptStatement = env.unmarshal_statement()?;
    if stmt.kind != "agent_card.v1" {
        return Err(format!("hub returned a `{}`, not an agent_card.v1", stmt.kind).into());
    }
    let card = stmt.payload.unwrap_or(serde_json::Value::Null);
    let card_keyid = card.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
    let signer = env
        .signatures
        .first()
        .map(|s| s.keyid.as_str())
        .unwrap_or("");
    let tools = declared_tools(&card);
    let key_bound = sig_ok && is_key_bound(card_keyid, signer, trust);

    // Honor an authorized, verifying revocation from the bundle.
    let mut revocation: Option<String> = None;
    if let Some(revs) = bundle.get("revocations").and_then(|v| v.as_array()) {
        for rev in revs {
            let rev_json = rev.get("envelope_json").and_then(|v| v.as_str()).unwrap_or("");
            let Ok(rev_env) = serde_json::from_str::<Envelope>(rev_json) else {
                continue;
            };
            if verifier.verify_any(&rev_env).is_err() {
                continue; // unverified revocation -> ignored
            }
            let Ok(rev_stmt) = rev_env.unmarshal_statement::<ReceiptStatement>() else {
                continue;
            };
            if rev_stmt.kind != "agent_card_revocation.v1" {
                continue;
            }
            let rev_signer = rev_env
                .signatures
                .first()
                .map(|s| s.keyid.as_str())
                .unwrap_or("");
            let self_revoke = !card_keyid.is_empty() && rev_signer == card_keyid;
            let issuer = trust
                .roots()
                .iter()
                .any(|r| r.key_id == rev_signer && r.kind == TrustRootKind::Ship);
            if self_revoke || issuer {
                revocation = Some(
                    rev_stmt
                        .payload
                        .as_ref()
                        .and_then(|p| p.get("reason"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("(no reason given)")
                        .to_string(),
                );
                break;
            }
        }
    }

    // Capability provenance from the card (captured grades travel with it).
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
    let n_captured = tools.iter().filter(|t| captured.contains(*t)).count();
    let n_other = tools.len().saturating_sub(n_captured);

    let sig_str = if sig_ok {
        "verified (trusted key)"
    } else {
        "UNVERIFIED (key not in your trust roots)"
    };
    let key_bound_str = if key_bound { "yes (AgentCert)" } else { "no" };
    let tools_str = if tools.is_empty() {
        "(none)".to_string()
    } else {
        tools.join(", ")
    };
    let mix_str = format!("{n_captured} captured, {n_other} declared (exercised n/a remotely)");
    let status = if revocation.is_some() {
        "REVOKED"
    } else if key_bound {
        "resolved (key-bound)"
    } else if sig_ok {
        "resolved (verified sig, not key-bound)"
    } else {
        "resolved (UNVERIFIED)"
    };

    printer.success(
        "agent resolved (remote)",
        &[
            ("agent", agent),
            ("hub", base),
            ("current card", &card_id),
            ("signature", sig_str),
            ("key-bound", key_bound_str),
            ("declared tools", &tools_str),
            ("capability mix", &mix_str),
            ("status", status),
        ],
    );
    if let Some(reason) = &revocation {
        printer.warn("card REVOKED — do not honor", &[("reason", reason.as_str())]);
    }
    printer.blank();
    printer.hint(
        "re-verified client-side against YOUR trust roots; the hub's word is not trusted. the exercised grade needs the agent's receipts (run `treeship resolve` locally).",
    );
    printer.blank();
    Ok(())
}
