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

use treeship_core::attestation::Envelope;
use treeship_core::capability::{declared_tools, is_key_bound, matched_capability};
use treeship_core::merkle::{MerkleTree, ProofFile};
use treeship_core::statements::{payload_type, ActionStatement, ReceiptStatement};
use treeship_core::trust::{TrustRootKind, TrustRootStore};
use treeship_core::verify::resolution::{verify_resolution, ResolutionBundle};

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
        let Some(payload) = stmt.payload else {
            continue;
        };
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
    let revocation =
        crate::commands::capability::find_revocation(&ctx, &card_id, card_keyid, &trust);

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
    // `discovered` (e.g. --from-a2a) is the agent's own published descriptor:
    // a real source, never silently lumped into operator-`declared`.
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
    let provenance_str = prov_parts.join(", ");

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

    // Hostile verdicts are machine-visible: nonzero exit, and in JSON mode a
    // single structured verdict object (the text path's info/warn lines are
    // suppressed or stream separately in JSON). A resolver that detects a
    // revoked card or violations and exits 0 lies to every script gating on it.
    let hostile = revocation.is_some() || (card_key_bound && out_of_scope > 0);
    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "verdict": status,
            "ok": !hostile,
            "agent": agent,
            "key": key_id,
            "key_provenance": key_grade,
            "current_card": card_id,
            "declared_tools": tools,
            "capabilities": cap_grade,
            "capability_mix": provenance_str,
            "captured_actions": total,
            "in_scope": in_scope,
            "out_of_scope": out_of_scope,
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
    if hostile {
        std::process::exit(1);
    }
    Ok(())
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

    // Parse the card statement for the capability display below.
    let stmt: ReceiptStatement = env.unmarshal_statement()?;
    if stmt.kind != "agent_card.v1" {
        return Err(format!("hub returned a `{}`, not an agent_card.v1", stmt.kind).into());
    }
    let card = stmt.payload.unwrap_or(serde_json::Value::Null);
    let tools = declared_tools(&card);

    // The single core trust-decision: verify the card (direct pin or chain
    // walk), then honor an authorized revocation. Same code path the WASM
    // verifier and SDKs run — see treeship_core::verify::resolution.
    let served_certs: Vec<(String, Envelope)> = bundle
        .get("certs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|c| {
                    let id = c.get("artifact_id").and_then(|v| v.as_str())?;
                    let ej = c.get("envelope_json").and_then(|v| v.as_str())?;
                    Some((id.to_string(), serde_json::from_str::<Envelope>(ej).ok()?))
                })
                .collect()
        })
        .unwrap_or_default();
    let revocation_envs: Vec<Envelope> = bundle
        .get("revocations")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|r| {
                    let ej = r.get("envelope_json").and_then(|v| v.as_str())?;
                    serde_json::from_str::<Envelope>(ej).ok()
                })
                .collect()
        })
        .unwrap_or_default();
    let now = treeship_core::statements::unix_to_rfc3339(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    );
    let verdict = verify_resolution(
        &ResolutionBundle {
            agent: agent.to_string(),
            card: env.clone(),
            certs: served_certs,
            revocations: revocation_envs,
        },
        trust,
        &now,
    )
    .map_err(|e| format!("hub returned an invalid card bundle: {e}"))?;
    let sig_ok = verdict.sig_ok;
    let key_bound = verdict.key_bound;
    let chain_cert_id = verdict.chain_cert_id;
    let revocation = verdict.revocation_reason;

    // Capability provenance from the card (captured/discovered grades travel
    // with it; exercised needs receipts and is unavailable over the network).
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
    let discovered: HashSet<String> = grade_set("discovered");
    let n_captured = tools.iter().filter(|t| captured.contains(*t)).count();
    let n_discovered = tools
        .iter()
        .filter(|t| !captured.contains(*t) && discovered.contains(*t))
        .count();
    let n_other = tools
        .len()
        .saturating_sub(n_captured)
        .saturating_sub(n_discovered);

    let sig_str = if sig_ok && chain_cert_id.is_some() {
        "verified (chain to pinned ship root)"
    } else if sig_ok {
        "verified (trusted key)"
    } else {
        "UNVERIFIED (key not in your trust roots)"
    };
    let key_bound_str = match (&chain_cert_id, key_bound) {
        (Some(_), _) => "yes (AgentCert via ship chain)",
        (None, true) => "yes (AgentCert)",
        (None, false) => "no",
    };
    let tools_str = if tools.is_empty() {
        "(none)".to_string()
    } else {
        tools.join(", ")
    };
    let mix_str = if n_discovered > 0 {
        format!("{n_captured} captured, {n_discovered} discovered, {n_other} declared (exercised n/a remotely)")
    } else {
        format!("{n_captured} captured, {n_other} declared (exercised n/a remotely)")
    };

    // Transparency: if the bundle carries a Merkle inclusion proof, re-verify
    // it offline (checkpoint signature against our trust roots + inclusion in
    // the signed root). Proves the card is in the log, not just signed.
    let transparency_str = match bundle.get("transparency").filter(|v| !v.is_null()) {
        Some(tp) => match serde_json::from_value::<ProofFile>(tp.clone()) {
            Ok(pf) => {
                let cp_ok = pf.checkpoint.verify(trust);
                let root_hex = pf
                    .checkpoint
                    .root
                    .strip_prefix("sha256:")
                    .unwrap_or(&pf.checkpoint.root);
                let incl_ok = MerkleTree::verify_proof(
                    pf.checkpoint.merkle_version,
                    root_hex,
                    &pf.artifact_id,
                    &pf.inclusion_proof,
                );
                if cp_ok && incl_ok {
                    format!("anchored & verified (checkpoint #{})", pf.checkpoint.index)
                } else if !cp_ok {
                    // Distinguish "you have not pinned this signer" from a
                    // genuinely failing signature. Checkpoint::verify fails
                    // closed on both, but they demand opposite reactions:
                    // pinning a root vs distrusting the hub. Labeling an
                    // unpinned signer INVALID is a mislabel this codebase
                    // cannot afford.
                    let signer_pinned = {
                        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
                        URL_SAFE_NO_PAD
                            .decode(&pf.checkpoint.public_key)
                            .ok()
                            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                            .map(|arr| trust.contains_bytes(&arr, TrustRootKind::HubCheckpoint))
                            .unwrap_or(false)
                    };
                    if signer_pinned {
                        "anchored, but checkpoint signature INVALID".to_string()
                    } else {
                        format!(
                            "anchored, but checkpoint signer not in your trust roots\n                   → pin it: treeship trust add <name> ed25519:{} --kind hub_checkpoint --yes",
                            pf.checkpoint.public_key
                        )
                    }
                } else {
                    "anchored, but inclusion proof INVALID".to_string()
                }
            }
            Err(_) => "anchored (proof unparseable)".to_string(),
        },
        None => "not anchored (no Merkle proof at the hub)".to_string(),
    };

    let status = if revocation.is_some() {
        "REVOKED"
    } else if key_bound {
        "resolved (key-bound)"
    } else if sig_ok {
        "resolved (verified sig, not key-bound)"
    } else {
        "resolved (UNVERIFIED)"
    };

    // Remote hostile verdicts: a revoked card, OR a signature that failed
    // against the verifier's roots (UNVERIFIED means verification FAILED —
    // matching verify-presentation's semantics — not merely "ungraded").
    // Machine-visible: nonzero exit + one structured JSON verdict object.
    let hostile = revocation.is_some() || !sig_ok;
    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "verdict": status,
            "ok": !hostile,
            "agent": agent,
            "hub": base,
            "current_card": card_id,
            "signature": sig_str,
            "key_bound": key_bound,
            "via_chain": chain_cert_id.is_some(),
            "chain_cert": chain_cert_id,
            "declared_tools": tools,
            "capability_mix": mix_str,
            "transparency": transparency_str,
            "revocation": revocation,
        }));
        if hostile {
            std::process::exit(1);
        }
        return Ok(());
    }

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
            ("transparency", &transparency_str),
            ("status", status),
        ],
    );
    if let Some(reason) = &revocation {
        printer.warn(
            "card REVOKED — do not honor",
            &[("reason", reason.as_str())],
        );
    }
    printer.blank();
    printer.hint(
        "re-verified client-side against YOUR trust roots; the hub's word is not trusted. the exercised grade needs the agent's receipts (run `treeship resolve` locally).",
    );
    printer.blank();
    if hostile {
        std::process::exit(1);
    }
    Ok(())
}
