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
use treeship_core::merkle::{MerkleTree, ProofFile};
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

/// Build an offline Verifier from the client's pinned trust roots. An agent
/// whose key the client has not pinned simply will not verify, which is the
/// honest answer, not an error.
pub(crate) fn verifier_from_trust(trust: &TrustRootStore) -> Verifier {
    let mut map: HashMap<String, VerifyingKey> = HashMap::new();
    for r in trust.roots() {
        if let Ok(vk) = decode_ed25519_pubkey(&r.public_key) {
            map.insert(r.key_id.clone(), vk);
        }
    }
    Verifier::new(map)
}

/// A card verified through the certificate chain rather than a direct leaf
/// pin: which cert artifact vouched, and the subject key it certified.
pub(crate) struct ChainVerdict {
    pub cert_id: String,
    pub subject_key: VerifyingKey,
}

/// Walk the certificate chain for a card whose signer key is NOT directly
/// pinned: find a served `agent_cert.v1` that (in this order, fail-closed at
/// every step):
///
///   1. is signed by a key pinned under `Ship` in MY trust roots — the cert
///      envelope signature is verified with the PINNED pubkey, never the
///      wire's, before any payload field is believed;
///   2. binds THIS agent URI to THIS card signer (`agent` + `subject_key_id`
///      match, and the card's own `keyid` claim equals its envelope signer,
///      mirroring `is_key_bound`);
///   3. is within its validity window at `now` (expired certs reject);
///   4. certifies a subject key that actually verifies the card envelope.
///
/// This is the TLS chain: pin the ship (the CA), verify its agents' leaves
/// through the cert, no per-leaf pinning. See registry-topology spec slice 1.
pub(crate) fn chain_verify_card(
    card_env: &Envelope,
    card_keyid: &str,
    agent: &str,
    certs: &[(String, Envelope)],
    trust: &TrustRootStore,
    now: &str,
) -> Option<ChainVerdict> {
    // The card must claim the key that signed it (same rule as is_key_bound):
    // a chain-verified signer vouches only for cards that bind themselves to
    // that exact key.
    let card_signer = card_env.signatures.first().map(|s| s.keyid.as_str())?;
    if card_keyid.is_empty() || card_keyid != card_signer {
        return None;
    }

    for (cert_id, cert_env) in certs {
        // 1. Cert envelope must verify against a PINNED Ship root. The
        //    pubkey comes from my trust store, never from the wire.
        let cert_signer = match cert_env.signatures.first() {
            Some(s) => s.keyid.as_str(),
            None => continue,
        };
        // Batch 5: certificate issuance is now scoped to the `CertIssuer`
        // kind (was the overloaded `Ship` kind).
        let Some(ship_root) = trust
            .roots()
            .iter()
            .find(|r| r.key_id == cert_signer && r.kind == TrustRootKind::CertIssuer)
        else {
            continue;
        };
        let Ok(ship_vk) = decode_ed25519_pubkey(&ship_root.public_key) else {
            continue;
        };
        let mut cert_verifier = Verifier::new(HashMap::new());
        cert_verifier.add_key(cert_signer.to_string(), ship_vk);
        if cert_verifier.verify_any(cert_env).is_err() {
            continue;
        }

        // Only now are the payload fields issuer-attested and believable.
        let Ok(stmt) = cert_env.unmarshal_statement::<ReceiptStatement>() else {
            continue;
        };
        if stmt.kind != "agent_cert.v1" {
            continue;
        }
        let Some(p) = stmt.payload else { continue };

        // 2. Binds this agent to this signer.
        if p.get("agent").and_then(|v| v.as_str()) != Some(agent)
            || p.get("subject_key_id").and_then(|v| v.as_str()) != Some(card_signer)
        {
            continue;
        }

        // 3. Validity window. Both bounds required — a cert missing either
        //    field fails closed. RFC 3339 UTC strings from the same
        //    generator compare lexicographically.
        let (Some(issued), Some(until)) = (
            p.get("issued_at").and_then(|v| v.as_str()),
            p.get("valid_until").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        if now < issued || now > until {
            continue;
        }

        // 4. The certified subject key must verify the card envelope itself.
        let Some(subject_b64) = p.get("subject_public_key").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(subject_vk) = decode_ed25519_pubkey(&format!("ed25519:{subject_b64}")) else {
            continue;
        };
        let mut card_verifier = Verifier::new(HashMap::new());
        card_verifier.add_key(card_signer.to_string(), subject_vk);
        if card_verifier.verify_any(card_env).is_err() {
            continue;
        }

        return Some(ChainVerdict {
            cert_id: cert_id.clone(),
            subject_key: subject_vk,
        });
    }
    None
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
    let mut sig_ok = verifier.verify_any(&env).is_ok();
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
    let mut key_bound = sig_ok && is_key_bound(card_keyid, signer, trust);

    // Chain walk: when the leaf key is not directly pinned, a served
    // agent_cert.v1 signed by a PINNED Ship root can vouch for it — the TLS
    // chain (pin the CA, verify the leaves through the cert). The verifier
    // used for the agent's revocations gains the chain-certified subject key
    // too, so a self-revocation signed by the agent's own key still counts.
    let mut chain_cert_id: Option<String> = None;
    let mut rev_verifier = verifier;
    if !key_bound {
        let served_certs: Vec<(String, Envelope)> = bundle
            .get("certs")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|c| {
                        let id = c.get("artifact_id").and_then(|v| v.as_str())?;
                        let ej = c.get("envelope_json").and_then(|v| v.as_str())?;
                        let cenv: Envelope = serde_json::from_str(ej).ok()?;
                        Some((id.to_string(), cenv))
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
        if let Some(verdict) =
            chain_verify_card(&env, card_keyid, agent, &served_certs, trust, &now)
        {
            sig_ok = true;
            key_bound = true;
            rev_verifier.add_key(signer.to_string(), verdict.subject_key);
            chain_cert_id = Some(verdict.cert_id);
        }
    }
    let verifier = rev_verifier;

    // Honor an authorized, verifying revocation from the bundle.
    let mut revocation: Option<String> = None;
    if let Some(revs) = bundle.get("revocations").and_then(|v| v.as_array()) {
        for rev in revs {
            let rev_json = rev
                .get("envelope_json")
                .and_then(|v| v.as_str())
                .unwrap_or("");
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
            // Batch 5: issuer revocation is now scoped to the `Revoker` kind
            // (was the overloaded `Ship` kind).
            let issuer = trust
                .roots()
                .iter()
                .any(|r| r.key_id == rev_signer && r.kind == TrustRootKind::Revoker);
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

#[cfg(test)]
mod chain_tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use treeship_core::attestation::{sign, Ed25519Signer, Signer};
    use treeship_core::trust::TrustRoot;

    const NOW: &str = "2026-07-06T12:00:00Z";

    fn cert_payload(agent: &str, subject: &Ed25519Signer) -> serde_json::Value {
        serde_json::json!({
            "agent": agent,
            "subject_key_id": subject.key_id(),
            "subject_public_key": URL_SAFE_NO_PAD.encode(subject.public_key_bytes()),
            "issuer": "ship://ship_test",
            "issued_at": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
        })
    }

    fn signed_receipt(kind: &str, payload: serde_json::Value, signer: &Ed25519Signer) -> Envelope {
        let mut stmt = ReceiptStatement::new("ship://ship_test", kind);
        stmt.payload = Some(payload);
        sign(&payload_type("receipt"), &stmt, signer)
            .unwrap()
            .envelope
    }

    fn signed_card(agent: &str, keyid_claim: &str, signer: &Ed25519Signer) -> Envelope {
        let mut stmt = ReceiptStatement::new("ship://ship_test", "agent_card.v1");
        stmt.payload = Some(serde_json::json!({ "agent": agent, "keyid": keyid_claim }));
        sign(&payload_type("receipt"), &stmt, signer)
            .unwrap()
            .envelope
    }

    fn ship_pinned(ship: &Ed25519Signer, kind: TrustRootKind) -> TrustRootStore {
        TrustRootStore::with_roots(vec![TrustRoot {
            key_id: ship.key_id().to_string(),
            public_key: format!(
                "ed25519:{}",
                URL_SAFE_NO_PAD.encode(ship.public_key_bytes())
            ),
            kind,
            label: "test ship".into(),
            added_at: String::new(),
        }])
    }

    #[test]
    fn chain_verifies_card_through_pinned_ship_root() {
        let ship = Ed25519Signer::generate("key_ship").unwrap();
        let agent_key = Ed25519Signer::generate("key_agent").unwrap();
        let cert = signed_receipt(
            "agent_cert.v1",
            cert_payload("agent://a", &agent_key),
            &ship,
        );
        let card = signed_card("agent://a", "key_agent", &agent_key);
        let trust = ship_pinned(&ship, TrustRootKind::CertIssuer);

        let verdict = chain_verify_card(
            &card,
            "key_agent",
            "agent://a",
            &[("art_cert".into(), cert)],
            &trust,
            NOW,
        );
        assert!(verdict.is_some(), "valid chain must verify");
        assert_eq!(verdict.unwrap().cert_id, "art_cert");
    }

    #[test]
    fn chain_rejects_unpinned_ship() {
        let ship = Ed25519Signer::generate("key_ship").unwrap();
        let agent_key = Ed25519Signer::generate("key_agent").unwrap();
        let cert = signed_receipt(
            "agent_cert.v1",
            cert_payload("agent://a", &agent_key),
            &ship,
        );
        let card = signed_card("agent://a", "key_agent", &agent_key);

        // Empty roots: a self-signed forgery chain must not verify.
        let empty = TrustRootStore::with_roots(vec![]);
        assert!(chain_verify_card(
            &card,
            "key_agent",
            "agent://a",
            &[("art_cert".into(), cert.clone())],
            &empty,
            NOW
        )
        .is_none());

        // Pinned under the WRONG kind (agent_cert, not ship) also rejects:
        // certifying agents is the Ship role, not a leaf role.
        let wrong_kind = ship_pinned(&ship, TrustRootKind::AgentCert);
        assert!(chain_verify_card(
            &card,
            "key_agent",
            "agent://a",
            &[("art_cert".into(), cert)],
            &wrong_kind,
            NOW
        )
        .is_none());
    }

    #[test]
    fn chain_rejects_expired_and_not_yet_valid_certs() {
        let ship = Ed25519Signer::generate("key_ship").unwrap();
        let agent_key = Ed25519Signer::generate("key_agent").unwrap();
        let card = signed_card("agent://a", "key_agent", &agent_key);
        let trust = ship_pinned(&ship, TrustRootKind::CertIssuer);

        let mut expired = cert_payload("agent://a", &agent_key);
        expired["valid_until"] = serde_json::json!("2026-01-02T00:00:00Z");
        let cert = signed_receipt("agent_cert.v1", expired, &ship);
        assert!(
            chain_verify_card(
                &card,
                "key_agent",
                "agent://a",
                &[("c".into(), cert)],
                &trust,
                NOW
            )
            .is_none(),
            "expired cert must reject"
        );

        let mut future = cert_payload("agent://a", &agent_key);
        future["issued_at"] = serde_json::json!("2026-12-01T00:00:00Z");
        let cert = signed_receipt("agent_cert.v1", future, &ship);
        assert!(
            chain_verify_card(
                &card,
                "key_agent",
                "agent://a",
                &[("c".into(), cert)],
                &trust,
                NOW
            )
            .is_none(),
            "not-yet-valid cert must reject"
        );

        let mut missing = cert_payload("agent://a", &agent_key);
        missing.as_object_mut().unwrap().remove("valid_until");
        let cert = signed_receipt("agent_cert.v1", missing, &ship);
        assert!(
            chain_verify_card(
                &card,
                "key_agent",
                "agent://a",
                &[("c".into(), cert)],
                &trust,
                NOW
            )
            .is_none(),
            "missing window must fail closed"
        );
    }

    #[test]
    fn chain_rejects_subject_and_agent_mismatches() {
        let ship = Ed25519Signer::generate("key_ship").unwrap();
        let agent_key = Ed25519Signer::generate("key_agent").unwrap();
        let other_key = Ed25519Signer::generate("key_other").unwrap();
        let trust = ship_pinned(&ship, TrustRootKind::CertIssuer);

        // Cert certifies a DIFFERENT key than the card's signer.
        let cert = signed_receipt(
            "agent_cert.v1",
            cert_payload("agent://a", &other_key),
            &ship,
        );
        let card = signed_card("agent://a", "key_agent", &agent_key);
        assert!(
            chain_verify_card(
                &card,
                "key_agent",
                "agent://a",
                &[("c".into(), cert)],
                &trust,
                NOW
            )
            .is_none(),
            "subject mismatch must reject"
        );

        // Cert for a DIFFERENT agent URI: key_agent certified for agent://b
        // must not vouch for a card claiming agent://a.
        let cert = signed_receipt(
            "agent_cert.v1",
            cert_payload("agent://b", &agent_key),
            &ship,
        );
        let card = signed_card("agent://a", "key_agent", &agent_key);
        assert!(
            chain_verify_card(
                &card,
                "key_agent",
                "agent://a",
                &[("c".into(), cert)],
                &trust,
                NOW
            )
            .is_none(),
            "agent URI mismatch must reject"
        );

        // Card signed by a key that is NOT the certified subject (stolen
        // cert, attacker's card): the subject-key check must catch it.
        let cert = signed_receipt(
            "agent_cert.v1",
            cert_payload("agent://a", &agent_key),
            &ship,
        );
        let card = signed_card("agent://a", "key_agent", &other_key);
        assert!(
            chain_verify_card(
                &card,
                "key_agent",
                "agent://a",
                &[("c".into(), cert)],
                &trust,
                NOW
            )
            .is_none(),
            "wrong card signer must reject"
        );

        // Card whose keyid claim differs from its envelope signer.
        let cert = signed_receipt(
            "agent_cert.v1",
            cert_payload("agent://a", &agent_key),
            &ship,
        );
        let card = signed_card("agent://a", "key_someone_else", &agent_key);
        assert!(
            chain_verify_card(
                &card,
                "key_someone_else",
                "agent://a",
                &[("c".into(), cert)],
                &trust,
                NOW
            )
            .is_none(),
            "keyid/signer mismatch must reject"
        );
    }
}
