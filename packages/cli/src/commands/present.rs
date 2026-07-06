//! `treeship present` / `treeship verify-presentation` — mutual-TLS-shaped
//! agent verification with no registry in the loop.
//!
//! Registry-topology slice 2 (docs/specs/registry-topology.md). In real TLS
//! the server HANDS you its cert chain; resolution-from-a-registry is the
//! backwards case. `present` packages what a counterparty needs into one
//! file the agent carries: its current capability card, the certificate
//! chain to its ship (so pinning one ship key suffices), any revocations it
//! knows of (honesty: the verifier decides their authority), and the
//! **staple** — the latest checkpoint plus this card's Merkle inclusion
//! proof, computed over the tree truncated to exactly the checkpoint's size
//! and root-cross-checked before anything is written.
//!
//! `verify-presentation` re-verifies everything offline against the
//! VERIFIER'S own trust roots: direct leaf pin or chain walk
//! (`chain_verify_card`, same code path as `resolve --hub`), authorized
//! revocations honored, staple checkpoint signature + inclusion re-checked,
//! and freshness reported as an explicit bound — `--max-staple-age` makes
//! it enforced. Honest constraint carried in the output: a presentation is
//! REPLAYABLE (it proves the record, not the counterparty; the
//! challenge-response mode that proves live key control is slice 3), and
//! revocation absence is only as current as the staple.

use std::collections::HashMap;

use crate::commands::resolve::{chain_verify_card, verifier_from_trust};
use crate::{ctx, printer::Printer};
use treeship_core::attestation::Envelope;
use treeship_core::merkle::{Checkpoint, InclusionProof, MerkleTree};
use treeship_core::statements::{parse_rfc3339_to_unix, payload_type, ReceiptStatement};
use treeship_core::trust::{TrustRootKind, TrustRootStore};

type CmdResult = Result<(), Box<dyn std::error::Error>>;

pub const PRESENTATION_TYPE: &str = "treeship/presentation/v1";

// ── present ─────────────────────────────────────────────────────────────────

pub fn present(
    agent: &str,
    out: Option<&str>,
    config: Option<&str>,
    printer: &Printer,
) -> CmdResult {
    let ctx = ctx::open(config)?;
    let agent = normalize_agent_uri(agent);
    let receipt_pt = payload_type("receipt");

    // The agent's registered key: same resolution rule as attest/resolve.
    let agents_dir = crate::commands::cards::agents_dir_for(&ctx.config_path);
    let key_id = crate::commands::cards::registered_key_for_actor(&agents_dir, &agent);

    // Current card: newest agent_card.v1 for this agent — signed by its
    // registered key when it has one (the same selection rule resolve uses,
    // so a presentation always carries the card a resolver would serve).
    let mut card: Option<(String, String, String)> = None; // (id, envelope_json, signed_at)
    let mut certs: Vec<(String, String)> = Vec::new(); // (id, envelope_json)
    let mut all_revocations: Vec<(String, String, String)> = Vec::new(); // (id, env, card_ref)
    for entry in ctx.storage.list_by_type(&receipt_pt) {
        let Ok(rec) = ctx.storage.read(&entry.id) else { continue };
        let Ok(stmt) = rec.envelope.unmarshal_statement::<ReceiptStatement>() else { continue };
        let env_json = serde_json::to_string(&rec.envelope)?;
        match stmt.kind.as_str() {
            "agent_card.v1" => {
                let Some(p) = &stmt.payload else { continue };
                if p.get("agent").and_then(|v| v.as_str()) != Some(agent.as_str()) {
                    continue;
                }
                if let Some(kid) = &key_id {
                    let signer = rec
                        .envelope
                        .signatures
                        .first()
                        .map(|s| s.keyid.as_str())
                        .unwrap_or("");
                    if signer != kid {
                        continue;
                    }
                }
                let newer = card
                    .as_ref()
                    .map(|(_, _, t)| entry.signed_at > *t)
                    .unwrap_or(true);
                if newer {
                    card = Some((entry.id.clone(), env_json, entry.signed_at.clone()));
                }
            }
            "agent_cert.v1" => {
                let Some(p) = &stmt.payload else { continue };
                if p.get("agent").and_then(|v| v.as_str()) == Some(agent.as_str()) {
                    certs.push((entry.id.clone(), env_json));
                }
            }
            "agent_card_revocation.v1" => {
                if let Some(card_ref) = stmt
                    .payload
                    .as_ref()
                    .and_then(|p| p.get("card"))
                    .and_then(|v| v.as_str())
                {
                    all_revocations.push((entry.id.clone(), env_json, card_ref.to_string()));
                }
            }
            _ => {}
        }
    }

    let Some((card_id, card_env_json, _)) = card else {
        return Err(format!(
            "no agent_card.v1 for {agent} in the local store\n\n  Fix: treeship onboard {agent} --from-harness <settings.json>"
        )
        .into());
    };

    // Honesty over self-interest: revocations referencing the presented card
    // are INCLUDED, not filtered. The verifier judges their authority; a
    // presenter that omitted them would be lying by omission, and the staple
    // hint in the verify output exists precisely because omission here is
    // possible for a hostile presenter.
    let revocations: Vec<serde_json::Value> = all_revocations
        .into_iter()
        .filter(|(_, _, card_ref)| card_ref == &card_id)
        .map(|(id, env, _)| serde_json::json!({ "artifact_id": id, "envelope_json": env }))
        .collect();

    // ── The staple: checkpoint + inclusion proof over the truncated tree ──
    // The proof must verify against the CHECKPOINT's root, so the tree is
    // rebuilt with exactly the first `tree_size` leaves and its root is
    // cross-checked against the checkpoint's before anything is written —
    // the same correctness rule the consistency publisher applies.
    let checkpoint = crate::commands::merkle::load_latest_checkpoint()?
        .ok_or("no checkpoints found -- run: treeship checkpoint")?;
    let (_, artifact_ids) = crate::commands::merkle::build_tree(&ctx)?;
    let leaf_index = artifact_ids
        .iter()
        .position(|id| id == &card_id)
        .ok_or("card artifact not found in the local Merkle tree")?;
    if leaf_index >= checkpoint.tree_size {
        return Err(format!(
            "the current card ({card_id}) is newer than the latest checkpoint (#{}, tree_size {})\n\n  Fix: treeship checkpoint  (then re-run present)",
            checkpoint.index, checkpoint.tree_size
        )
        .into());
    }
    let mut cp_tree = MerkleTree::new();
    for id in &artifact_ids[..checkpoint.tree_size] {
        cp_tree.append(id);
    }
    let computed_root = cp_tree
        .root()
        .map(hex::encode)
        .ok_or("checkpoint-sized tree has no root")?;
    let cp_root_hex = checkpoint.root.strip_prefix("sha256:").unwrap_or(&checkpoint.root);
    if computed_root != cp_root_hex {
        return Err(
            "local tree root does not match the latest checkpoint (artifacts changed since checkpointing)\n\n  Fix: treeship checkpoint  (then re-run present)"
                .into(),
        );
    }
    let inclusion_proof = cp_tree
        .inclusion_proof(leaf_index)
        .ok_or("failed to generate inclusion proof")?;

    let presentation = serde_json::json!({
        "type": PRESENTATION_TYPE,
        "profile": "identity",
        "agent": agent,
        "generated_at": treeship_core::statements::unix_to_rfc3339(unix_now()),
        "card": { "artifact_id": card_id, "envelope_json": card_env_json },
        "certs": certs
            .iter()
            .map(|(id, env)| serde_json::json!({ "artifact_id": id, "envelope_json": env }))
            .collect::<Vec<_>>(),
        "revocations": revocations,
        "staple": {
            "checkpoint": checkpoint,
            "inclusion_proof": inclusion_proof,
        },
    });

    let default_name = format!("{}.presentation.json", agent.trim_start_matches("agent://"));
    let out_path = out.unwrap_or(&default_name);
    std::fs::write(out_path, serde_json::to_vec_pretty(&presentation)?)?;

    printer.success("presentation written", &[
        ("agent",  agent.as_str()),
        ("card",   card_id.as_str()),
        ("certs",  &certs.len().to_string()),
        ("staple", &format!("checkpoint #{} ({})", checkpoint.index, checkpoint.signed_at)),
        ("file",   out_path),
    ]);
    printer.hint(&format!("a counterparty verifies with: treeship verify-presentation {out_path}"));
    printer.hint("static presentation: proves the record, not the bearer — challenge mode (slice 3) proves live key control");
    printer.blank();
    Ok(())
}

// ── verify-presentation ─────────────────────────────────────────────────────

pub fn verify_presentation(
    path: &str,
    max_staple_age: Option<&str>,
    printer: &Printer,
) -> CmdResult {
    let trust = TrustRootStore::open_default_or_empty()?;
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read {path}: {e}"))?;
    let pres: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("{path} is not valid JSON: {e}"))?;

    if pres.get("type").and_then(|v| v.as_str()) != Some(PRESENTATION_TYPE) {
        return Err(format!("{path} is not a {PRESENTATION_TYPE} file").into());
    }
    let agent = pres
        .get("agent")
        .and_then(|v| v.as_str())
        .ok_or("presentation carries no agent URI")?;

    // ── Card: direct pin, or chain walk to a pinned Ship root ─────────────
    let card_env_json = pres
        .get("card")
        .and_then(|c| c.get("envelope_json"))
        .and_then(|v| v.as_str())
        .ok_or("presentation carries no card envelope")?;
    let card_id = pres
        .get("card")
        .and_then(|c| c.get("artifact_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let env: Envelope = serde_json::from_str(card_env_json)
        .map_err(|e| format!("unparseable card envelope: {e}"))?;
    let mut verifier = verifier_from_trust(&trust);
    let mut sig_ok = verifier.verify_any(&env).is_ok();
    let stmt: ReceiptStatement = env.unmarshal_statement()?;
    if stmt.kind != "agent_card.v1" {
        return Err(format!("presentation card is a `{}`, not an agent_card.v1", stmt.kind).into());
    }
    let card = stmt.payload.unwrap_or(serde_json::Value::Null);
    if card.get("agent").and_then(|v| v.as_str()) != Some(agent) {
        return Err("card's agent URI does not match the presentation's".into());
    }
    let card_keyid = card.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
    let signer = env
        .signatures
        .first()
        .map(|s| s.keyid.as_str())
        .unwrap_or("")
        .to_string();
    let mut key_bound =
        sig_ok && treeship_core::capability::is_key_bound(card_keyid, &signer, &trust);

    let served_certs: Vec<(String, Envelope)> = pres
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
    let now_rfc = treeship_core::statements::unix_to_rfc3339(unix_now());
    let mut via_chain = false;
    if !key_bound {
        if let Some(verdict) =
            chain_verify_card(&env, card_keyid, agent, &served_certs, &trust, &now_rfc)
        {
            sig_ok = true;
            key_bound = true;
            via_chain = true;
            verifier.add_key(signer.clone(), verdict.subject_key);
        }
    }

    // ── Revocations: honored when authorized, exactly as resolve does ─────
    let mut revoked: Option<String> = None;
    if let Some(revs) = pres.get("revocations").and_then(|v| v.as_array()) {
        for rev in revs {
            let rev_json = rev.get("envelope_json").and_then(|v| v.as_str()).unwrap_or("");
            let Ok(rev_env) = serde_json::from_str::<Envelope>(rev_json) else { continue };
            if verifier.verify_any(&rev_env).is_err() {
                continue;
            }
            let Ok(rev_stmt) = rev_env.unmarshal_statement::<ReceiptStatement>() else { continue };
            if rev_stmt.kind != "agent_card_revocation.v1" {
                continue;
            }
            if rev_stmt
                .payload
                .as_ref()
                .and_then(|p| p.get("card"))
                .and_then(|v| v.as_str())
                != Some(card_id)
            {
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
                revoked = Some(
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

    // ── Staple: checkpoint signature + card inclusion, then freshness ─────
    let (staple_str, staple_ok, staple_age_secs) = verify_staple(&pres, card_id, &trust);

    // Freshness bound: enforced only when the verifier asks. Reported always.
    let mut stale = false;
    if let Some(max) = max_staple_age {
        let max_secs = parse_duration_secs(max)
            .ok_or(format!("--max-staple-age {max} is not a duration (try 30s, 15m, 2h, 1d)"))?;
        match staple_age_secs {
            Some(age) if age <= max_secs => {}
            Some(age) => {
                stale = true;
                printer.warn(
                    &format!(
                        "staple is {} — older than your --max-staple-age {max}",
                        human_secs(age)
                    ),
                    &[],
                );
            }
            None => {
                stale = true;
                printer.warn("staple age unknown; --max-staple-age fails closed", &[]);
            }
        }
    }

    // ── Verdict ────────────────────────────────────────────────────────────
    let sig_str = if sig_ok && via_chain {
        "verified (chain to pinned ship root)"
    } else if sig_ok {
        "verified (trusted key)"
    } else {
        "UNVERIFIED (key not in your trust roots)"
    };
    let key_bound_str = if via_chain {
        "yes (AgentCert via ship chain)"
    } else if key_bound {
        "yes (AgentCert)"
    } else {
        "no"
    };
    let age_str = staple_age_secs
        .map(human_secs)
        .unwrap_or_else(|| "unknown age".into());
    let revocation_str = match &revoked {
        Some(reason) => format!("REVOKED — {reason}"),
        None => format!(
            "none included — current as of the staple ({age_str}); for currency, audit a log"
        ),
    };
    let status = if revoked.is_some() {
        "REVOKED"
    } else if stale {
        "STALE (verified, but older than your freshness bound)"
    } else if key_bound && staple_ok {
        "verified (key-bound, anchored)"
    } else if key_bound {
        "verified (key-bound; staple unverified)"
    } else {
        "UNVERIFIED"
    };

    let ok = revoked.is_none() && key_bound && !stale;
    let headline = "presentation";
    if ok {
        printer.success(headline, &[]);
    } else {
        printer.warn(headline, &[]);
    }
    printer.info(&format!("  agent:       {agent}"));
    printer.info(&format!("  card:        {card_id}"));
    printer.info(&format!("  signature:   {sig_str}"));
    printer.info(&format!("  key-bound:   {key_bound_str}"));
    printer.info(&format!("  staple:      {staple_str}"));
    printer.info(&format!("  revocation:  {revocation_str}"));
    printer.info(&format!("  status:      {status}"));
    printer.blank();
    printer.hint(
        "static presentation: proves the record, not the bearer. For proof the counterparty controls this key, use challenge mode (slice 3).",
    );
    printer.blank();
    if !ok {
        return Err("presentation did not verify".into());
    }
    Ok(())
}

/// Verify the staple offline: checkpoint signature against pinned
/// hub_checkpoint roots, then the card's inclusion in that signed root.
/// Returns (report line, verified, age in seconds when computable).
fn verify_staple(
    pres: &serde_json::Value,
    card_id: &str,
    trust: &TrustRootStore,
) -> (String, bool, Option<u64>) {
    let Some(staple) = pres.get("staple").filter(|v| !v.is_null()) else {
        return ("none included".into(), false, None);
    };
    let Ok(checkpoint) =
        serde_json::from_value::<Checkpoint>(staple.get("checkpoint").cloned().unwrap_or_default())
    else {
        return ("unparseable checkpoint".into(), false, None);
    };
    let Ok(proof) = serde_json::from_value::<InclusionProof>(
        staple.get("inclusion_proof").cloned().unwrap_or_default(),
    ) else {
        return ("unparseable inclusion proof".into(), false, None);
    };

    let age = parse_rfc3339_to_unix(&checkpoint.signed_at)
        .map(|t| unix_now().saturating_sub(t));

    if !checkpoint.verify(trust) {
        return (
            format!(
                "checkpoint #{} signer not in your trust roots (or signature invalid) — pin it: treeship trust add <name> ed25519:{} --kind hub_checkpoint --yes",
                checkpoint.index, checkpoint.public_key
            ),
            false,
            age,
        );
    }
    let root_hex = checkpoint
        .root
        .strip_prefix("sha256:")
        .unwrap_or(&checkpoint.root);
    if !MerkleTree::verify_proof(checkpoint.merkle_version, root_hex, card_id, &proof) {
        return (
            format!("checkpoint #{} verified, but card inclusion proof INVALID", checkpoint.index),
            false,
            age,
        );
    }
    let age_str = age.map(human_secs).unwrap_or_else(|| "unknown age".into());
    (
        format!(
            "checkpoint #{} verified, inclusion verified ({age_str})",
            checkpoint.index
        ),
        true,
        age,
    )
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn normalize_agent_uri(agent: &str) -> String {
    if agent.starts_with("agent://") {
        agent.to_string()
    } else {
        format!("agent://{agent}")
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// "30s" / "15m" / "2h" / "1d" / bare seconds → seconds. None on anything else.
pub(crate) fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Ok(n) = s.parse::<u64>() {
        return Some(n);
    }
    let (num, unit) = s.split_at(s.len().checked_sub(1)?);
    let n: u64 = num.parse().ok()?;
    match unit {
        "s" => Some(n),
        "m" => n.checked_mul(60),
        "h" => n.checked_mul(3600),
        "d" => n.checked_mul(86400),
        _ => None,
    }
}

fn human_secs(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s old")
    } else if secs < 3600 {
        format!("{}m old", secs / 60)
    } else if secs < 86400 {
        format!("{}h old", secs / 3600)
    } else {
        format!("{}d old", secs / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration_secs("30s"), Some(30));
        assert_eq!(parse_duration_secs("15m"), Some(900));
        assert_eq!(parse_duration_secs("2h"), Some(7200));
        assert_eq!(parse_duration_secs("1d"), Some(86400));
        assert_eq!(parse_duration_secs("90"), Some(90));
        assert_eq!(parse_duration_secs("soon"), None);
        assert_eq!(parse_duration_secs(""), None);
        assert_eq!(parse_duration_secs("-5m"), None);
    }

    #[test]
    fn agent_uri_normalization() {
        assert_eq!(normalize_agent_uri("deployer"), "agent://deployer");
        assert_eq!(normalize_agent_uri("agent://deployer"), "agent://deployer");
    }
}
