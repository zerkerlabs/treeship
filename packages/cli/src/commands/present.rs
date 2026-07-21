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

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::{ctx, printer::Printer};
use treeship_core::attestation::Envelope;
use treeship_core::merkle::MerkleTree;
use treeship_core::statements::{parse_rfc3339_to_unix, payload_type, ReceiptStatement};
use treeship_core::trust::TrustRootStore;
use treeship_core::verify::presentation::{
    challenge_canonical, ChallengeOutcome, PresentationVerdict, StapleStatus,
};

type CmdResult = Result<(), Box<dyn std::error::Error>>;

pub const PRESENTATION_TYPE: &str = "treeship/presentation/v1";

// ── present ─────────────────────────────────────────────────────────────────

pub fn present(
    agent: &str,
    out: Option<&str>,
    challenge: Option<&str>,
    disclose: &[String],
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
        let Ok(rec) = ctx.storage.read(&entry.id) else {
            continue;
        };
        let Ok(stmt) = rec.envelope.unmarshal_statement::<ReceiptStatement>() else {
            continue;
        };
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

    let Some((mut card_id, mut card_env_json, _)) = card else {
        return Err(format!(
            "no agent_card.v1 for {agent} in the local store\n\n  Fix: treeship onboard {agent} --from-harness <settings.json>"
        )
        .into());
    };

    // ── Selective disclosure ──────────────────────────────────────────────
    // Re-sign a digests-only copy of the card that reveals only the named
    // capabilities; the rest become opaque salted digests. The re-sign is by
    // the agent's OWN key (so the disclosed card stays key-bound), and it is
    // ephemeral -- not in the transparency log -- so a disclosed presentation
    // carries no staple and reports "not anchored". This is the honest trade:
    // a private selective claim you would not want in the public log.
    let mut disclosures_block: Option<Vec<String>> = None;
    let mut disclosed_total: Option<usize> = None;
    if !disclose.is_empty() {
        let Some(kid) = &key_id else {
            return Err(format!(
                "selective disclosure requires a per-agent key for {agent}\n\n  Fix: treeship agent register --name {} --own-key",
                agent.trim_start_matches("agent://")
            )
            .into());
        };
        let env_parsed: Envelope = serde_json::from_str(&card_env_json)?;
        let card_stmt: ReceiptStatement = env_parsed.unmarshal_statement()?;
        let card_payload = card_stmt.payload.ok_or("card carries no payload")?;
        // The card must be bound to the agent's key, or the re-sign would swap
        // the binding out from under the disclosure.
        let bound = card_payload
            .get("keyid")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if bound != kid {
            return Err(format!(
                "the current card is bound to {bound}, but this agent's key is {kid} -- re-mint the card first\n\n  Fix: treeship attest card --agent {agent} ..."
            )
            .into());
        }
        // Every requested capability must actually be in the card, or the
        // presentation would claim something the agent never declared.
        let all_tools = treeship_core::capability::declared_tools(&card_payload);
        disclosed_total = Some(all_tools.len());
        for cap in disclose {
            if !all_tools.iter().any(|t| t == cap) {
                return Err(format!(
                    "capability `{cap}` is not in {agent}'s card\n  card declares: {}",
                    all_tools.join(", ")
                )
                .into());
            }
        }
        let (disclosed_payload, selected) =
            treeship_core::capability::disclose_capabilities(&card_payload, disclose);
        let mut stmt = ReceiptStatement::new("system://registry", "agent_card.v1");
        stmt.payload = Some(disclosed_payload);
        let signer = ctx.keys.signer(kid)?;
        let result = treeship_core::attestation::sign::sign(&receipt_pt, &stmt, signer.as_ref())?;
        card_id = result.artifact_id.clone();
        card_env_json = serde_json::to_string(&result.envelope)?;
        disclosures_block = Some(selected);
    }

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
    //
    // Skipped for a disclosed presentation: the disclosed card is an ephemeral
    // re-sign that is deliberately not in the transparency log, so there is
    // nothing to staple. The presentation reports "not anchored" instead.
    let (staple_json, staple_desc): (serde_json::Value, String) = if disclose.is_empty() {
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
        let cp_root_hex = checkpoint
            .root
            .strip_prefix("sha256:")
            .unwrap_or(&checkpoint.root);
        if computed_root != cp_root_hex {
            return Err(
                "local tree root does not match the latest checkpoint (artifacts changed since checkpointing)\n\n  Fix: treeship checkpoint  (then re-run present)"
                    .into(),
            );
        }
        let inclusion_proof = cp_tree
            .inclusion_proof(leaf_index)
            .ok_or("failed to generate inclusion proof")?;
        let desc = format!(
            "checkpoint #{} ({})",
            checkpoint.index, checkpoint.signed_at
        );
        (
            serde_json::json!({ "checkpoint": checkpoint, "inclusion_proof": inclusion_proof }),
            desc,
        )
    } else {
        (
            serde_json::Value::Null,
            "none (disclosed presentation, not anchored)".to_string(),
        )
    };

    // ── Challenge response (slice 3, the handshake) ────────────────────────
    // Signs the verifier's nonce with the AGENT'S OWN key — never a
    // fallback. resolve_actor_signer's silent ship-key fallback is exactly
    // wrong here: a ship-key signature would prove the operator is present,
    // not the agent, while claiming the latter. Fail closed instead.
    let mut challenge_block: Option<serde_json::Value> = None;
    if let Some(nonce) = challenge {
        let Some(kid) = &key_id else {
            return Err(format!(
                "challenge mode requires a per-agent key for {agent}\n\n  Fix: treeship agent register --name {} --own-key",
                agent.trim_start_matches("agent://")
            )
            .into());
        };
        // The signing key must be the key the card is bound to — a challenge
        // answered by a different key than the card's proves nothing about
        // the card's subject.
        let card_env_parsed: Envelope = serde_json::from_str(&card_env_json)?;
        let card_stmt: ReceiptStatement = card_env_parsed.unmarshal_statement()?;
        let card_bound_key = card_stmt
            .payload
            .as_ref()
            .and_then(|p| p.get("keyid"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if card_bound_key != kid {
            return Err(format!(
                "the current card is bound to {card_bound_key}, but this agent's registered key is {kid} — re-mint the card before answering challenges\n\n  Fix: treeship attest card --agent {agent} ..."
            )
            .into());
        }
        let signed_at = treeship_core::statements::unix_to_rfc3339(unix_now());
        let canonical = challenge_canonical(&agent, &card_id, nonce, &signed_at);
        let signer = ctx.keys.signer(kid)?;
        let sig = signer.sign(&canonical)?;
        challenge_block = Some(serde_json::json!({
            "nonce": nonce,
            "key_id": kid,
            "signed_at": signed_at,
            "signature": URL_SAFE_NO_PAD.encode(sig),
        }));
    }

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
        "staple": staple_json,
        "disclosures": disclosures_block,
        "challenge": challenge_block,
    });

    let default_name = format!("{}.presentation.json", agent.trim_start_matches("agent://"));
    let out_path = out.unwrap_or(&default_name);
    std::fs::write(out_path, serde_json::to_vec_pretty(&presentation)?)?;

    let disclosed_desc = disclosures_block
        .as_ref()
        .map(|d| {
            format!(
                "{} of {} capabilities revealed",
                d.len(),
                disclosed_total.unwrap_or(d.len())
            )
        })
        .unwrap_or_else(|| "full card".to_string());
    printer.success(
        "presentation written",
        &[
            ("agent", agent.as_str()),
            ("card", card_id.as_str()),
            ("certs", &certs.len().to_string()),
            ("staple", &staple_desc),
            ("reveals", &disclosed_desc),
            ("file", out_path),
        ],
    );
    printer.hint(&format!(
        "a counterparty verifies with: treeship verify-presentation {out_path}"
    ));
    if challenge.is_some() {
        printer.hint("challenge response included — the verifier passes the SAME nonce to verify-presentation --challenge");
    } else {
        printer.hint("static presentation: proves the record, not the bearer — add --challenge <their-nonce> to prove live key control");
    }
    printer.blank();
    Ok(())
}

// ── verify-presentation ─────────────────────────────────────────────────────

pub fn verify_presentation(
    path: &str,
    max_staple_age: Option<&str>,
    challenge: Option<&str>,
    printer: &Printer,
) -> CmdResult {
    let trust = TrustRootStore::open_default_or_empty()?;
    let raw = std::fs::read_to_string(path).map_err(|e| format!("could not read {path}: {e}"))?;
    let pres: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("{path} is not valid JSON: {e}"))?;

    if pres.get("type").and_then(|v| v.as_str()) != Some(PRESENTATION_TYPE) {
        return Err(format!("{path} is not a {PRESENTATION_TYPE} file").into());
    }

    // The single core trust-decision: card (direct pin or chain), revocation,
    // challenge liveness, and staple. Same code the WASM verifier and SDKs run.
    let now = unix_now();
    let PresentationVerdict {
        agent,
        card_id,
        sig_ok,
        key_bound,
        via_chain,
        revoked,
        challenge: challenge_outcome,
        staple: sv,
    } = treeship_core::verify::presentation::verify_presentation(&pres, &trust, challenge, now)?;

    // Re-parse the card payload for the selective-disclosure display below (the
    // trust decision above already consumed and verified the envelope).
    let card: serde_json::Value = pres
        .get("card")
        .and_then(|c| c.get("envelope_json"))
        .and_then(|v| v.as_str())
        .and_then(|ej| serde_json::from_str::<Envelope>(ej).ok())
        .and_then(|env| env.unmarshal_statement::<ReceiptStatement>().ok())
        .and_then(|st| st.payload)
        .unwrap_or(serde_json::Value::Null);

    // Challenge display + liveness, formatted from the core outcome.
    let challenge_ok = challenge_outcome.is_ok();
    let challenge_str: Option<String> = match &challenge_outcome {
        ChallengeOutcome::NotRequested => None,
        ChallengeOutcome::PresentButUnchecked => Some(
            "response present but NOT checked — pass --challenge <the nonce you issued> to verify liveness"
                .to_string(),
        ),
        ChallengeOutcome::NoResponse => Some(
            "no challenge response in this presentation — ask the bearer to re-present with --challenge <your nonce>"
                .to_string(),
        ),
        ChallengeOutcome::NoEstablishedKey => Some(
            "cannot check: the card did not verify key-bound, so there is no established key to check the response against"
                .to_string(),
        ),
        ChallengeOutcome::Failed { reason } => Some(reason.clone()),
        ChallengeOutcome::Verified { signed_at } => {
            let age = parse_rfc3339_to_unix(signed_at)
                .map(|t| human_secs(now.saturating_sub(t)))
                .unwrap_or_else(|| "unknown age".into());
            let keyid = card.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
            Some(format!("verified — bearer controls {keyid} (response {age})"))
        }
    };

    let card_id = card_id.as_str();
    let agent = agent.as_str();
    let staple_ok = sv.verified;
    let staple_age_secs = sv.age_secs;
    let staple_str = match sv.status {
        StapleStatus::NoStaple => "none included".to_string(),
        StapleStatus::Unparseable => "unparseable staple".to_string(),
        StapleStatus::SignerNotTrusted => format!(
            "checkpoint #{} signer not in your trust roots (or signature invalid) — pin it: treeship trust add <name> ed25519:{} --kind hub_checkpoint --yes",
            sv.checkpoint_index.unwrap_or(0),
            sv.checkpoint_public_key.as_deref().unwrap_or("")
        ),
        StapleStatus::InclusionInvalid => format!(
            "checkpoint #{} verified, but card inclusion proof INVALID",
            sv.checkpoint_index.unwrap_or(0)
        ),
        StapleStatus::Verified => {
            let age_str = sv
                .age_secs
                .map(human_secs)
                .unwrap_or_else(|| "unknown age".into());
            format!(
                "checkpoint #{} verified, inclusion verified ({age_str})",
                sv.checkpoint_index.unwrap_or(0)
            )
        }
    };

    // Freshness bound: enforced only when the verifier asks. Reported always.
    let mut stale = false;
    if let Some(max) = max_staple_age {
        let max_secs = parse_duration_secs(max).ok_or(format!(
            "--max-staple-age {max} is not a duration (try 30s, 15m, 2h, 1d)"
        ))?;
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
    let live = challenge.is_some() && challenge_ok;
    let status = if revoked.is_some() {
        "REVOKED"
    } else if challenge.is_some() && !challenge_ok {
        "CHALLENGE FAILED (record may verify, but the bearer did not prove key control)"
    } else if stale {
        "STALE (verified, but older than your freshness bound)"
    } else if key_bound && staple_ok && live {
        "verified (key-bound, anchored, live)"
    } else if key_bound && staple_ok {
        "verified (key-bound, anchored)"
    } else if key_bound {
        "verified (key-bound; staple unverified)"
    } else {
        "UNVERIFIED"
    };

    let ok = revoked.is_none() && key_bound && !stale && challenge_ok;

    // Selective disclosure: a card carrying `capabilities.tools_sd` is a
    // disclosed card. Reconstruct exactly the capabilities the presenter
    // revealed, checked against the signed digests (a tampered or foreign
    // disclosure reveals nothing). These are only as trustworthy as the card's
    // signature verdict above; the status line carries that.
    let disclosed = card
        .get("capabilities")
        .and_then(|c| c.get("tools_sd"))
        .is_some();
    let (revealed_caps, reveal_str): (Vec<String>, Option<String>) = if disclosed {
        let disclosures: Vec<String> = pres
            .get("disclosures")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|d| d.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let revealed = treeship_core::capability::reconstruct_capabilities(&card, &disclosures);
        let total = treeship_core::capability::committed_tool_digests(&card).len();
        let s = format!(
            "selective — revealed {} of {} capabilities: [{}]",
            revealed.len(),
            total,
            revealed.join(", ")
        );
        (revealed, Some(s))
    } else {
        (Vec::new(), None)
    };

    // JSON mode: one structured object with the complete verdict. The text
    // path below reports via printer.info, which JSON mode suppresses — a
    // programmatic caller (the gateway) must never receive an empty success
    // envelope in place of a verdict.
    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "verdict": status,
            "ok": ok,
            "agent": agent,
            "card": card_id,
            "signature": sig_str,
            "key_bound": key_bound,
            "via_chain": via_chain,
            "staple": {
                "detail": staple_str,
                "verified": staple_ok,
                "age_secs": staple_age_secs,
                "stale": stale,
            },
            "challenge": challenge_str,
            "challenge_checked": challenge.is_some(),
            "challenge_ok": if challenge.is_some() { Some(challenge_ok) } else { None },
            "revocation": revocation_str,
            "revoked": revoked,
            "disclosed": disclosed,
            "revealed_capabilities": revealed_caps,
        }));
        if !ok {
            std::process::exit(1);
        }
        return Ok(());
    }

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
    if let Some(rs) = &reveal_str {
        printer.info(&format!("  reveals:     {rs}"));
    }
    printer.info(&format!("  staple:      {staple_str}"));
    if let Some(cs) = &challenge_str {
        printer.info(&format!("  challenge:   {cs}"));
    }
    printer.info(&format!("  revocation:  {revocation_str}"));
    printer.info(&format!("  status:      {status}"));
    printer.blank();
    if !live {
        printer.hint(
            "static verification proves the record, not the bearer. For proof the counterparty controls this key: they run present --challenge <your nonce>, you run verify-presentation --challenge <the same nonce>.",
        );
        printer.blank();
    }
    if !ok {
        return Err(format!("presentation did not verify — status: {status}").into());
    }
    Ok(())
}

/// Verify the staple offline: checkpoint signature against pinned
/// hub_checkpoint roots, then the card's inclusion in that signed root.
/// Returns (report line, verified, age in seconds when computable).

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
