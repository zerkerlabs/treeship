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

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::commands::resolve::{chain_verify_card, verifier_from_trust};
use crate::{ctx, printer::Printer};
use treeship_core::attestation::Envelope;
use treeship_core::merkle::{Checkpoint, InclusionProof, MerkleTree};
use treeship_core::statements::{parse_rfc3339_to_unix, payload_type, ReceiptStatement};
use treeship_core::trust::{decode_ed25519_pubkey, TrustRootKind, TrustRootStore};

type CmdResult = Result<(), Box<dyn std::error::Error>>;

pub const PRESENTATION_TYPE: &str = "treeship/presentation/v1";

/// The canonical bytes a challenge response signs (slice 3, the handshake).
///
/// Domain-separated and pipe-delimited in the v0.10.4 house shape: every
/// variable-length, externally-supplied field is folded into a sha256 digest
/// so no field can inject separators and shift the others (the verifier's
/// nonce is arbitrary text). Binding all four fields means a challenge
/// signature cannot be replayed across protocols (domain tag), across agents
/// or cards (their digests), or across challenges (the nonce digest);
/// `signed_at` is bound so the reported freshness is bearer-signed, not
/// bearer-editable.
pub(crate) fn challenge_canonical(
    agent: &str,
    card_id: &str,
    nonce: &str,
    signed_at: &str,
) -> Vec<u8> {
    let d = |s: &str| hex::encode(Sha256::digest(s.as_bytes()));
    format!(
        "v1|presentation-challenge|{}|{}|{}|{signed_at}",
        d(agent),
        d(card_id),
        d(nonce)
    )
    .into_bytes()
}

/// Verify a presentation's challenge block against the nonce THIS verifier
/// issued and the subject key the card verification established. Returns the
/// bearer-signed `signed_at` on success; a specific, honest reason on
/// failure. Pure — unit-tested against real keys.
pub(crate) fn check_challenge(
    challenge: &serde_json::Value,
    agent: &str,
    card_id: &str,
    expected_nonce: &str,
    card_keyid: &str,
    subject: &VerifyingKey,
) -> Result<String, String> {
    let nonce = challenge
        .get("nonce")
        .and_then(|v| v.as_str())
        .ok_or("challenge block carries no nonce")?;
    if nonce != expected_nonce {
        return Err(
            "challenge nonce does not match the one you issued — this response answers a DIFFERENT challenge (replay?)"
                .into(),
        );
    }
    let key_id = challenge
        .get("key_id")
        .and_then(|v| v.as_str())
        .ok_or("challenge block carries no key_id")?;
    if key_id != card_keyid {
        return Err(format!(
            "challenge signed by {key_id}, but the card is bound to {card_keyid}"
        ));
    }
    let signed_at = challenge
        .get("signed_at")
        .and_then(|v| v.as_str())
        .ok_or("challenge block carries no signed_at")?;
    let sig_b64 = challenge
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or("challenge block carries no signature")?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| "challenge signature is not valid base64url")?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "challenge signature is not 64 bytes")?;
    let canonical = challenge_canonical(agent, card_id, expected_nonce, signed_at);
    subject
        .verify_strict(&canonical, &Signature::from_bytes(&sig_arr))
        .map_err(|_| "challenge signature INVALID for the card's key".to_string())?;
    Ok(signed_at.to_string())
}

// ── present ─────────────────────────────────────────────────────────────────

pub fn present(
    agent: &str,
    out: Option<&str>,
    challenge: Option<&str>,
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
        "staple": {
            "checkpoint": checkpoint,
            "inclusion_proof": inclusion_proof,
        },
        "challenge": challenge_block,
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
    // The subject key the verification establishes — the ONLY key a
    // challenge response may be checked against. From the chain verdict, or
    // (direct-pin path) decoded from the verifier's own AgentCert root.
    let mut subject_vk: Option<VerifyingKey> = None;
    if !key_bound {
        if let Some(verdict) =
            chain_verify_card(&env, card_keyid, agent, &served_certs, &trust, &now_rfc)
        {
            sig_ok = true;
            key_bound = true;
            via_chain = true;
            subject_vk = Some(verdict.subject_key);
            verifier.add_key(signer.clone(), verdict.subject_key);
        }
    } else {
        subject_vk = trust
            .roots()
            .iter()
            .find(|r| r.key_id == card_keyid && r.kind == TrustRootKind::AgentCert)
            .and_then(|r| decode_ed25519_pubkey(&r.public_key).ok());
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

    // ── Challenge: the handshake — live key control, or nothing ───────────
    // Checked ONLY against the subject key that card verification itself
    // established (chain verdict or the verifier's own AgentCert pin). If
    // the card did not verify key-bound, there is no key to check against
    // and the challenge fails closed — a signature from an unverified key
    // proves nothing worth reporting as success.
    let mut challenge_str: Option<String> = None;
    let mut challenge_ok = true; // vacuously true when the verifier asked for none
    if let Some(nonce) = challenge {
        challenge_ok = false;
        let verdict = match (pres.get("challenge").filter(|v| !v.is_null()), &subject_vk) {
            (None, _) => "no challenge response in this presentation — ask the bearer to re-present with --challenge <your nonce>".to_string(),
            (_, None) => "cannot check: the card did not verify key-bound, so there is no established key to check the response against".to_string(),
            (Some(block), Some(vk)) => {
                match check_challenge(block, agent, card_id, nonce, card_keyid, vk) {
                    Ok(signed_at) => {
                        challenge_ok = true;
                        let age = parse_rfc3339_to_unix(&signed_at)
                            .map(|t| human_secs(unix_now().saturating_sub(t)))
                            .unwrap_or_else(|| "unknown age".into());
                        format!("verified — bearer controls {card_keyid} (response {age})")
                    }
                    Err(reason) => reason,
                }
            }
        };
        challenge_str = Some(verdict);
    } else if pres.get("challenge").filter(|v| !v.is_null()).is_some() {
        challenge_str = Some(
            "response present but NOT checked — pass --challenge <the nonce you issued> to verify liveness"
                .to_string(),
        );
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

    #[test]
    fn challenge_canonical_resists_separator_injection() {
        // A nonce containing pipes and field-lookalikes must not collide
        // with a differently-split canonical — every variable field is
        // digest-folded.
        let a = challenge_canonical("agent://a", "art_1", "n|art_2|x", "2026-07-06T12:00:00Z");
        let b = challenge_canonical("agent://a", "art_1|n", "art_2|x", "2026-07-06T12:00:00Z");
        assert_ne!(a, b);
        // And it is deterministic.
        assert_eq!(
            challenge_canonical("agent://a", "art_1", "n", "2026-07-06T12:00:00Z"),
            challenge_canonical("agent://a", "art_1", "n", "2026-07-06T12:00:00Z"),
        );
    }

    fn signed_challenge_block(
        signer: &treeship_core::attestation::Ed25519Signer,
        agent: &str,
        card_id: &str,
        nonce: &str,
    ) -> serde_json::Value {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use treeship_core::attestation::Signer;
        let signed_at = "2026-07-06T12:00:00Z";
        let sig = signer
            .sign(&challenge_canonical(agent, card_id, nonce, signed_at))
            .unwrap();
        serde_json::json!({
            "nonce": nonce,
            "key_id": signer.key_id(),
            "signed_at": signed_at,
            "signature": URL_SAFE_NO_PAD.encode(sig),
        })
    }

    fn vk_of(signer: &treeship_core::attestation::Ed25519Signer) -> VerifyingKey {
        use treeship_core::attestation::Signer;
        VerifyingKey::from_bytes(&signer.public_key_bytes().try_into().unwrap()).unwrap()
    }

    #[test]
    fn challenge_verifies_and_rejects_all_substitutions() {
        use treeship_core::attestation::Ed25519Signer;
        let agent_key = Ed25519Signer::generate("key_agent").unwrap();
        let other_key = Ed25519Signer::generate("key_other").unwrap();
        let vk = vk_of(&agent_key);

        // Happy path.
        let block = signed_challenge_block(&agent_key, "agent://a", "art_card", "nonce-1");
        assert!(check_challenge(&block, "agent://a", "art_card", "nonce-1", "key_agent", &vk).is_ok());

        // Wrong nonce: a captured response must not answer a new challenge.
        assert!(check_challenge(&block, "agent://a", "art_card", "nonce-2", "key_agent", &vk)
            .unwrap_err()
            .contains("DIFFERENT challenge"));

        // Signed by a different key than the card's.
        let forged = signed_challenge_block(&other_key, "agent://a", "art_card", "nonce-1");
        assert!(
            check_challenge(&forged, "agent://a", "art_card", "nonce-1", "key_agent", &vk)
                .is_err(),
            "response signed by a non-card key must reject"
        );

        // Replayed for a DIFFERENT card of the same agent: canonical binds card_id.
        assert!(
            check_challenge(&block, "agent://a", "art_other_card", "nonce-1", "key_agent", &vk)
                .unwrap_err()
                .contains("INVALID"),
            "challenge for one card must not vouch for another"
        );

        // Replayed for a DIFFERENT agent: canonical binds the agent URI.
        assert!(
            check_challenge(&block, "agent://b", "art_card", "nonce-1", "key_agent", &vk)
                .unwrap_err()
                .contains("INVALID")
        );

        // Tampered signed_at: freshness is bearer-signed, not bearer-editable.
        let mut aged = block.clone();
        aged["signed_at"] = serde_json::json!("2020-01-01T00:00:00Z");
        assert!(
            check_challenge(&aged, "agent://a", "art_card", "nonce-1", "key_agent", &vk)
                .unwrap_err()
                .contains("INVALID")
        );
    }
}
