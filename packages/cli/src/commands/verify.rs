use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use treeship_core::{
    attestation::{Envelope, Verifier},
    statements::{ActionStatement, ApprovalStatement, HandoffStatement, ReceiptStatement, payload_type},
    storage::Store,
};

use crate::{ctx, printer::Printer};

/// Result of verifying one artifact.
struct ArtifactCheck {
    id:           String,
    payload_type: String,
    actor_or_sys: String,
    outcome:      Outcome,
    reason:       Option<String>,
}

#[derive(Debug, PartialEq)]
enum Outcome { Pass, Fail }

pub fn run(
    target:     &str,          // artifact ID or .treeship file path
    no_chain:   bool,
    max_depth:  usize,
    config:     Option<&str>,
    printer:    &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    // Build a Verifier from every known public key in the keystore.
    let verifier = build_verifier(&ctx.keys)?;

    // Resolve starting artifact.
    let _root_record = ctx.storage.read(target)
        .map_err(|_| format!("artifact not found locally: {target}\n  Run 'treeship dock pull {target}' to fetch from Hub"))?;

    let mut checks: Vec<ArtifactCheck> = Vec::new();
    let _current_id = Some(target.to_string());
    let mut depth = 0usize;

    // Walk the chain parent-first (deepest ancestor → leaf).
    // We collect IDs first then verify in order root→leaf.
    let mut chain_ids: Vec<String> = Vec::new();

    // Traverse to root.
    if !no_chain {
        let mut walk_id = Some(target.to_string());
        while let Some(id) = walk_id {
            chain_ids.push(id.clone());
            if depth >= max_depth { break; }
            let rec = ctx.storage.read(&id);
            walk_id = rec.ok().and_then(|r| r.parent_id.clone());
            depth += 1;
        }
        chain_ids.reverse(); // root first
    } else {
        chain_ids.push(target.to_string());
    }

    // Verify each artifact in chain order.
    // Collect all envelopes so we can do cross-artifact checks (nonce binding).
    let mut chain_envelopes: Vec<(String, Envelope)> = Vec::new();

    for id in &chain_ids {
        let rec = match ctx.storage.read(id) {
            Ok(r)  => r,
            Err(_) => {
                checks.push(ArtifactCheck {
                    id: id.clone(),
                    payload_type: "unknown".into(),
                    actor_or_sys: "—".into(),
                    outcome: Outcome::Fail,
                    reason:  Some(format!("not found in local storage")),
                });
                continue;
            }
        };

        let check = verify_one(&verifier, &rec.envelope, id);
        chain_envelopes.push((id.clone(), rec.envelope));
        checks.push(check);
    }

    // Nonce binding: for each action with approval_nonce, find the matching
    // approval and verify the binding is valid.
    let nonce_checks = verify_nonce_bindings(&chain_envelopes, &ctx.storage);
    checks.extend(nonce_checks);

    // Print results.
    let total  = checks.len();
    let passed = checks.iter().filter(|c| c.outcome == Outcome::Pass).count();
    let failed = total - passed;

    if printer.format == crate::printer::Format::Json {
        let out: Vec<_> = checks.iter().map(|c| serde_json::json!({
            "id":      c.id,
            "outcome": if c.outcome == Outcome::Pass { "pass" } else { "fail" },
            "reason":  c.reason,
        })).collect();
        printer.json(&serde_json::json!({
            "outcome": if failed == 0 { "pass" } else { "fail" },
            "total": total, "passed": passed, "failed": failed,
            "checks": out,
        }));
        if failed > 0 { std::process::exit(1); }
        return Ok(());
    }

    if failed == 0 {
        printer.success("verified", &[
            ("outcome", "pass"),
            ("chain",   &format!("{total} artifact{}", if total == 1 { "" } else { "s" })),
        ]);
    } else {
        printer.failure("verification failed", &[
            ("outcome", "fail"),
            ("passed",  &passed.to_string()),
            ("failed",  &failed.to_string()),
        ]);
    }

    // Per-artifact detail.
    for c in &checks {
        let icon = if c.outcome == Outcome::Pass { "  ✓" } else { "  ✗" };
        let short_type = c.payload_type
            .strip_prefix("application/vnd.treeship.")
            .and_then(|s| s.strip_suffix(".v1+json"))
            .unwrap_or(&c.payload_type);
        let line = format!("{icon}  {}  {short_type}  {}", &c.id[..16.min(c.id.len())], c.actor_or_sys);
        if c.outcome == Outcome::Pass {
            printer.info(&line);
        } else {
            let reason = c.reason.as_deref().unwrap_or("unknown");
            printer.info(&format!("{line}\n       reason: {reason}"));
        }
    }

    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn verify_one(verifier: &Verifier, envelope: &Envelope, id: &str) -> ArtifactCheck {
    let actor_or_sys = extract_actor(envelope);
    let pt = envelope.payload_type.clone();

    match verifier.verify(envelope) {
        Ok(result) => {
            // Content-addressed ID check: the ID re-derived from the envelope
            // during verification must match the ID we stored it under.
            if result.artifact_id != id {
                ArtifactCheck {
                    id: id.to_string(),
                    payload_type: pt,
                    actor_or_sys,
                    outcome: Outcome::Fail,
                    reason: Some(format!(
                        "ID mismatch: stored as {} but envelope re-derives {}",
                        id, result.artifact_id
                    )),
                }
            } else {
                ArtifactCheck {
                    id: id.to_string(),
                    payload_type: pt,
                    actor_or_sys,
                    outcome: Outcome::Pass,
                    reason: None,
                }
            }
        }
        Err(e) => ArtifactCheck {
            id: id.to_string(),
            payload_type: pt,
            actor_or_sys,
            outcome: Outcome::Fail,
            reason: Some(e.to_string()),
        },
    }
}

/// Verify nonce bindings between actions and approvals.
///
/// For each ActionStatement with an `approval_nonce`, find the matching
/// ApprovalStatement (in the chain or in storage) and check:
/// 1. Nonce match: action.approval_nonce == approval.nonce
/// 2. Approval not expired
/// 3. Scope constraints (allowed_actions) are respected
fn verify_nonce_bindings(
    chain: &[(String, Envelope)],
    storage: &Store,
) -> Vec<ArtifactCheck> {
    let mut checks = Vec::new();

    // Index approvals from the chain by nonce for O(1) lookup.
    let mut approvals_by_nonce: HashMap<String, ApprovalStatement> = HashMap::new();
    for (_id, env) in chain {
        if env.payload_type == payload_type("approval") {
            if let Ok(approval) = env.unmarshal_statement::<ApprovalStatement>() {
                approvals_by_nonce.insert(approval.nonce.clone(), approval);
            }
        }
    }

    for (id, env) in chain {
        if env.payload_type != payload_type("action") {
            continue;
        }
        let action = match env.unmarshal_statement::<ActionStatement>() {
            Ok(a)  => a,
            Err(_) => continue,
        };
        let nonce = match &action.approval_nonce {
            Some(n) => n.clone(),
            None    => continue, // no approval binding claimed
        };

        // Look up the approval: first in chain, then in storage.
        let approval = if let Some(a) = approvals_by_nonce.get(&nonce) {
            a.clone()
        } else {
            // Search storage for approvals with this nonce.
            match find_approval_by_nonce(&nonce, storage) {
                Some(a) => a,
                None => {
                    checks.push(ArtifactCheck {
                        id:           id.clone(),
                        payload_type: env.payload_type.clone(),
                        actor_or_sys: action.actor.clone(),
                        outcome:      Outcome::Fail,
                        reason:       Some(format!(
                            "approval_nonce '{}' set but no matching approval found",
                            &nonce[..16.min(nonce.len())]
                        )),
                    });
                    continue;
                }
            }
        };

        // Check expiry.
        if let Some(ref expires) = approval.expires_at {
            let now = now_rfc3339();
            if *expires < now {
                checks.push(ArtifactCheck {
                    id:           id.clone(),
                    payload_type: env.payload_type.clone(),
                    actor_or_sys: action.actor.clone(),
                    outcome:      Outcome::Fail,
                    reason:       Some(format!(
                        "approval expired at {} (now: {})", expires, now
                    )),
                });
                continue;
            }
        }

        // Check scope: if the approval restricts allowed_actions, the
        // action label must be in the list.
        if let Some(ref scope) = approval.scope {
            if !scope.allowed_actions.is_empty()
                && !scope.allowed_actions.contains(&action.action)
            {
                checks.push(ArtifactCheck {
                    id:           id.clone(),
                    payload_type: env.payload_type.clone(),
                    actor_or_sys: action.actor.clone(),
                    outcome:      Outcome::Fail,
                    reason:       Some(format!(
                        "action '{}' not in approval's allowed_actions: {:?}",
                        action.action, scope.allowed_actions
                    )),
                });
                continue;
            }
        }

        // Nonce binding valid.
        checks.push(ArtifactCheck {
            id:           id.clone(),
            payload_type: "nonce-binding".into(),
            actor_or_sys: action.actor.clone(),
            outcome:      Outcome::Pass,
            reason:       None,
        });
    }

    checks
}

/// Search storage for an approval whose nonce matches.
fn find_approval_by_nonce(nonce: &str, storage: &Store) -> Option<ApprovalStatement> {
    let approval_type = payload_type("approval");
    for entry in storage.list_by_type(&approval_type) {
        if let Ok(rec) = storage.read(&entry.id) {
            if let Ok(approval) = rec.envelope.unmarshal_statement::<ApprovalStatement>() {
                if approval.nonce == nonce {
                    return Some(approval);
                }
            }
        }
    }
    None
}

/// Minimal RFC 3339 "now" for expiry comparison.
fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    treeship_core::statements::unix_to_rfc3339(secs)
}

/// Extract a human-readable actor/system from the envelope payload.
fn extract_actor(envelope: &Envelope) -> String {
    // Try each statement type in turn — first one that parses wins.
    if let Ok(s) = envelope.unmarshal_statement::<ActionStatement>() {
        return s.actor;
    }
    if let Ok(s) = envelope.unmarshal_statement::<ApprovalStatement>() {
        return s.approver;
    }
    if let Ok(s) = envelope.unmarshal_statement::<HandoffStatement>() {
        return format!("{} → {}", s.from, s.to);
    }
    if let Ok(s) = envelope.unmarshal_statement::<ReceiptStatement>() {
        return s.system;
    }
    "—".into()
}

/// Build a Verifier populated with all public keys from the keystore.
fn build_verifier(keys: &treeship_core::keys::Store) -> Result<Verifier, Box<dyn std::error::Error>> {
    let key_list = keys.list()?;
    let mut map: HashMap<String, VerifyingKey> = HashMap::new();

    for info in key_list {
        if info.algorithm == "ed25519" && info.public_key.len() == 32 {
            let bytes: [u8; 32] = info.public_key.try_into().unwrap();
            if let Ok(vk) = VerifyingKey::from_bytes(&bytes) {
                map.insert(info.id, vk);
            }
        }
    }

    Ok(Verifier::new(map))
}
