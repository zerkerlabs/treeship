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

/// Rich per-step data extracted from each artifact in the chain.
struct StepInfo {
    index:        usize,
    id:           String,
    actor:        String,
    action:       String,
    timestamp:    String,
    payload_type: String,
    // From meta.execution
    output_digest:  Option<String>,
    output_lines:   Option<u64>,
    exit_code:      Option<i64>,
    elapsed_ms:     Option<f64>,
    // From meta.state_changes
    files_changed:  Option<u64>,
    // Approval info
    approver:       Option<String>,
    approval_id:    Option<String>,
    description:    Option<String>,
    // Handoff info
    handoff_from:   Option<String>,
    handoff_to:     Option<String>,
    // Parent linkage
    parent_id:      Option<String>,
    // Approval nonce on action
    approval_nonce: Option<String>,
}

pub fn run(
    target:     &str,
    no_chain:   bool,
    max_depth:  usize,
    full:       bool,
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

    // Walk the chain parent-first (deepest ancestor -> leaf).
    // We collect IDs first then verify in order root->leaf.
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
                    actor_or_sys: "\u{2014}".into(),
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

    // --- Full chain timeline display ---
    if full {
        print_full_timeline(&chain_envelopes, &checks, &ctx.storage, printer, target);
        if failed > 0 { std::process::exit(1); }
        return Ok(());
    }

    // --- Improved short output ---
    let chain_count = chain_envelopes.len();
    if failed == 0 {
        let header = format!(
            "verified  ({} artifact{} . chain intact)",
            chain_count,
            if chain_count == 1 { "" } else { "s" }
        );
        printer.success(&header, &[]);

        // Show info about the target artifact.
        if let Some((_id, env)) = chain_envelopes.last() {
            let mut fields: Vec<(&str, String)> = Vec::new();
            fields.push(("target", short_id(target)));

            if let Ok(action) = env.unmarshal_statement::<ActionStatement>() {
                fields.push(("actor", action.actor.clone()));
                fields.push(("action", action.action.clone()));
                fields.push(("time", action.timestamp.clone()));
                // Check for approval
                if let Some(ref nonce) = action.approval_nonce {
                    if let Some(approval) = find_approval_by_nonce(nonce, &ctx.storage) {
                        fields.push(("approved", approval.approver.clone()));
                    }
                }
            } else if let Ok(approval) = env.unmarshal_statement::<ApprovalStatement>() {
                fields.push(("approver", approval.approver.clone()));
                fields.push(("time", approval.timestamp.clone()));
            } else if let Ok(handoff) = env.unmarshal_statement::<HandoffStatement>() {
                fields.push(("actor", format!("{} -> {}", handoff.from, handoff.to)));
                fields.push(("time", handoff.timestamp.clone()));
            } else if let Ok(receipt) = env.unmarshal_statement::<ReceiptStatement>() {
                fields.push(("system", receipt.system.clone()));
                fields.push(("time", receipt.timestamp.clone()));
            }

            // Print fields with alignment
            if !fields.is_empty() {
                let max_key = fields.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
                for (k, v) in &fields {
                    let pad = " ".repeat(max_key - k.len());
                    printer.info(&format!("  {k}:{pad}   {v}"));
                }
            }
        }

        printer.blank();
        printer.hint(&format!(
            "treeship verify {} --full  for chain timeline",
            &target[..16.min(target.len())]
        ));
    } else {
        printer.failure("verification failed", &[
            ("outcome", "fail"),
            ("passed",  &passed.to_string()),
            ("failed",  &failed.to_string()),
        ]);

        // Per-artifact detail.
        for c in &checks {
            let icon = if c.outcome == Outcome::Pass { "  \u{2713}" } else { "  \u{2717}" };
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
    }

    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

// =============================================================================
// Full timeline display
// =============================================================================

const BOX_WIDTH: usize = 58;

fn print_full_timeline(
    chain: &[(String, Envelope)],
    checks: &[ArtifactCheck],
    storage: &Store,
    printer: &Printer,
    target: &str,
) {
    let passed = checks.iter().filter(|c| c.outcome == Outcome::Pass).count();
    let failed = checks.len() - passed;

    // Build step info for each artifact in chain.
    let steps: Vec<StepInfo> = chain.iter().enumerate().map(|(i, (id, env))| {
        extract_step_info(i + 1, id, env, storage)
    }).collect();

    // Header
    if failed == 0 {
        printer.info(&printer.green(&format!(
            "\u{2713} chain verified  ({} artifact{} . all signatures valid)",
            chain.len(),
            if chain.len() == 1 { "" } else { "s" }
        )));
    } else {
        printer.info(&printer.red(&format!(
            "\u{2717} chain verification failed  ({} passed, {} failed)",
            passed, failed
        )));
    }
    printer.blank();

    // Print each step as a box-drawn card.
    for (i, step) in steps.iter().enumerate() {
        print_step_card(step, printer);

        // Connector between steps.
        if i + 1 < steps.len() {
            let next = &steps[i + 1];
            let connector = determine_connector(step, next, chain);
            printer.info(&format!("              {}", printer.dim(&connector)));
            printer.blank();
        }
    }

    printer.blank();

    // Verification summary.
    let sig_count = chain.len();
    let nonce_checks: Vec<&ArtifactCheck> = checks.iter()
        .filter(|c| c.payload_type == "nonce-binding")
        .collect();

    printer.info("  Verification summary");
    let rule = "\u{2500}".repeat(BOX_WIDTH);
    printer.info(&format!("  {rule}"));

    // Signatures
    let sig_status = if checks.iter().any(|c| c.outcome == Outcome::Fail && c.payload_type != "nonce-binding") {
        printer.red(&format!("\u{2717}  signatures      FAILED"))
    } else {
        printer.green(&format!("\u{2713}  signatures      all {} Ed25519 signatures valid", sig_count))
    };
    printer.info(&format!("  {sig_status}"));

    // Content IDs
    let id_fail = checks.iter().any(|c| {
        c.outcome == Outcome::Fail && c.reason.as_deref().map_or(false, |r| r.contains("ID mismatch"))
    });
    let id_status = if id_fail {
        printer.red("\u{2717}  content IDs     ID mismatch detected")
    } else {
        printer.green(&format!("\u{2713}  content IDs     all {} artifact IDs match content", sig_count))
    };
    printer.info(&format!("  {id_status}"));

    // Chain integrity
    let chain_ok = !checks.iter().any(|c| {
        c.outcome == Outcome::Fail && c.reason.as_deref().map_or(false, |r| r.contains("not found"))
    });
    let chain_status = if chain_ok {
        printer.green("\u{2713}  chain integrity no gaps, no tampering detected")
    } else {
        printer.red("\u{2717}  chain integrity gaps detected in chain")
    };
    printer.info(&format!("  {chain_status}"));

    // Nonce binding (only if there were nonce checks)
    if !nonce_checks.is_empty() {
        let nonce_ok = nonce_checks.iter().all(|c| c.outcome == Outcome::Pass);
        let nonce_status = if nonce_ok {
            printer.green("\u{2713}  nonce binding   approval nonce matched, single-use enforced")
        } else {
            printer.red("\u{2717}  nonce binding   nonce verification failed")
        };
        printer.info(&format!("  {nonce_status}"));
    }

    printer.info(&format!("  {rule}"));
    printer.info(&printer.dim(&format!("  treeship.dev/verify/{}", short_id(target))));
}

fn print_step_card(step: &StepInfo, printer: &Printer) {
    // Header: index + artifact ID
    let id_display = short_id(&step.id);
    let header_content = format!(" {} {}", step.index, id_display);
    // Pad to fill the box width
    let header_pad = if header_content.len() + 4 < BOX_WIDTH {
        "\u{2500}".repeat(BOX_WIDTH - header_content.len() - 4)
    } else {
        String::new()
    };
    printer.info(&format!(
        "  \u{250C}\u{2500}{} {}\u{2510}",
        header_content, header_pad
    ));

    // Actor + action line
    let actor_action = if step.payload_type.contains("approval") {
        format!(
            "{} . approval",
            step.actor
        )
    } else if step.payload_type.contains("handoff") {
        let from = step.handoff_from.as_deref().unwrap_or(&step.actor);
        let to = step.handoff_to.as_deref().unwrap_or("?");
        format!("{} -> {} . handoff", from, to)
    } else if step.payload_type.contains("receipt") {
        format!("{} . receipt", step.actor)
    } else {
        format!("{} . {}", step.actor, step.action)
    };
    print_box_line(&actor_action, printer);

    // Output line (if available)
    if step.output_digest.is_some() || step.output_lines.is_some() || step.exit_code.is_some() {
        let digest_str = step.output_digest.as_deref().unwrap_or("--");
        let digest_short = if digest_str.len() > 16 {
            &digest_str[..16]
        } else {
            digest_str
        };
        let lines_str = step.output_lines
            .map(|n| format!("{} lines", n))
            .unwrap_or_default();
        let exit_str = step.exit_code
            .map(|c| format!("exit {}", c))
            .unwrap_or_default();
        let parts: Vec<&str> = [lines_str.as_str(), exit_str.as_str()]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect();
        let suffix = if parts.is_empty() {
            String::new()
        } else {
            format!("  ({})", parts.join(", "))
        };
        print_box_line(&format!("output: {}{}", digest_short, suffix), printer);
    }

    // Files line
    if let Some(n) = step.files_changed {
        print_box_line(&format!("files:  {} modified", n), printer);
    }

    // Approval info (if this action references an approval)
    if let (Some(ref appr_id), Some(ref approver)) = (&step.approval_id, &step.approver) {
        print_box_line(
            &format!("approval: {} . {}", short_id(appr_id), approver),
            printer,
        );
    }

    // Description (for approval statements)
    if let Some(ref desc) = step.description {
        let truncated = if desc.len() > 44 {
            format!("{}...", &desc[..41])
        } else {
            desc.clone()
        };
        print_box_line(&format!("desc: {}", truncated), printer);
    }

    // Timestamp + elapsed
    let elapsed_str = step.elapsed_ms
        .map(|ms| {
            if ms < 1000.0 {
                format!("{:.0}ms", ms)
            } else {
                format!("{:.1}s", ms / 1000.0)
            }
        })
        .unwrap_or_default();
    let time_line = if elapsed_str.is_empty() {
        step.timestamp.clone()
    } else {
        format!("{} . {}", step.timestamp, elapsed_str)
    };
    print_box_line(&time_line, printer);

    // Bottom border
    let bottom = "\u{2500}".repeat(BOX_WIDTH - 2);
    printer.info(&format!("  \u{2514}{}\u{2518}", bottom));
}

fn print_box_line(content: &str, printer: &Printer) {
    // Left border + content + right border, padded to BOX_WIDTH
    let inner_width = BOX_WIDTH - 4; // account for "  | " and " |"
    let padded = if content.len() < inner_width {
        format!("{}{}", content, " ".repeat(inner_width - content.len()))
    } else {
        content[..inner_width].to_string()
    };
    printer.info(&format!("  \u{2502}  {} \u{2502}", padded));
}

fn determine_connector(current: &StepInfo, next: &StepInfo, _chain: &[(String, Envelope)]) -> String {
    // Check if next step references an approval
    if next.approval_nonce.is_some() {
        return "\u{2193} approval required".to_string();
    }

    // Check if next is a handoff
    if next.payload_type.contains("handoff") {
        let from = next.handoff_from.as_deref().unwrap_or("?");
        let to = next.handoff_to.as_deref().unwrap_or("?");
        return format!("\u{2193} handoff . {} -> {}", from, to);
    }

    // Check if current is an approval
    if current.payload_type.contains("approval") {
        return "\u{2193} approval granted".to_string();
    }

    // Check if next step's parent_id matches current step's id
    if next.parent_id.as_deref() == Some(&current.id) {
        return "\u{2193} chained".to_string();
    }

    // Default: chained (they are in the same chain after all)
    "\u{2193} chained".to_string()
}

fn extract_step_info(index: usize, id: &str, env: &Envelope, storage: &Store) -> StepInfo {
    let mut info = StepInfo {
        index,
        id: id.to_string(),
        actor: "\u{2014}".into(),
        action: "\u{2014}".into(),
        timestamp: String::new(),
        payload_type: env.payload_type.clone(),
        output_digest: None,
        output_lines: None,
        exit_code: None,
        elapsed_ms: None,
        files_changed: None,
        approver: None,
        approval_id: None,
        description: None,
        handoff_from: None,
        handoff_to: None,
        parent_id: None,
        approval_nonce: None,
    };

    // Try action statement
    if let Ok(action) = env.unmarshal_statement::<ActionStatement>() {
        info.actor = action.actor;
        info.action = action.action;
        info.timestamp = action.timestamp;
        info.parent_id = action.parent_id;
        info.approval_nonce = action.approval_nonce.clone();

        // If there's an approval nonce, look up the approval for display
        if let Some(ref nonce) = action.approval_nonce {
            if let Some(approval) = find_approval_by_nonce(nonce, storage) {
                info.approver = Some(approval.approver);
                // Try to find the approval artifact ID
                let approval_type = payload_type("approval");
                for entry in storage.list_by_type(&approval_type) {
                    if let Ok(rec) = storage.read(&entry.id) {
                        if let Ok(a) = rec.envelope.unmarshal_statement::<ApprovalStatement>() {
                            if a.nonce == *nonce {
                                info.approval_id = Some(entry.id.clone());
                                break;
                            }
                        }
                    }
                }
            }
        }

        // Extract meta fields
        if let Some(ref meta) = action.meta {
            extract_meta_fields(&mut info, meta);
        }
        return info;
    }

    // Try approval statement
    if let Ok(approval) = env.unmarshal_statement::<ApprovalStatement>() {
        info.actor = approval.approver;
        info.action = "approval".into();
        info.timestamp = approval.timestamp;
        info.description = approval.description;
        return info;
    }

    // Try handoff statement
    if let Ok(handoff) = env.unmarshal_statement::<HandoffStatement>() {
        info.actor = format!("{} -> {}", handoff.from, handoff.to);
        info.action = "handoff".into();
        info.timestamp = handoff.timestamp;
        info.handoff_from = Some(handoff.from);
        info.handoff_to = Some(handoff.to);
        return info;
    }

    // Try receipt statement
    if let Ok(receipt) = env.unmarshal_statement::<ReceiptStatement>() {
        info.actor = receipt.system;
        info.action = receipt.kind;
        info.timestamp = receipt.timestamp;
        return info;
    }

    info
}

fn extract_meta_fields(info: &mut StepInfo, meta: &serde_json::Value) {
    // Sprint 1 nested structure: meta.execution.* and meta.state_changes.*
    if let Some(exec) = meta.get("execution") {
        if let Some(v) = exec.get("output_digest").and_then(|v| v.as_str()) {
            info.output_digest = Some(v.to_string());
        }
        if let Some(v) = exec.get("output_lines").and_then(|v| v.as_u64()) {
            info.output_lines = Some(v);
        }
        if let Some(v) = exec.get("exit_code").and_then(|v| v.as_i64()) {
            info.exit_code = Some(v);
        }
        if let Some(v) = exec.get("elapsed_ms").and_then(|v| v.as_f64()) {
            info.elapsed_ms = Some(v);
        }
    }

    if let Some(state) = meta.get("state_changes") {
        if let Some(files) = state.get("files_modified").and_then(|v| v.as_array()) {
            info.files_changed = Some(files.len() as u64);
        }
        // Also accept files_changed as a direct count
        if info.files_changed.is_none() {
            if let Some(v) = state.get("files_changed").and_then(|v| v.as_u64()) {
                info.files_changed = Some(v);
            }
        }
    }

    // Flat structure fallback (from the user's spec)
    if info.output_digest.is_none() {
        if let Some(v) = meta.get("output_digest").and_then(|v| v.as_str()) {
            info.output_digest = Some(v.to_string());
        }
    }
    if info.output_lines.is_none() {
        if let Some(v) = meta.get("output_lines").and_then(|v| v.as_u64()) {
            info.output_lines = Some(v);
        }
    }
    if info.exit_code.is_none() {
        if let Some(v) = meta.get("exitCode").and_then(|v| v.as_i64()) {
            info.exit_code = Some(v);
        }
        if info.exit_code.is_none() {
            if let Some(v) = meta.get("exit_code").and_then(|v| v.as_i64()) {
                info.exit_code = Some(v);
            }
        }
    }
    if info.elapsed_ms.is_none() {
        if let Some(v) = meta.get("elapsedMs").and_then(|v| v.as_f64()) {
            info.elapsed_ms = Some(v);
        }
        if info.elapsed_ms.is_none() {
            if let Some(v) = meta.get("elapsed_ms").and_then(|v| v.as_f64()) {
                info.elapsed_ms = Some(v);
            }
        }
    }
    if info.files_changed.is_none() {
        if let Some(v) = meta.get("files_changed").and_then(|v| v.as_u64()) {
            info.files_changed = Some(v);
        }
        if info.files_changed.is_none() {
            if let Some(files) = meta.get("files_modified").and_then(|v| v.as_array()) {
                info.files_changed = Some(files.len() as u64);
            }
        }
    }
}

fn short_id(id: &str) -> String {
    if id.len() > 20 {
        id[..20].to_string()
    } else {
        id.to_string()
    }
}

// =============================================================================
// Verification logic (unchanged)
// =============================================================================

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
    // Try each statement type in turn -- first one that parses wins.
    if let Ok(s) = envelope.unmarshal_statement::<ActionStatement>() {
        return s.actor;
    }
    if let Ok(s) = envelope.unmarshal_statement::<ApprovalStatement>() {
        return s.approver;
    }
    if let Ok(s) = envelope.unmarshal_statement::<HandoffStatement>() {
        return format!("{} -> {}", s.from, s.to);
    }
    if let Ok(s) = envelope.unmarshal_statement::<ReceiptStatement>() {
        return s.system;
    }
    "\u{2014}".into()
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
