use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use treeship_core::{
    attestation::{Envelope, Verifier},
    statements::{ActionStatement, ApprovalStatement, ApprovalScope, DecisionStatement, HandoffStatement, ReceiptStatement, payload_type},
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
    // Decision info
    decision_model:      Option<String>,
    decision_tokens_in:  Option<u64>,
    decision_tokens_out: Option<u64>,
    decision_summary:    Option<String>,
    decision_confidence: Option<f64>,
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

    // Resolve "last" keyword to the most recent artifact ID.
    let resolved_target = if target == "last" {
        let last_path = std::path::Path::new(&ctx.config.storage_dir).join(".last");
        std::fs::read_to_string(&last_path)
            .map_err(|_| "no recent artifact found -- run 'treeship wrap' first")?
            .trim()
            .to_string()
    } else {
        target.to_string()
    };
    let target = resolved_target.as_str();

    // Build a Verifier from every known public key in the keystore.
    let verifier = build_verifier(&ctx.keys)?;

    // Resolve starting artifact.
    let _root_record = ctx.storage.read(target)
        .map_err(|_| format!("artifact not found locally: {target}\n  Run 'treeship hub pull {target}' to fetch from Hub"))?;

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
    let nonce_checks = verify_nonce_bindings(&chain_envelopes, &ctx.storage, &ctx.config_path);
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
            } else if let Ok(decision) = env.unmarshal_statement::<DecisionStatement>() {
                fields.push(("actor", decision.actor.clone()));
                if let Some(ref model) = decision.model {
                    fields.push(("model", model.clone()));
                }
                fields.push(("time", decision.timestamp.clone()));
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

    // Approval binding + scope + replay reporting.
    //
    // Three independent properties must be reported separately so the
    // audit reader knows exactly what was checked:
    //   1. Binding   -- did the action's nonce match a real approval?
    //   2. Scope     -- did actor/action/subject fall inside the
    //                   approval's signed allow-lists? An unscoped
    //                   approval cannot answer this and the line says so.
    //   3. Replay    -- was the nonce consumed before? Only checkable
    //                   for the artifacts inside this package; a global
    //                   replay ledger does not exist yet, and verify
    //                   must NOT claim "single-use enforced" without one.
    let approval_checks: Vec<&ArtifactCheck> = checks.iter()
        .filter(|c| c.payload_type.starts_with("nonce-binding"))
        .collect();
    if !approval_checks.is_empty() {
        let any_fail = approval_checks.iter().any(|c| c.outcome == Outcome::Fail);
        let any_unscoped = approval_checks.iter().any(|c| c.payload_type == "nonce-binding-unscoped");
        let any_scoped   = approval_checks.iter().any(|c| c.payload_type == "nonce-binding-scoped");

        // Line 1: cryptographic binding (always emitted).
        let bind_status = if any_fail {
            printer.red("\u{2717}  approval binding nonce verification failed")
        } else {
            printer.green("\u{2713}  approval binding nonce matched a signed approval")
        };
        printer.info(&format!("  {bind_status}"));

        // Line 2: scope evaluation. Only when a scoped approval was in
        // the chain. Unscoped approvals get the warning instead.
        if any_scoped && !any_fail {
            printer.info(&format!(
                "  {}",
                printer.green("\u{2713}  approval scope   actor / action / subject matched approval scope")
            ));
        }
        if any_unscoped {
            printer.info(&format!(
                "  {}",
                printer.yellow("\u{26A0}  approval scope   approval is unscoped -- proves binding only, not actor/action/subject authorization")
            ));
        }

        // Line 3: replay posture. PR 3 upgraded this from
        // "package-local only" to a stronger reading when the local
        // Approval Use Journal had something to say. The printer
        // shows the strongest level it actually achieved -- never
        // overclaims, never silently downgrades.
        let journal_check = checks.iter().find(|c| c.payload_type == "replay-local-journal");
        match journal_check {
            Some(c) if c.outcome == Outcome::Pass => {
                let detail = c.reason.clone().unwrap_or_else(|| {
                    "local Approval Use Journal passed".into()
                });
                printer.info(&format!(
                    "  {}  {}",
                    printer.green("\u{2713}  replay check"),
                    detail,
                ));
            }
            Some(c) /* fail */ => {
                let detail = c.reason.clone().unwrap_or_else(|| {
                    "local Approval Use Journal: max_uses exceeded".into()
                });
                printer.info(&format!(
                    "  {}  {}",
                    printer.red("\u{2717}  replay check"),
                    detail,
                ));
            }
            None => {
                printer.info(&format!(
                    "  {}",
                    printer.yellow("\u{26A0}  replay check     package-local only -- no global ledger consulted")
                ));
            }
        }
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
    let actor_action = if step.payload_type.contains("decision") {
        format!("{} . decision", step.actor)
    } else if step.payload_type.contains("approval") {
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

    // Decision info (model, tokens, summary, confidence)
    if step.decision_model.is_some() || step.decision_tokens_in.is_some() {
        let model_str = step.decision_model.as_deref().unwrap_or("--");
        let tokens_str = match (step.decision_tokens_in, step.decision_tokens_out) {
            (Some(ti), Some(to)) => format!("  .  {} -> {} tokens", format_num(ti), format_num(to)),
            (Some(ti), None) => format!("  .  {} tokens in", format_num(ti)),
            (None, Some(to)) => format!("  .  {} tokens out", format_num(to)),
            (None, None) => String::new(),
        };
        print_box_line(&format!("model: {}{}", model_str, tokens_str), printer);
    }
    if let Some(ref summary) = step.decision_summary {
        let truncated = if summary.len() > 44 {
            format!("\"{}...\"", &summary[..41])
        } else {
            format!("\"{}\"", summary)
        };
        print_box_line(&truncated, printer);
    }
    if let Some(conf) = step.decision_confidence {
        print_box_line(&format!("confidence: {}%", (conf * 100.0) as u32), printer);
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
        decision_model: None,
        decision_tokens_in: None,
        decision_tokens_out: None,
        decision_summary: None,
        decision_confidence: None,
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

    // Try decision statement
    if let Ok(decision) = env.unmarshal_statement::<DecisionStatement>() {
        info.actor = decision.actor;
        info.action = "decision".into();
        info.timestamp = decision.timestamp;
        info.parent_id = decision.parent_id;
        info.decision_model = decision.model;
        info.decision_tokens_in = decision.tokens_in;
        info.decision_tokens_out = decision.tokens_out;
        info.decision_summary = decision.summary;
        info.decision_confidence = decision.confidence;
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

/// Format a number with comma separators (e.g. 8432 -> "8,432").
fn format_num(n: u64) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, &b) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            result.push(',');
        }
        result.push(b as char);
    }
    result
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

/// Verify nonce bindings AND scope constraints between actions and approvals.
///
/// For each ActionStatement with an `approval_nonce`:
///   1. Look up the matching ApprovalStatement (in chain or storage).
///   2. Check the approval is not expired.
///   3. If the approval has a scope, check the action's `actor`,
///      `action`, and `subject` are within the scope's allowed lists.
///   4. Stamp a result row with payload_type set to a scope-specific
///      tag so the summary block can report what was actually checked
///      versus what was absent (the `unscoped` case is reported as a
///      warning, not a failure -- the binding still holds).
///
/// What this does NOT check (and the summary block must say so):
///   - Replay / single-use enforcement. Stateless verification cannot
///     observe whether a nonce was already consumed by an artifact
///     outside the package being verified. `approval.scope.max_actions`
///     is signed into the grant for a future ledger-backed enforcer
///     but is not enforced here.
fn verify_nonce_bindings(
    chain: &[(String, Envelope)],
    storage: &Store,
    config_path: &std::path::Path,
) -> Vec<ArtifactCheck> {
    let mut checks = Vec::new();
    // Resolve the workspace's local Approval Use Journal once. Empty
    // when no journal exists; check_replay returns NotPerformed in
    // that case and the printer falls back to the v0.9.6
    // "package-local only" message.
    let journal_dir = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("journals")
        .join("approval-use");
    let journal = treeship_core::journal::Journal::new(&journal_dir);

    // Index approvals from the chain by nonce for O(1) lookup.
    let mut approvals_by_nonce: HashMap<String, ApprovalStatement> = HashMap::new();
    for (_id, env) in chain {
        if env.payload_type == payload_type("approval") {
            if let Ok(approval) = env.unmarshal_statement::<ApprovalStatement>() {
                approvals_by_nonce.insert(approval.nonce.clone(), approval);
            }
        }
    }

    // Track per-nonce consumption WITHIN THIS PACKAGE so the summary can
    // report a package-local replay finding even though no global
    // ledger exists yet. Multiple actions claiming the same nonce
    // inside one verified bundle are observable here and must not be
    // silently accepted as "single-use."
    let mut nonce_consumed_by: HashMap<String, String> = HashMap::new();

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
            match find_approval_by_nonce(&nonce, storage) {
                Some(a) => a,
                None => {
                    checks.push(ArtifactCheck {
                        id:           id.clone(),
                        payload_type: "nonce-binding".into(),
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

        // Check approval expiry.
        if let Some(ref expires) = approval.expires_at {
            let now = now_rfc3339();
            if *expires < now {
                checks.push(ArtifactCheck {
                    id:           id.clone(),
                    payload_type: "nonce-binding".into(),
                    actor_or_sys: action.actor.clone(),
                    outcome:      Outcome::Fail,
                    reason:       Some(format!(
                        "approval expired at {} (now: {})", expires, now
                    )),
                });
                continue;
            }
        }

        // Check scope: actor, action, subject, and scope-level expiry.
        // Default-empty (no scope at all, or all-empty scope) is a
        // bearer / unscoped grant -- the binding holds but no
        // authorization claims are made. We still pass the binding row
        // and let the summary emit the unscoped warning separately.
        let scope_tag = match &approval.scope {
            Some(scope) if !scope.is_unscoped() => {
                if let Some(reason) = check_scope_violation(scope, &action) {
                    checks.push(ArtifactCheck {
                        id:           id.clone(),
                        payload_type: "nonce-binding".into(),
                        actor_or_sys: action.actor.clone(),
                        outcome:      Outcome::Fail,
                        reason:       Some(reason),
                    });
                    continue;
                }
                "nonce-binding-scoped"
            }
            _ => "nonce-binding-unscoped",
        };

        // Package-local replay observation: same nonce, second action.
        // Not a global ledger; just what we can see in this bundle.
        if let Some(prev) = nonce_consumed_by.get(&nonce) {
            checks.push(ArtifactCheck {
                id:           id.clone(),
                payload_type: "nonce-binding".into(),
                actor_or_sys: action.actor.clone(),
                outcome:      Outcome::Fail,
                reason:       Some(format!(
                    "nonce already consumed by {} in this package (package-local replay)",
                    short_id(prev)
                )),
            });
            continue;
        }
        nonce_consumed_by.insert(nonce.clone(), id.clone());

        // Binding + scope (if any) valid.
        checks.push(ArtifactCheck {
            id:           id.clone(),
            payload_type: scope_tag.into(),
            actor_or_sys: action.actor.clone(),
            outcome:      Outcome::Pass,
            reason:       None,
        });

        // Local journal replay check (PR 3). Reports the strongest
        // level we can speak to. Resolve the grant_id by walking
        // storage one more time (same approach as the binding check
        // above; the cost is bounded by the small set of approvals).
        // Stamp a synthesized check the printer reads.
        if journal.exists() {
            // The grant_id is the artifact id of the approval whose
            // nonce matched. We don't have it in scope here, so
            // re-derive from storage (cheap; few approvals per
            // workspace and the lookup is by-type).
            let approval_type = payload_type("approval");
            let mut grant_id_opt: Option<String> = None;
            for entry in storage.list_by_type(&approval_type) {
                if let Ok(rec) = storage.read(&entry.id) {
                    if let Ok(a) = rec.envelope.unmarshal_statement::<ApprovalStatement>() {
                        if a.nonce == nonce {
                            grant_id_opt = Some(entry.id);
                            break;
                        }
                    }
                }
            }
            if let Some(grant_id) = grant_id_opt {
                let nonce_dig = treeship_core::statements::nonce_digest(&nonce);
                let max_uses = approval.scope.as_ref().and_then(|s| s.max_actions);
                // Verify-time question: "is the recorded use within
                // max_uses?" Distinct from consume-time's "would the
                // next use exceed?". find_use_for_action returns None
                // when there's no journal record for this action,
                // which simply means no journal-level evidence
                // exists -- the printer falls back to the warning.
                if let Ok(Some((_use_rec, replay))) = treeship_core::journal::find_use_for_action(
                    &journal, &grant_id, &nonce_dig, max_uses,
                ) {
                    let outcome = match replay.passed {
                        Some(false) => Outcome::Fail,
                        Some(true) | None => Outcome::Pass,
                    };
                    let detail = replay.details.clone().unwrap_or_default();
                    checks.push(ArtifactCheck {
                        id:           id.clone(),
                        payload_type: "replay-local-journal".into(),
                        actor_or_sys: action.actor.clone(),
                        outcome,
                        reason:       Some(detail),
                    });
                }
            }
        }
    }

    checks
}

/// Returns `Some(reason)` if the action violates the approval's scope,
/// `None` if every populated scope axis matches.
///
/// Empty `allowed_*` lists mean "no constraint on that axis." The order
/// of checks is actor → action → subject → scope-level expiry; the
/// first violation wins for a clear failure message.
pub(crate) fn check_scope_violation(scope: &ApprovalScope, action: &ActionStatement) -> Option<String> {
    if !scope.allowed_actors.is_empty()
        && !scope.allowed_actors.contains(&action.actor)
    {
        return Some(format!(
            "actor '{}' not in approval's allowed_actors: {:?}",
            action.actor, scope.allowed_actors
        ));
    }

    if !scope.allowed_actions.is_empty()
        && !scope.allowed_actions.contains(&action.action)
    {
        return Some(format!(
            "action '{}' not in approval's allowed_actions: {:?}",
            action.action, scope.allowed_actions
        ));
    }

    if !scope.allowed_subjects.is_empty() {
        // Match on whichever subject reference the action carries.
        // URI is the canonical form; artifact_id is a chain-internal
        // form. Either may appear in allowed_subjects.
        let observed = action.subject.uri.clone()
            .or_else(|| action.subject.artifact_id.clone())
            .or_else(|| action.subject.digest.clone());
        let matches = match observed.as_deref() {
            Some(s) => scope.allowed_subjects.iter().any(|allowed| allowed == s),
            None    => false,
        };
        if !matches {
            return Some(format!(
                "subject '{}' not in approval's allowed_subjects: {:?}",
                observed.as_deref().unwrap_or("<none>"),
                scope.allowed_subjects
            ));
        }
    }

    if let Some(ref valid_until) = scope.valid_until {
        let now = now_rfc3339();
        if *valid_until < now {
            return Some(format!(
                "approval scope expired at {} (now: {})", valid_until, now
            ));
        }
    }

    None
}

/// Search storage for an approval whose nonce matches.
pub(crate) fn find_approval_by_nonce(nonce: &str, storage: &Store) -> Option<ApprovalStatement> {
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
pub(crate) fn now_rfc3339() -> String {
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
    if let Ok(s) = envelope.unmarshal_statement::<DecisionStatement>() {
        return s.actor;
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

#[cfg(test)]
mod tests {
    use super::*;
    use treeship_core::statements::{ActionStatement, ApprovalScope, SubjectRef};

    fn act(actor: &str, action: &str, subject_uri: Option<&str>) -> ActionStatement {
        let mut a = ActionStatement::new(actor, action);
        if let Some(uri) = subject_uri {
            a.subject = SubjectRef { uri: Some(uri.into()), ..Default::default() };
        }
        a
    }

    // ── check_scope_violation: actor axis ──────────────────────────────
    #[test]
    fn scope_wrong_actor_fails() {
        let scope = ApprovalScope {
            allowed_actors: vec!["agent://deployer".into()],
            ..Default::default()
        };
        let action = act("agent://other", "deploy.production", None);
        let r = check_scope_violation(&scope, &action);
        assert!(r.is_some(), "wrong actor should violate scope");
        assert!(r.unwrap().contains("not in approval's allowed_actors"));
    }

    #[test]
    fn scope_right_actor_passes() {
        let scope = ApprovalScope {
            allowed_actors: vec!["agent://deployer".into()],
            ..Default::default()
        };
        let action = act("agent://deployer", "deploy.production", None);
        assert!(check_scope_violation(&scope, &action).is_none());
    }

    // ── check_scope_violation: action axis ─────────────────────────────
    #[test]
    fn scope_wrong_action_fails() {
        // The repro from the engineer's report: deploy.production approval
        // must NOT authorize deploy.staging.
        let scope = ApprovalScope {
            allowed_actions: vec!["deploy.production".into()],
            ..Default::default()
        };
        let action = act("agent://deployer", "deploy.staging", None);
        let r = check_scope_violation(&scope, &action);
        assert!(r.is_some());
        assert!(r.unwrap().contains("not in approval's allowed_actions"));
    }

    // ── check_scope_violation: subject axis ────────────────────────────
    #[test]
    fn scope_wrong_subject_uri_fails() {
        // env://production approval must NOT authorize env://staging
        // even with the right actor + action.
        let scope = ApprovalScope {
            allowed_subjects: vec!["env://production".into()],
            ..Default::default()
        };
        let action = act("agent://deployer", "deploy.production", Some("env://staging"));
        let r = check_scope_violation(&scope, &action);
        assert!(r.is_some());
        assert!(r.unwrap().contains("not in approval's allowed_subjects"));
    }

    #[test]
    fn scope_right_subject_uri_passes() {
        let scope = ApprovalScope {
            allowed_subjects: vec!["env://production".into()],
            ..Default::default()
        };
        let action = act("agent://deployer", "deploy.production", Some("env://production"));
        assert!(check_scope_violation(&scope, &action).is_none());
    }

    #[test]
    fn scope_subject_artifact_id_fallback() {
        // When the action's subject is a chain-internal artifact_id,
        // it should also be matchable against allowed_subjects.
        let scope = ApprovalScope {
            allowed_subjects: vec!["art_abc123".into()],
            ..Default::default()
        };
        let mut action = act("agent://x", "doit", None);
        action.subject = SubjectRef { artifact_id: Some("art_abc123".into()), ..Default::default() };
        assert!(check_scope_violation(&scope, &action).is_none());
    }

    #[test]
    fn scope_subject_required_but_action_has_none_fails() {
        let scope = ApprovalScope {
            allowed_subjects: vec!["env://production".into()],
            ..Default::default()
        };
        let action = act("agent://x", "doit", None); // no subject
        assert!(check_scope_violation(&scope, &action).is_some());
    }

    // ── check_scope_violation: combined axes ───────────────────────────
    #[test]
    fn scope_first_violation_wins_actor_then_action() {
        // Actor matches, action doesn't -- action error reported.
        let scope = ApprovalScope {
            allowed_actors:  vec!["agent://deployer".into()],
            allowed_actions: vec!["deploy.production".into()],
            ..Default::default()
        };
        let action = act("agent://deployer", "deploy.staging", None);
        let r = check_scope_violation(&scope, &action).unwrap();
        assert!(r.contains("allowed_actions"));
    }

    #[test]
    fn scope_first_violation_wins_actor_takes_priority() {
        // Both wrong; actor reported because it's checked first.
        let scope = ApprovalScope {
            allowed_actors:  vec!["agent://deployer".into()],
            allowed_actions: vec!["deploy.production".into()],
            ..Default::default()
        };
        let action = act("agent://other", "deploy.staging", None);
        let r = check_scope_violation(&scope, &action).unwrap();
        assert!(r.contains("allowed_actors"));
    }

    // ── ApprovalScope::is_unscoped ─────────────────────────────────────
    #[test]
    fn scope_default_is_unscoped() {
        let scope = ApprovalScope::default();
        assert!(scope.is_unscoped());
        // And produces no violations.
        let action = act("agent://anyone", "anything", Some("any://subject"));
        assert!(check_scope_violation(&scope, &action).is_none());
    }

    #[test]
    fn scope_with_max_uses_only_is_not_unscoped() {
        let scope = ApprovalScope { max_actions: Some(1), ..Default::default() };
        assert!(!scope.is_unscoped());
    }

    // ── scope_valid_until ──────────────────────────────────────────────
    #[test]
    fn scope_expired_fails() {
        let scope = ApprovalScope {
            valid_until: Some("2000-01-01T00:00:00Z".into()),
            ..Default::default()
        };
        let action = act("agent://x", "doit", None);
        let r = check_scope_violation(&scope, &action);
        assert!(r.is_some());
        assert!(r.unwrap().contains("scope expired"));
    }
}
