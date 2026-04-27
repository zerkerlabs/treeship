//! CLI commands for inspecting and verifying .treeship packages.

use std::path::PathBuf;

use treeship_core::session::{read_package, verify_package, VerifyStatus};

use crate::printer::Printer;

// ---------------------------------------------------------------------------
// treeship package inspect <path>
// ---------------------------------------------------------------------------

pub fn inspect(
    path: PathBuf,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let receipt = read_package(&path)?;

    let session = &receipt.session;
    let p = &receipt.participants;
    let se = &receipt.side_effects;

    printer.blank();
    printer.section("session receipt");
    printer.info(&format!("  type:       {}", receipt.type_));
    printer.info(&format!("  id:         {}", session.id));
    if let Some(ref name) = session.name {
        printer.info(&format!("  name:       {}", name));
    }
    printer.info(&format!("  mode:       {:?}", session.mode));
    printer.info(&format!("  status:     {:?}", session.status));
    printer.info(&format!("  started:    {}", session.started_at));
    if let Some(ref ended) = session.ended_at {
        printer.info(&format!("  ended:      {}", ended));
    }
    if let Some(ms) = session.duration_ms {
        printer.info(&format!("  duration:   {}ms", ms));
    }

    printer.blank();
    printer.section("participants");
    printer.info(&format!("  agents:     {}", p.total_agents));
    printer.info(&format!("  spawned:    {}", p.spawned_subagents));
    printer.info(&format!("  handoffs:   {}", p.handoffs));
    printer.info(&format!("  max depth:  {}", p.max_depth));
    printer.info(&format!("  hosts:      {}", p.hosts));
    if let Some(ref root) = p.root_agent_instance_id {
        printer.info(&format!("  root agent: {}", root));
    }

    if !receipt.agent_graph.nodes.is_empty() {
        printer.blank();
        printer.section("agent graph");
        for node in &receipt.agent_graph.nodes {
            let role = node.agent_role.as_deref().unwrap_or("--");
            let status = node.status.as_deref().unwrap_or("active");
            printer.info(&format!(
                "  {} ({}) depth={} tools={} [{}] @{}",
                node.agent_name, role, node.depth, node.tool_calls, status, node.host_id,
            ));
        }
    }

    printer.blank();
    printer.section("side effects");
    let summary = se.summary();
    printer.info(&format!("  files read:     {}", summary.files_read));
    printer.info(&format!("  files written:  {}", summary.files_written));
    printer.info(&format!("  tool calls:     {}", summary.tool_invocations));
    printer.info(&format!("  processes:      {}", summary.processes));
    printer.info(&format!("  ports opened:   {}", summary.ports_opened));
    printer.info(&format!("  network conns:  {}", summary.network_connections));

    printer.blank();
    printer.section("timeline");
    printer.info(&format!("  events: {}", receipt.timeline.len()));
    for entry in receipt.timeline.iter().take(20) {
        let detail = entry.summary.as_deref().unwrap_or("");
        printer.dim_info(&format!(
            "  {} {} {} {}",
            &entry.timestamp[11..19.min(entry.timestamp.len())],
            entry.event_type,
            entry.agent_name,
            detail,
        ));
    }
    if receipt.timeline.len() > 20 {
        printer.dim_info(&format!("  ... and {} more", receipt.timeline.len() - 20));
    }

    printer.blank();
    printer.section("merkle");
    printer.info(&format!("  leaves:  {}", receipt.merkle.leaf_count));
    if let Some(ref root) = receipt.merkle.root {
        printer.info(&format!("  root:    {}", root));
    }
    printer.info(&format!("  proofs:  {}", receipt.merkle.inclusion_proofs.len()));

    printer.blank();
    printer.section("artifacts");
    printer.info(&format!("  count: {}", receipt.artifacts.len()));
    for art in receipt.artifacts.iter().take(10) {
        let digest = art.digest.as_deref().unwrap_or("--");
        printer.dim_info(&format!("  {} ({}) {}", art.artifact_id, art.payload_type, digest));
    }
    if receipt.artifacts.len() > 10 {
        printer.dim_info(&format!("  ... and {} more", receipt.artifacts.len() - 10));
    }

    // Surface event-log incompleteness when present (Codex finding #8).
    // The receipt is still cryptographically valid, but it represents
    // fewer events than were appended to the log because some lines
    // failed to parse during close. Make that visible without burying
    // it in the proofs subtree.
    if receipt.proofs.event_log_skipped > 0 {
        printer.blank();
        printer.warn(
            &format!(
                "event log incomplete: {} skipped",
                receipt.proofs.event_log_skipped,
            ),
            &[(
                "what",
                "events.jsonl had lines that failed to parse during close",
            ), (
                "impact",
                "the receipt does not represent the full event stream",
            ), (
                "next",
                "inspect close-time stderr or events.jsonl to investigate",
            )],
        );
    }

    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// treeship package verify <path>
// ---------------------------------------------------------------------------

pub fn verify(
    path: PathBuf,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let checks = verify_package(&path)?;

    let pass_count = checks.iter().filter(|c| c.status == VerifyStatus::Pass).count();
    let fail_count = checks.iter().filter(|c| c.status == VerifyStatus::Fail).count();
    let warn_count = checks.iter().filter(|c| c.status == VerifyStatus::Warn).count();

    printer.blank();
    printer.section("package verification");
    printer.info(&format!("  package: {}", path.display()));
    printer.blank();

    for check in &checks {
        let icon = match check.status {
            VerifyStatus::Pass => printer.green("PASS"),
            VerifyStatus::Fail => printer.red("FAIL"),
            VerifyStatus::Warn => printer.yellow("WARN"),
        };
        printer.info(&format!("  {} {} -- {}", icon, check.name, check.detail));
    }

    printer.blank();
    printer.info(&format!(
        "  {} passed, {} failed, {} warnings",
        pass_count, fail_count, warn_count,
    ));

    if fail_count > 0 {
        printer.blank();
        printer.warn("package verification failed", &[]);
    } else {
        printer.blank();
        printer.success("package verified", &[]);
    }

    printer.blank();

    Ok(())
}
