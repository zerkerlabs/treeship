//! `treeship agents` -- inspect and manage the local Agent Card store.
//!
//! Companion to `treeship add --discover` (which detects) and
//! `treeship agent register` (which mints a signed certificate). This is
//! where the user *manages* what got created: list every card, review one,
//! approve it (Draft -> Active or NeedsReview -> Active), or remove it.
//!
//! v0.9.8 surface:
//!   treeship agents              # list every card
//!   treeship agents review <id>  # show full card details
//!   treeship agents approve <id> # promote to Active
//!   treeship agents remove <id>  # delete the card
//!
//! `verified` is set programmatically by `treeship setup` (PR 3) once a
//! smoke session proves capture. It is intentionally not exposed as a manual
//! `agents verify` flag in v0.9.8 because the word "verified" must mean
//! something Treeship checked, not something the user toggled.

use crate::commands::cards::{self, AgentCard, CardStatus};
use crate::ctx;
use crate::printer::{Format, Printer};

fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    treeship_core::statements::unix_to_rfc3339(secs)
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

/// `treeship agents` -- list every card in the workspace's agents directory.
pub fn list(
    config: Option<&str>,
    format: Format,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let agents_dir = cards::agents_dir_for(&ctx.config_path);
    let cards_list = cards::list(&agents_dir)?;

    match format {
        Format::Json => {
            let value = serde_json::json!({
                "agents_dir": agents_dir,
                "cards":      cards_list,
            });
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Format::Text => {
            print_list(&cards_list, &agents_dir, printer);
        }
    }
    Ok(())
}

fn print_list(
    cards_list: &[AgentCard],
    agents_dir: &std::path::Path,
    printer: &Printer,
) {
    printer.blank();
    if cards_list.is_empty() {
        printer.dim_info("  No agent cards yet.");
        printer.blank();
        printer.hint("Run `treeship add --discover` to find local agents, then `treeship agent register` to register one.");
        printer.blank();
        return;
    }
    printer.section(&format!("Agent cards ({})", agents_dir.display()));
    printer.blank();
    for card in cards_list {
        let mark = match card.status {
            CardStatus::Verified    => "✓",
            CardStatus::Active      => "✓",
            CardStatus::NeedsReview => "?",
            CardStatus::Draft       => "·",
        };
        printer.info(&format!(
            "  {mark} {}  ({})",
            card.agent_name,
            card.surface.kind()
        ));
        printer.dim_info(&format!("    id:         {}", card.agent_id));
        printer.dim_info(&format!("    status:     {}", card.status.label()));
        printer.dim_info(&format!("    coverage:   {}", card.coverage.label()));
        printer.dim_info(&format!("    provenance: {}", card.provenance.label()));
        printer.blank();
    }
}

// ---------------------------------------------------------------------------
// review
// ---------------------------------------------------------------------------

/// `treeship agents review <id>` -- show every field on the card so the
/// user can decide whether to approve it.
pub fn review(
    agent_id: &str,
    config: Option<&str>,
    format: Format,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let agents_dir = cards::agents_dir_for(&ctx.config_path);
    let card = cards::load(&agents_dir, agent_id)?;

    match format {
        Format::Json => {
            println!("{}", serde_json::to_string_pretty(&card)?);
        }
        Format::Text => {
            print_review(&card, printer);
        }
    }
    Ok(())
}

fn print_review(card: &AgentCard, printer: &Printer) {
    printer.blank();
    printer.section(&format!("Agent card: {}", card.agent_name));
    printer.blank();

    printer.info(&format!("  id:         {}", card.agent_id));
    printer.info(&format!("  surface:    {}", card.surface.kind()));
    let conns: Vec<&str> = card
        .connection_modes
        .iter()
        .map(|c| c.label())
        .collect();
    printer.info(&format!("  connection: {}", conns.join(" + ")));
    printer.info(&format!("  coverage:   {}", card.coverage.label()));
    printer.info(&format!("  status:     {}", card.status.label()));
    printer.info(&format!("  provenance: {}", card.provenance.label()));
    printer.info(&format!("  host:       {}", card.host));
    printer.info(&format!("  workspace:  {}", card.workspace));
    if let Some(model) = &card.model {
        printer.info(&format!("  model:      {model}"));
    }
    if let Some(desc) = &card.description {
        printer.info(&format!("  note:       {desc}"));
    }
    if let Some(digest) = &card.certificate_digest {
        printer.info(&format!("  cert:       {digest}"));
    }
    if let Some(ssn) = &card.latest_session_id {
        printer.info(&format!("  last:       session {ssn}"));
    }
    printer.dim_info(&format!("  created:    {}", card.created_at));
    printer.dim_info(&format!("  updated:    {}", card.updated_at));

    if !card.capabilities.bounded_tools.is_empty() {
        printer.blank();
        printer.info(&format!(
            "  tools:      {}",
            card.capabilities.bounded_tools.join(", ")
        ));
    }
    if !card.capabilities.escalation_required.is_empty() {
        printer.info(&format!(
            "  escalate:   {}",
            card.capabilities.escalation_required.join(", ")
        ));
    }
    if !card.capabilities.forbidden.is_empty() {
        printer.info(&format!(
            "  forbidden:  {}",
            card.capabilities.forbidden.join(", ")
        ));
    }

    printer.blank();
    match card.status {
        CardStatus::Draft | CardStatus::NeedsReview => {
            printer.hint(&format!(
                "Approve with: treeship agents approve {}",
                card.agent_id
            ));
        }
        CardStatus::Active => {
            printer.dim_info("  Approved. Treeship will use this card during sessions.");
        }
        CardStatus::Verified => {
            printer.dim_info("  Verified by smoke session. Treeship has confirmed capture works.");
        }
    }
    printer.blank();
}

// ---------------------------------------------------------------------------
// approve / remove
// ---------------------------------------------------------------------------

/// `treeship agents approve <id>` -- promote Draft/NeedsReview to Active.
/// Refuses to demote an already-Verified card.
pub fn approve(
    agent_id: &str,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let agents_dir = cards::agents_dir_for(&ctx.config_path);
    let existing = cards::load(&agents_dir, agent_id)?;

    if existing.status == CardStatus::Verified {
        printer.dim_info(&format!(
            "  {} is already verified -- nothing to do.",
            existing.agent_id
        ));
        return Ok(());
    }
    if existing.status == CardStatus::Active {
        printer.dim_info(&format!(
            "  {} is already active.",
            existing.agent_id
        ));
        return Ok(());
    }

    let updated = cards::set_status(&agents_dir, agent_id, CardStatus::Active, &now_rfc3339())?;
    printer.blank();
    printer.success(
        &format!("approved {}", updated.agent_name),
        &[("status", updated.status.label())],
    );
    printer.dim_info(&format!("  id: {}", updated.agent_id));
    printer.blank();
    Ok(())
}

/// `treeship agents remove <id>` -- delete a card. Idempotent.
pub fn remove(
    agent_id: &str,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let agents_dir = cards::agents_dir_for(&ctx.config_path);
    cards::remove(&agents_dir, agent_id)?;
    printer.dim_info(&format!("  removed agent card {agent_id}"));
    Ok(())
}

