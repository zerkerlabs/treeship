//! `treeship approval` subcommands -- v0.9.9 PR 2 read-only surface.
//!
//! Three commands wrap the local Approval Use Journal:
//!
//!     treeship approval uses <grant-id>             # list every use
//!     treeship approval status <grant-id>           # count vs max_uses
//!     treeship approval journal verify              # chain integrity check
//!
//! No write commands (consume-before-action lands in PR 3 inside
//! `treeship attest action`). No package-level commands (PR 4). Just
//! enough surface for users + tests to inspect the journal that PR 3's
//! consume flow will write to.
//!
//! The journal directory follows the same precedence pattern as
//! cards (PR 2 of v0.9.8) and harness state (PR 5 of v0.9.8): we resolve
//! it relative to the active config_path so a project-local Treeship
//! gets its own journal, and the global config gets another. This keeps
//! the trust scope honest -- the journal answers questions about the
//! workspace it was created for, not some shared global state.

use std::path::{Path, PathBuf};

use treeship_core::journal::{self, Journal};

use crate::ctx;
use crate::printer::{Format, Printer};

fn journal_dir_for(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("journals")
        .join("approval-use")
}

// ---------------------------------------------------------------------------
// uses
// ---------------------------------------------------------------------------

/// `treeship approval uses <grant-id>` -- list every recorded use of a
/// grant. Empty list when the journal is missing or has no entries for
/// the grant; that's the same posture verify falls back to (package-local).
pub fn uses(
    grant_id: &str,
    config: Option<&str>,
    format: Format,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let j = Journal::new(journal_dir_for(&ctx.config_path));
    let uses = journal::list_uses_for_grant(&j, grant_id)?;

    match format {
        Format::Json => {
            let value = serde_json::json!({
                "grant_id":      grant_id,
                "journal_exists": j.exists(),
                "uses":           uses,
            });
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Format::Text => {
            printer.blank();
            if !j.exists() {
                printer.dim_info("  No local Approval Use Journal at this workspace.");
                printer.dim_info("  Verify will fall back to package-local replay only.");
                printer.blank();
                return Ok(());
            }
            if uses.is_empty() {
                printer.dim_info(&format!("  No recorded uses for grant {grant_id}."));
                printer.blank();
                return Ok(());
            }
            printer.section(&format!("approval uses ({} for grant {grant_id})", uses.len()));
            for u in &uses {
                let max = u.max_uses.map(|m| m.to_string()).unwrap_or_else(|| "?".into());
                printer.info(&format!(
                    "  use {}/{}  {}  -> {}  by {}  at {}",
                    u.use_number, max, u.action, u.subject, u.actor, u.created_at,
                ));
                printer.dim_info(&format!("    use_id:        {}", u.use_id));
                printer.dim_info(&format!("    nonce_digest:  {}", u.nonce_digest));
                if let Some(idem) = &u.idempotency_key {
                    printer.dim_info(&format!("    idempotency:   {idem}"));
                }
                if let Some(aid) = &u.action_artifact_id {
                    printer.dim_info(&format!("    action_id:     {aid}"));
                }
            }
            printer.blank();
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

/// `treeship approval status <grant-id>` -- summary of the grant's
/// consumption state. Reports use_count, max_uses (when known from
/// stored records), and whether further uses would exceed.
pub fn status(
    grant_id: &str,
    config: Option<&str>,
    format: Format,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let j = Journal::new(journal_dir_for(&ctx.config_path));
    let uses = journal::list_uses_for_grant(&j, grant_id)?;

    let count = uses.len() as u32;
    let max_uses = uses.iter().filter_map(|u| u.max_uses).last();
    let exceeded = match max_uses {
        Some(m) => count >= m,
        None    => false,
    };

    match format {
        Format::Json => {
            let value = serde_json::json!({
                "grant_id":       grant_id,
                "journal_exists": j.exists(),
                "use_count":      count,
                "max_uses":       max_uses,
                "would_exceed":   exceeded,
            });
            println!("{}", serde_json::to_string_pretty(&value)?);
        }
        Format::Text => {
            printer.blank();
            printer.section(&format!("approval status: {grant_id}"));
            if !j.exists() {
                printer.dim_info("  no local Approval Use Journal at this workspace");
                printer.blank();
                return Ok(());
            }
            let max_label = max_uses.map(|m| m.to_string()).unwrap_or_else(|| "unbounded".into());
            printer.info(&format!("  use count:    {count}"));
            printer.info(&format!("  max_uses:     {max_label}"));
            if exceeded {
                printer.warn(
                    "  next use would exceed max_uses",
                    &[("grant_id", grant_id)],
                );
            } else {
                printer.dim_info("  next use is within max_uses");
            }
            printer.blank();
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// journal verify
// ---------------------------------------------------------------------------

/// `treeship approval journal verify` -- walk the entire journal,
/// recompute every record digest, check the previous_record_digest
/// chain, and compare against the head. On success prints "passed"
/// with the record count; on failure prints the exact integrity
/// violation pinpointing the broken record.
pub fn journal_verify(
    config: Option<&str>,
    format: Format,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let j = Journal::new(journal_dir_for(&ctx.config_path));

    if !j.exists() {
        match format {
            Format::Json => {
                let value = serde_json::json!({
                    "journal_exists": false,
                    "passed":         null,
                });
                println!("{}", serde_json::to_string_pretty(&value)?);
            }
            Format::Text => {
                printer.blank();
                printer.dim_info("  No local Approval Use Journal in this workspace; nothing to verify.");
                printer.blank();
            }
        }
        return Ok(());
    }

    match journal::verify_integrity(&j) {
        Ok(count) => {
            match format {
                Format::Json => {
                    let value = serde_json::json!({
                        "journal_exists": true,
                        "passed":         true,
                        "record_count":   count,
                    });
                    println!("{}", serde_json::to_string_pretty(&value)?);
                }
                Format::Text => {
                    printer.blank();
                    printer.success(
                        &format!("journal verified: {count} records, chain intact"),
                        &[],
                    );
                    printer.blank();
                }
            }
            Ok(())
        }
        Err(e) => {
            match format {
                Format::Json => {
                    let value = serde_json::json!({
                        "journal_exists": true,
                        "passed":         false,
                        "error":          e.to_string(),
                    });
                    println!("{}", serde_json::to_string_pretty(&value)?);
                }
                Format::Text => {
                    printer.blank();
                    printer.warn("journal integrity check failed", &[("error", &e.to_string())]);
                    printer.blank();
                }
            }
            // Return the error so the process exits non-zero.
            Err(Box::new(std::io::Error::other(e.to_string())))
        }
    }
}
