//! `treeship publish <agent>` — push an agent's resolvable set to the Hub.
//!
//! Makes an agent resolvable over the network: finds the agent's current
//! capability cards and any revocations in the local store and pushes them to
//! the configured Hub, so `treeship resolve --hub <url> <agent>` (and anyone
//! else) can resolve and re-verify them. Slice 4 of the agent resolver
//! (docs/specs/agent-resolver.md). The push reuses the authenticated
//! `hub push` path; the artifacts are unchanged signed envelopes.

use std::collections::HashSet;

use crate::{ctx, printer::Printer};
use treeship_core::statements::{payload_type, ReceiptStatement};

type CmdResult = Result<(), Box<dyn std::error::Error>>;

pub fn publish(agent: &str, config: Option<&str>, printer: &Printer) -> CmdResult {
    let ctx = ctx::open(config)?;
    let receipt_pt = payload_type("receipt");

    // The agent's capability cards.
    let mut to_push: Vec<String> = Vec::new();
    let mut card_ids: HashSet<String> = HashSet::new();
    for entry in ctx.storage.list_by_type(&receipt_pt) {
        let Ok(rec) = ctx.storage.read(&entry.id) else {
            continue;
        };
        let Ok(stmt) = rec.envelope.unmarshal_statement::<ReceiptStatement>() else {
            continue;
        };
        if stmt.kind == "agent_card.v1"
            && stmt
                .payload
                .as_ref()
                .and_then(|p| p.get("agent"))
                .and_then(|v| v.as_str())
                == Some(agent)
        {
            to_push.push(entry.id.clone());
            card_ids.insert(entry.id.clone());
        }
    }

    // The agent's certificate chain: agent_cert.v1 receipts binding this
    // agent's URI to its per-agent key, signed by the ship (registry-topology
    // slice 1). Pushing the chain is what lets a remote verifier who pins
    // only the ship key verify this agent's card — without it, verifiers
    // must pin every leaf key directly.
    for entry in ctx.storage.list_by_type(&receipt_pt) {
        let Ok(rec) = ctx.storage.read(&entry.id) else {
            continue;
        };
        let Ok(stmt) = rec.envelope.unmarshal_statement::<ReceiptStatement>() else {
            continue;
        };
        if stmt.kind == "agent_cert.v1"
            && stmt
                .payload
                .as_ref()
                .and_then(|p| p.get("agent"))
                .and_then(|v| v.as_str())
                == Some(agent)
        {
            to_push.push(entry.id.clone());
        }
    }

    // Revocations referencing one of those cards.
    for entry in ctx.storage.list_by_type(&receipt_pt) {
        let Ok(rec) = ctx.storage.read(&entry.id) else {
            continue;
        };
        let Ok(stmt) = rec.envelope.unmarshal_statement::<ReceiptStatement>() else {
            continue;
        };
        if stmt.kind == "agent_card_revocation.v1" {
            if let Some(card) = stmt
                .payload
                .as_ref()
                .and_then(|p| p.get("card"))
                .and_then(|v| v.as_str())
            {
                if card_ids.contains(card) {
                    to_push.push(entry.id.clone());
                }
            }
        }
    }

    if to_push.is_empty() {
        printer.warn("nothing to publish", &[("agent", agent)]);
        printer.hint(
            "no agent_card.v1 for this agent in the local store; mint one with `treeship attest card`.",
        );
        printer.blank();
        return Ok(());
    }

    let mut pushed = 0usize;
    for id in &to_push {
        match crate::commands::hub::push_artifact(&ctx, id) {
            Ok(_) => {
                pushed += 1;
                printer.info(&format!("  published {id}"));
            }
            Err(e) => {
                printer.warn("publish failed", &[("artifact", id), ("error", &e.to_string())]);
                return Err(e);
            }
        }
    }

    let count = pushed.to_string();
    printer.success(
        "agent published",
        &[("agent", agent), ("artifacts", &count)],
    );
    printer.hint(&format!(
        "now resolvable: treeship resolve --hub <url> {agent}"
    ));
    printer.blank();
    Ok(())
}
