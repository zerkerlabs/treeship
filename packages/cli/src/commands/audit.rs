//! `treeship audit --hub <url> <agent>` — audit an agent's transparency log.
//!
//! The client half of Certificate Transparency for agents
//! (docs/specs/transparency-log.md): pull an agent's append-only history from a
//! Hub, **re-verify each anchored entry's Merkle inclusion offline** against
//! your own trust roots, and check completeness against the agent's committed
//! `evidence_anchor` so omission is detectable. The Hub serves metadata and
//! anchors; this command, not the Hub, decides what holds.

use crate::{ctx, printer::Printer};
use treeship_core::merkle::{MerkleTree, ProofFile};
use treeship_core::trust::TrustRootStore;

type CmdResult = Result<(), Box<dyn std::error::Error>>;

pub fn audit(agent: &str, hub: Option<&str>, config: Option<&str>, printer: &Printer) -> CmdResult {
    let _ctx = ctx::open(config)?;
    let trust = TrustRootStore::open_default_or_empty()?;
    let Some(hub) = hub else {
        return Err(
            "audit requires --hub <url> (the network transparency log); local history is `treeship log`"
                .into(),
        );
    };
    let base = hub.trim_end_matches('/');

    let log: serde_json::Value = ureq::get(&format!("{base}/v1/agents/log"))
        .query("agent", agent)
        .call()
        .map_err(|e| format!("could not reach hub {base}: {e}"))?
        .into_json()
        .map_err(|e| format!("hub returned invalid JSON: {e}"))?;

    let entries = log
        .get("entries")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Walk the history; re-verify each anchored entry's inclusion offline.
    let (mut anchored, mut verified) = (0usize, 0usize);
    let mut lines: Vec<String> = Vec::new();
    for e in &entries {
        let id = e.get("artifact_id").and_then(|v| v.as_str()).unwrap_or("");
        let kind = e.get("kind").and_then(|v| v.as_str()).unwrap_or("?");
        let action = e.get("action").and_then(|v| v.as_str()).unwrap_or("");
        let has_anchor = e
            .get("merkle_anchor")
            .map(|v| !v.is_null())
            .unwrap_or(false);

        let mark = if has_anchor {
            anchored += 1;
            match verify_inclusion(base, id, &trust) {
                Ok(true) => {
                    verified += 1;
                    "anchored ✓"
                }
                Ok(false) => "anchored ✗ INVALID",
                Err(_) => "anchored (proof unavailable)",
            }
        } else {
            ""
        };
        let label = if action.is_empty() {
            kind.to_string()
        } else {
            format!("{kind} {action}")
        };
        lines.push(format!("  {label:24} {} {mark}", &id[..id.len().min(20)]));
    }

    // Completeness against the agent's committed evidence_anchor.
    let committed_count = log
        .get("committed_anchor")
        .and_then(|c| c.get("receipt_count"))
        .and_then(|v| v.as_u64());
    let observed = entries.len() as u64;
    let completeness = match committed_count {
        Some(c) if observed >= c => format!("complete (committed {c}, observed {observed})"),
        Some(c) => format!("OMISSION — committed {c}, observed {observed}"),
        None => format!("no committed anchor (observed {observed})"),
    };

    let receipts_str = observed.to_string();
    let anchored_str = format!("{verified}/{anchored} verified");
    printer.success(
        "agent audit (remote)",
        &[
            ("agent", agent),
            ("hub", base),
            ("receipts", &receipts_str),
            ("anchored", &anchored_str),
            ("completeness", &completeness),
        ],
    );
    if committed_count.is_some_and(|c| observed < c) {
        printer.warn(
            "history is incomplete vs the agent's committed anchor",
            &[("completeness", &completeness)],
        );
    }
    printer.blank();
    if lines.is_empty() {
        printer.hint("no history for this agent on the hub.");
    } else {
        printer.info("timeline (newest first):");
        for line in &lines {
            printer.info(line);
        }
    }
    printer.blank();
    printer.hint(
        "metadata + anchors only, never payloads. each anchored entry's inclusion is re-verified offline against your trust roots; completeness is checked against the agent's committed evidence_anchor (omission detectable for committed sets, not absolute).",
    );
    printer.blank();
    Ok(())
}

/// Fetch one artifact's Merkle proof from the Hub and re-verify it offline:
/// the checkpoint signature against our trust roots + inclusion in the signed
/// root. Returns Ok(true) when both hold.
fn verify_inclusion(base: &str, artifact_id: &str, trust: &TrustRootStore) -> CmdResult2 {
    let pf: ProofFile = ureq::get(&format!("{base}/v1/merkle/{artifact_id}"))
        .call()?
        .into_json()?;
    let cp_ok = pf.checkpoint.verify(trust);
    let root_hex = pf
        .checkpoint
        .root
        .strip_prefix("sha256:")
        .unwrap_or(&pf.checkpoint.root);
    let incl_ok = MerkleTree::verify_proof(
        pf.checkpoint.merkle_version,
        root_hex,
        &pf.artifact_id,
        &pf.inclusion_proof,
    );
    Ok(cp_ok && incl_ok)
}

type CmdResult2 = Result<bool, Box<dyn std::error::Error>>;
