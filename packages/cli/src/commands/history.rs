//! `treeship history <agent>` — the work-history projection
//! (docs/specs/work-history.md slice 2).
//!
//! An agent's work history IS its transparency log filtered to `session.v1`
//! records: no new store, no new trust surface. Locally this scans the
//! artifact store; remotely it pulls raw signed envelopes from the Hub and
//! re-verifies each one on this machine — the envelope signature is checked
//! against YOUR trust roots (leaf pin or nothing; grading, not gating), each
//! anchored entry's Merkle inclusion is re-proved offline, and the typed
//! fields are read from the verified envelope, never from Hub-supplied
//! metadata. Filters and sort keys are schema fields (`attestation_class`,
//! `closed_at`), which is the entire point of the records being typed.

use crate::commands::resolve::verifier_from_trust;
use crate::{ctx, printer::Printer};
use treeship_core::attestation::Envelope;
use treeship_core::statements::{payload_type, ReceiptStatement};
use treeship_core::trust::TrustRootStore;

type CmdResult = Result<(), Box<dyn std::error::Error>>;

/// One rendered history row, extracted from a VERIFIED envelope.
struct Row {
    artifact_id: String,
    headline: String,
    outcome: String,
    class: String,
    closed_at: String,
    actions: u64,
    tools: usize,
    sig: &'static str,
    anchored: &'static str,
    hostile: bool,
}

pub fn history(
    agent: &str,
    hub: Option<&str>,
    class_filter: Option<&str>,
    since: Option<&str>,
    limit: usize,
    config: Option<&str>,
    printer: &Printer,
) -> CmdResult {
    let trust = TrustRootStore::open_default_or_empty()?;
    let agent = if agent.contains("://") {
        agent.to_string()
    } else {
        format!("agent://{agent}")
    };

    // Collect (artifact_id, envelope, anchored?) pairs from the chosen source.
    let mut raw: Vec<(String, Envelope, Option<bool>)> = Vec::new();
    if let Some(hub_url) = hub {
        let base = hub_url.trim_end_matches('/');
        let resp: serde_json::Value = ureq::get(&format!("{base}/v1/agents/history"))
            .query("agent", &agent)
            .call()
            .map_err(|e| format!("could not reach hub {base}: {e}"))?
            .into_json()
            .map_err(|e| format!("hub returned invalid JSON: {e}"))?;
        for e in resp
            .get("entries")
            .and_then(|v| v.as_array())
            .unwrap_or(&Vec::new())
        {
            let Some(id) = e.get("artifact_id").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(ej) = e.get("envelope_json").and_then(|v| v.as_str()) else {
                continue;
            };
            let Ok(env) = serde_json::from_str::<Envelope>(ej) else {
                continue;
            };
            // Re-verify the anchor OFFLINE when the hub claims one; the
            // claim itself is never trusted.
            let anchored = if e
                .get("merkle_anchor")
                .map(|v| !v.is_null())
                .unwrap_or(false)
            {
                Some(
                    crate::commands::audit::verify_inclusion(base, id, &trust)
                        .map(|(ok, _)| ok)
                        .unwrap_or(false),
                )
            } else {
                None
            };
            raw.push((id.to_string(), env, anchored));
        }
    } else {
        let ctx = ctx::open(config)?;
        let receipt_pt = payload_type("receipt");
        for entry in ctx.storage.list_by_type(&receipt_pt) {
            let Ok(rec) = ctx.storage.read(&entry.id) else {
                continue;
            };
            raw.push((entry.id.clone(), rec.envelope, None));
        }
    }

    // Verify + extract. The typed fields come from the envelope payload we
    // just checked, never from transport metadata.
    let verifier = verifier_from_trust(&trust);
    let mut rows: Vec<Row> = Vec::new();
    for (id, env, anchored) in raw {
        let sig_ok = verifier.verify_any(&env).is_ok();
        let Ok(stmt) = env.unmarshal_statement::<ReceiptStatement>() else {
            continue;
        };
        if stmt.kind != "session.v1" {
            continue;
        }
        let Some(p) = stmt.payload else { continue };
        if p.get("actor").and_then(|v| v.as_str()) != Some(agent.as_str()) {
            continue;
        }
        // AUD-06: cap the displayed class to what the payload's own counts
        // justify, so a forged `countersigned`/`runtime` label does not render
        // as such. A record with no class at all still shows "?".
        let class = match p.get("attestation_class").and_then(|v| v.as_str()) {
            Some(declared) => super::profile::cap_class_to_evidence(declared, &p).to_string(),
            None => "?".to_string(),
        };
        if let Some(cf) = class_filter {
            if class != cf {
                continue;
            }
        }
        let closed_at = p
            .get("closed_at")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(s) = since {
            if closed_at.as_str() < s {
                continue;
            }
        }
        let (anchored_str, anchor_hostile) = match anchored {
            Some(true) => ("anchored ✓", false),
            Some(false) => ("anchored ✗ INVALID", true),
            None => ("", false),
        };
        rows.push(Row {
            artifact_id: id,
            headline: p
                .get("headline")
                .and_then(|v| v.as_str())
                .unwrap_or("(no headline)")
                .to_string(),
            outcome: p
                .get("outcome")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string(),
            class,
            closed_at,
            actions: p.get("action_count").and_then(|v| v.as_u64()).unwrap_or(0),
            tools: p
                .get("tools_exercised")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0),
            sig: if sig_ok { "verified" } else { "unverified" },
            anchored: anchored_str,
            hostile: anchor_hostile,
        });
    }

    // Newest first, bounded.
    rows.sort_by(|a, b| b.closed_at.cmp(&a.closed_at));
    let total = rows.len();
    rows.truncate(limit);
    let hostile = rows.iter().any(|r| r.hostile);

    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "agent": agent,
            "total": total,
            "shown": rows.len(),
            "ok": !hostile,
            "records": rows.iter().map(|r| serde_json::json!({
                "artifact_id": r.artifact_id,
                "headline": r.headline,
                "outcome": r.outcome,
                "attestation_class": r.class,
                "closed_at": r.closed_at,
                "action_count": r.actions,
                "tools_exercised_count": r.tools,
                "signature": r.sig,
                "anchored": r.anchored,
            })).collect::<Vec<_>>(),
        }));
        if hostile {
            std::process::exit(1);
        }
        return Ok(());
    }

    if rows.is_empty() {
        printer.warn("no work history", &[("agent", agent.as_str())]);
        printer.hint("session.v1 records are minted on `treeship session close` (0.16.0+); publish them with `treeship publish` + `merkle publish` to serve history from a hub.");
        printer.blank();
        return Ok(());
    }

    printer.success(
        "work history",
        &[
            ("agent", agent.as_str()),
            ("records", &format!("{} shown of {total}", rows.len())),
        ],
    );
    printer.blank();
    for r in &rows {
        printer.info(&format!(
            "  {}  {:<11} {:<13} {}",
            r.closed_at, r.outcome, r.class, r.headline
        ));
        printer.dim_info(&format!(
            "    {}  {} actions, {} tools  sig: {}  {}",
            r.artifact_id, r.actions, r.tools, r.sig, r.anchored
        ));
    }
    printer.blank();
    printer.hint(
        "each record is a signed session.v1 receipt, fields read from the verified envelope. sig is graded against YOUR trust roots; anchored entries' inclusion is re-proved offline. history proves what was recorded, never everything that happened.",
    );
    printer.blank();
    if hostile {
        std::process::exit(1);
    }
    Ok(())
}
