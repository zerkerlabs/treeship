//! `treeship match --hub <url> --exercised <glob>` — find agents by their
//! EXERCISED evidence (docs/specs/work-history.md slice 4).
//!
//! Declared capability gets an agent *found*; exercised history gets it
//! *chosen*. The Hub indexes `tools_exercised` from the typed session.v1
//! records it already holds and proposes candidates; it grades nothing. The
//! client re-verifies every candidate's records on this machine — each
//! record's envelope signature against YOUR trust roots, each claimed anchor
//! re-proved offline — and ranks by *verified* evidence, so a candidate the
//! Hub proposes but whose records don't verify is shown honestly as
//! unverified, never silently trusted. This is the honest version of an
//! agent marketplace: the search is only ever a lead, the verdict is always
//! recomputed locally.

use crate::commands::resolve::verifier_from_trust;
use crate::printer::Printer;
use treeship_core::attestation::Envelope;
use treeship_core::capability::tool_matches;
use treeship_core::statements::ReceiptStatement;
use treeship_core::trust::TrustRootStore;

type CmdResult = Result<(), Box<dyn std::error::Error>>;

pub fn match_agents(
    hub: &str,
    exercised: &str,
    class: Option<&str>,
    min_sessions: usize,
    printer: &Printer,
) -> CmdResult {
    let trust = TrustRootStore::open_default_or_empty()?;
    let base = hub.trim_end_matches('/');

    let mut req = ureq::get(&format!("{base}/v1/agents/match")).query("exercised", exercised);
    if let Some(c) = class {
        req = req.query("class", c);
    }
    if min_sessions > 1 {
        req = req.query("min_sessions", &min_sessions.to_string());
    }
    let resp: serde_json::Value = req
        .call()
        .map_err(|e| format!("could not reach hub {base}: {e}"))?
        .into_json()
        .map_err(|e| format!("hub returned invalid JSON: {e}"))?;

    let verifier = verifier_from_trust(&trust);

    struct Candidate {
        agent: String,
        matched_tools: Vec<String>,
        proposed_sessions: usize,
        verified_sessions: usize,
        verified_matches: bool,
    }
    let mut candidates: Vec<Candidate> = Vec::new();

    for c in resp
        .get("candidates")
        .and_then(|v| v.as_array())
        .unwrap_or(&Vec::new())
    {
        let agent = c
            .get("agent")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let matched_tools: Vec<String> = c
            .get("matched_tools")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|t| t.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let proposed = c
            .get("matched_sessions")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize;

        // Re-verify each record the Hub returned: the envelope must verify
        // against our roots, be a session.v1 for THIS agent, and actually
        // exercise a tool matching the glob (never trust the Hub's own
        // match — recompute it here with the shared matcher).
        let mut verified = 0usize;
        if let Some(records) = c.get("records").and_then(|v| v.as_array()) {
            for rec in records {
                let Some(ej) = rec.get("envelope_json").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Ok(env) = serde_json::from_str::<Envelope>(ej) else {
                    continue;
                };
                if verifier.verify_any(&env).is_err() {
                    continue;
                }
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
                let exercises_match = p
                    .get("tools_exercised")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|t| t.as_str())
                            .any(|t| tool_matches(exercised, t))
                    })
                    .unwrap_or(false);
                if exercises_match {
                    verified += 1;
                }
            }
        }
        candidates.push(Candidate {
            agent,
            matched_tools,
            proposed_sessions: proposed,
            verified_sessions: verified,
            verified_matches: verified > 0,
        });
    }

    // Rank by VERIFIED sessions (locally recomputed), not the Hub's count.
    candidates.sort_by(|a, b| b.verified_sessions.cmp(&a.verified_sessions));

    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "exercised": exercised,
            "count": candidates.len(),
            "candidates": candidates.iter().map(|c| serde_json::json!({
                "agent": c.agent,
                "matched_tools": c.matched_tools,
                "proposed_sessions": c.proposed_sessions,
                "verified_sessions": c.verified_sessions,
                "verified": c.verified_matches,
            })).collect::<Vec<_>>(),
        }));
        return Ok(());
    }

    if candidates.is_empty() {
        printer.warn("no agents match", &[("exercised", exercised)]);
        printer.hint("no published session.v1 records exercise a tool matching this glob. matching is only as good as the density of published history.");
        printer.blank();
        return Ok(());
    }

    printer.success(
        "evidence match",
        &[
            ("exercised", exercised),
            ("candidates", &candidates.len().to_string()),
        ],
    );
    printer.blank();
    for c in &candidates {
        let mark = if c.verified_matches {
            format!("{} verified", c.verified_sessions)
        } else {
            "unverified (records did not verify against your trust roots)".to_string()
        };
        printer.info(&format!(
            "  {}  {}/{} sessions {mark}",
            c.agent, c.verified_sessions, c.proposed_sessions
        ));
        printer.dim_info(&format!("    exercised: {}", c.matched_tools.join(", ")));
    }
    printer.blank();
    printer.hint(
        "the hub proposed candidates from its index; each record was re-verified on this machine against YOUR trust roots. ranked by verified sessions. pin an agent's key (treeship trust add) to move it from unverified to verified.",
    );
    printer.blank();
    Ok(())
}
