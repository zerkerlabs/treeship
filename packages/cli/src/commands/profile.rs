//! `treeship profile` / `verify-profile` — the derived track record
//! (docs/specs/work-history.md slice 3).
//!
//! A profile is a claim ("37 sessions, 212 actions, these tools, this span")
//! and claims are `asserted` until checked. The anti-drift mechanism is
//! checkpoint pinning: every number is a **deterministic aggregation over
//! the log's first `tree_size` leaves** at a named checkpoint whose root is
//! embedded in the payload. `verify-profile` rebuilds that exact prefix,
//! cross-checks its root against the pinned one, recomputes the aggregate,
//! and compares — match grades the profile `checked`; mismatch is a provable
//! lie, named field by field. Because the log carries consistency proofs,
//! history under a pinned profile cannot be silently rewritten either.
//! Reputation pinned to a root is falsifiable; reputation that floats is
//! marketing.

use crate::commands::merkle::{build_tree, checkpoint_tree, load_latest_checkpoint};
use crate::{ctx, printer::Printer};
use treeship_core::attestation::sign;
use treeship_core::merkle::Checkpoint;
use treeship_core::statements::{payload_type, ReceiptStatement};
use treeship_core::storage::Record;

type CmdResult = Result<(), Box<dyn std::error::Error>>;

/// The deterministic aggregation: agent + pinned checkpoint + the session.v1
/// payloads found in the pinned prefix (IN PREFIX ORDER) → profile payload.
/// Pure — the entire recomputability guarantee rests on this function being
/// a function of exactly these inputs. `computed_at` is deliberately NOT
/// part of the comparable aggregate (verify-profile ignores it).
/// Normalize a self-declared class to a known ladder value; anything outside
/// the vocabulary folds to `self` so it can never be tallied as a trusted
/// bucket or outrank a real class.
fn normalize_class(class: &str) -> &'static str {
    match class {
        "countersigned" => "countersigned",
        "runtime" => "runtime",
        _ => "self",
    }
}

/// Ladder rank: self < runtime < countersigned.
fn class_rank(class: &str) -> u8 {
    match class {
        "countersigned" => 2,
        "runtime" => 1,
        _ => 0,
    }
}

/// The strongest class a session.v1 payload's OWN counts substantiate, using
/// the same rule `session close` mints by: countersigned requires a consumed
/// approval; runtime requires a non-cli harness. A self-consistency floor,
/// not a full evidence check (AUD-06).
fn justified_class(p: &serde_json::Value) -> &'static str {
    let approvals = p
        .get("approval_count")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let harness = p.get("harness").and_then(|v| v.as_str()).unwrap_or("cli");
    if approvals > 0 {
        "countersigned"
    } else if !harness.is_empty() && harness != "cli" {
        "runtime"
    } else {
        "self"
    }
}

/// Cap a declared class to what the payload's own evidence justifies: the
/// weaker of (normalized declared, justified). A record claiming
/// `countersigned` with zero approvals is tallied as what its counts support.
pub(crate) fn cap_class_to_evidence(declared: &str, p: &serde_json::Value) -> &'static str {
    let declared = normalize_class(declared);
    let justified = justified_class(p);
    if class_rank(declared) <= class_rank(justified) {
        declared
    } else {
        justified
    }
}

pub(crate) fn aggregate_profile(
    agent: &str,
    checkpoint: &Checkpoint,
    session_payloads: &[serde_json::Value],
    computed_at: &str,
) -> serde_json::Value {
    let mut by_class = std::collections::BTreeMap::new();
    let (mut actions, mut approvals, mut handoffs) = (0u64, 0u64, 0u64);
    let mut tools: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut span: Vec<String> = Vec::new();

    for p in session_payloads {
        let declared = p
            .get("attestation_class")
            .and_then(|v| v.as_str())
            .unwrap_or("self");
        // AUD-06: do not tally a self-declared class higher than the payload's
        // own evidence counts justify. `session close` derives `countersigned`
        // only when approvals were consumed and `runtime` only under a real
        // tool runtime; a record claiming a stronger class than its own
        // approval_count / harness support is internally inconsistent, so we
        // cap it to what it can substantiate rather than laundering it into
        // the higher trust bucket. (Full cross-checking against the embedded
        // signed grants requires the sealed packages, not just these payloads;
        // that deeper dereference is tracked as a follow-up.)
        let class = cap_class_to_evidence(declared, p).to_string();
        *by_class.entry(class).or_insert(0u64) += 1;
        actions += p.get("action_count").and_then(|v| v.as_u64()).unwrap_or(0);
        approvals += p
            .get("approval_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        handoffs += p.get("handoff_count").and_then(|v| v.as_u64()).unwrap_or(0);
        if let Some(ts) = p.get("tools_exercised").and_then(|v| v.as_array()) {
            for t in ts.iter().filter_map(|t| t.as_str()) {
                tools.insert(t.to_string());
            }
        }
        if let Some(c) = p.get("closed_at").and_then(|v| v.as_str()) {
            span.push(c.to_string());
        }
    }
    span.sort();

    serde_json::json!({
        "agent": agent,
        "checkpoint_index": checkpoint.index,
        "checkpoint_tree_size": checkpoint.tree_size,
        "checkpoint_root": checkpoint.root,
        "computed_at": computed_at,
        "sessions_total": session_payloads.len(),
        "sessions_self": by_class.get("self").copied().unwrap_or(0),
        "sessions_runtime": by_class.get("runtime").copied().unwrap_or(0),
        "sessions_countersigned": by_class.get("countersigned").copied().unwrap_or(0),
        "actions_total": actions,
        "approvals_total": approvals,
        "handoffs_total": handoffs,
        "tools_exercised": tools.into_iter().collect::<Vec<_>>(),
        "span_first": span.first(),
        "span_last": span.last(),
    })
}

/// Collect the agent's session.v1 payloads from EXACTLY the checkpoint's
/// prefix, in prefix order — the shared input path for compute and verify,
/// so the two cannot drift. The prefix's rebuilt root is cross-checked
/// against `expected_root` before anything is aggregated: numbers computed
/// over a prefix that does not reproduce the pinned root are meaningless.
fn sessions_in_prefix(
    ctx: &ctx::Ctx,
    agent: &str,
    tree_size: usize,
    expected_root: &str,
    checkpoint: &Checkpoint,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error>> {
    let (_, artifact_ids) = build_tree(ctx)?;
    // Reuse the audited truncate-and-cross-check helper for the root check.
    if checkpoint.tree_size != tree_size || checkpoint.root != expected_root {
        return Err("internal: checkpoint/pin mismatch".into());
    }
    let _ = checkpoint_tree(&artifact_ids, checkpoint)?;

    let receipt_pt = payload_type("receipt");
    let mut out = Vec::new();
    for id in &artifact_ids[..tree_size] {
        let Ok(rec) = ctx.storage.read(id) else {
            continue;
        };
        if rec.payload_type != receipt_pt {
            continue;
        }
        let Ok(stmt) = rec.envelope.unmarshal_statement::<ReceiptStatement>() else {
            continue;
        };
        if stmt.kind != "session.v1" {
            continue;
        }
        let Some(p) = stmt.payload else { continue };
        if p.get("actor").and_then(|v| v.as_str()) == Some(agent) {
            out.push(p);
        }
    }
    Ok(out)
}

fn now_rfc3339() -> String {
    treeship_core::statements::unix_to_rfc3339(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

pub fn profile(agent: &str, attest: bool, config: Option<&str>, printer: &Printer) -> CmdResult {
    let ctx = ctx::open(config)?;
    let agent = if agent.contains("://") {
        agent.to_string()
    } else {
        format!("agent://{agent}")
    };

    let checkpoint = load_latest_checkpoint()?
        .ok_or("no checkpoints found -- run: treeship checkpoint  (a profile must pin one)")?;
    let sessions = sessions_in_prefix(
        &ctx,
        &agent,
        checkpoint.tree_size,
        &checkpoint.root,
        &checkpoint,
    )?;
    let payload = aggregate_profile(&agent, &checkpoint, &sessions, &now_rfc3339());

    let mut attested_id: Option<String> = None;
    if attest {
        treeship_core::predicates::validate("profile.v1", Some(&payload))
            .map_err(|e| format!("profile.v1 validation failed: {e}"))?;
        let mut stmt =
            ReceiptStatement::new(&format!("ship://{}", ctx.config.ship_id), "profile.v1");
        stmt.payload = Some(payload.clone());
        // The SHIP signs: a profile is the operator's claim about the
        // agent's record, checked by anyone via recompute — not the agent
        // grading itself.
        let signer = ctx.keys.default_signer()?;
        let pt = payload_type("receipt");
        let result = sign(&pt, &stmt, signer.as_ref())?;
        ctx.storage.write(&Record {
            artifact_id: result.artifact_id.clone(),
            digest: result.digest,
            payload_type: pt,
            key_id: signer.key_id().to_string(),
            signed_at: stmt.timestamp.clone(),
            parent_id: None,
            envelope: result.envelope,
            hub_url: None,
        })?;
        attested_id = Some(result.artifact_id);
    }

    if printer.format == crate::printer::Format::Json {
        let mut body = payload;
        if let Some(id) = &attested_id {
            body["attested_artifact_id"] = serde_json::json!(id);
        }
        printer.json(&body);
        return Ok(());
    }

    printer.success(
        "profile",
        &[
            ("agent", agent.as_str()),
            (
                "pinned",
                &format!(
                    "checkpoint #{} (tree_size {})",
                    checkpoint.index, checkpoint.tree_size
                ),
            ),
            (
                "sessions",
                &format!(
                    "{} ({} self, {} runtime, {} countersigned)",
                    payload["sessions_total"],
                    payload["sessions_self"],
                    payload["sessions_runtime"],
                    payload["sessions_countersigned"]
                ),
            ),
            ("actions", &payload["actions_total"].to_string()),
            ("approvals", &payload["approvals_total"].to_string()),
            (
                "tools",
                &payload["tools_exercised"]
                    .as_array()
                    .map(|a| a.len())
                    .unwrap_or(0)
                    .to_string(),
            ),
            (
                "span",
                &format!(
                    "{} → {}",
                    payload["span_first"].as_str().unwrap_or("-"),
                    payload["span_last"].as_str().unwrap_or("-")
                ),
            ),
        ],
    );
    if let Some(id) = attested_id {
        printer.info(&format!(
            "  attested:  {id}  (profile.v1, ship-signed claim)"
        ));
        printer.hint(&format!(
            "anyone recomputes it: treeship verify-profile {id}"
        ));
    } else {
        printer.hint("sign it as a claim: treeship profile <agent> --attest");
    }
    printer.blank();
    printer.hint("every number is recomputable from the log at the pinned checkpoint. asserted until checked; checked by recompute, not by trust.");
    printer.blank();
    Ok(())
}

pub fn verify_profile(artifact_id: &str, config: Option<&str>, printer: &Printer) -> CmdResult {
    let ctx = ctx::open(config)?;
    let rec = ctx.storage.read(artifact_id)?;
    let stmt: ReceiptStatement = rec.envelope.unmarshal_statement()?;
    if stmt.kind != "profile.v1" {
        return Err(format!("{artifact_id} is a `{}`, not a profile.v1", stmt.kind).into());
    }
    let claimed = stmt.payload.ok_or("profile carries no payload")?;
    let agent = claimed
        .get("agent")
        .and_then(|v| v.as_str())
        .ok_or("profile carries no agent")?
        .to_string();
    let tree_size = claimed
        .get("checkpoint_tree_size")
        .and_then(|v| v.as_u64())
        .ok_or("profile carries no pinned tree_size")? as usize;
    let root = claimed
        .get("checkpoint_root")
        .and_then(|v| v.as_str())
        .ok_or("profile carries no pinned root")?
        .to_string();
    let index = claimed
        .get("checkpoint_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    // Recompute from the pinned prefix. The pin travels IN the claim; the
    // synthetic Checkpoint below only carries what recomputation needs
    // (size + root for the cross-check) — signature trust for the claim is
    // the envelope's, already stored, and checkpoint-signature trust was
    // the anchor path's job at publish time.
    let pin = Checkpoint {
        index,
        root: root.clone(),
        tree_size,
        ..rec_pin_defaults()
    };
    let sessions = sessions_in_prefix(&ctx, &agent, tree_size, &root, &pin).map_err(|e| {
        format!(
            "cannot recompute: {e}\n\n  the local log must reproduce the pinned checkpoint (#{index}, tree_size {tree_size}) to grade this profile"
        )
    })?;
    let recomputed = aggregate_profile(&agent, &pin, &sessions, "");

    // Compare every field except computed_at (informational, not aggregate).
    let mut mismatches: Vec<String> = Vec::new();
    if let (Some(c), Some(r)) = (claimed.as_object(), recomputed.as_object()) {
        for (k, rv) in r {
            if k == "computed_at" {
                continue;
            }
            let cv = c.get(k).unwrap_or(&serde_json::Value::Null);
            if cv != rv {
                mismatches.push(format!("{k}: claimed {cv}, recomputed {rv}"));
            }
        }
    }

    let checked = mismatches.is_empty();
    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "verdict": if checked { "checked (recomputed, all fields match)" } else { "MISMATCH — profile is provably false" },
            "ok": checked,
            "profile": artifact_id,
            "agent": agent,
            "pinned_checkpoint": { "index": index, "tree_size": tree_size, "root": root },
            "mismatches": mismatches,
        }));
        if !checked {
            std::process::exit(1);
        }
        return Ok(());
    }

    if checked {
        printer.success(
            "profile checked",
            &[
                ("profile", artifact_id),
                ("agent", agent.as_str()),
                (
                    "pinned",
                    &format!("checkpoint #{index} (tree_size {tree_size}), root reproduced"),
                ),
                (
                    "grade",
                    "checked — every number recomputed from the log and matched",
                ),
            ],
        );
    } else {
        printer.warn(
            "profile MISMATCH — provably false",
            &[("profile", artifact_id)],
        );
        for m in &mismatches {
            printer.info(&format!("  {m}"));
        }
    }
    printer.blank();
    if !checked {
        std::process::exit(1);
    }
    Ok(())
}

/// Defaults for the synthetic pin Checkpoint (recompute needs only
/// index/root/tree_size; the rest are unused by the truncation cross-check).
fn rec_pin_defaults() -> Checkpoint {
    serde_json::from_value(serde_json::json!({
        "index": 0, "root": "", "tree_size": 0, "height": 0,
        "signed_at": "", "signer": "", "public_key": "", "signature": ""
    }))
    .expect("static checkpoint defaults")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp(index: u64, tree_size: usize, root: &str) -> Checkpoint {
        let mut c = rec_pin_defaults();
        c.index = index;
        c.tree_size = tree_size;
        c.root = root.into();
        c
    }

    fn session(class: &str, actions: u64, tools: &[&str], closed: &str) -> serde_json::Value {
        serde_json::json!({
            "attestation_class": class,
            "action_count": actions,
            "approval_count": 1,
            "handoff_count": 0,
            "tools_exercised": tools,
            "closed_at": closed,
        })
    }

    // AUD-06: a self-declared class must not be tallied higher than the
    // payload's own counts justify.
    #[test]
    fn forged_countersigned_without_approvals_is_capped_to_self() {
        let forged = serde_json::json!({
            "attestation_class": "countersigned",
            "action_count": 9999,
            "approval_count": 0,   // no consumed approval backs the claim
            "harness": "cli",      // no runtime either
            "closed_at": "2026-07-06T00:00:00Z",
        });
        assert_eq!(cap_class_to_evidence("countersigned", &forged), "self");

        let c = cp(1, 10, "sha256:aa");
        let out = aggregate_profile("agent://x", &c, &[forged], "T");
        assert_eq!(
            out["sessions_countersigned"], 0,
            "forge must not land in countersigned"
        );
        assert_eq!(out["sessions_self"], 1);
    }

    #[test]
    fn forged_runtime_without_harness_is_capped_to_self() {
        let forged = serde_json::json!({
            "attestation_class": "runtime",
            "approval_count": 0,
            "harness": "cli",
            "closed_at": "2026-07-06T00:00:00Z",
        });
        assert_eq!(cap_class_to_evidence("runtime", &forged), "self");
    }

    #[test]
    fn honest_countersigned_with_approval_is_kept() {
        let honest = serde_json::json!({
            "attestation_class": "countersigned",
            "approval_count": 2,
            "harness": "claude-code",
            "closed_at": "2026-07-06T00:00:00Z",
        });
        assert_eq!(
            cap_class_to_evidence("countersigned", &honest),
            "countersigned"
        );
    }

    #[test]
    fn unknown_class_folds_to_self() {
        let p = serde_json::json!({ "approval_count": 5, "harness": "claude-code" });
        // Even though evidence would justify countersigned, an unrecognized
        // declared label never outranks; it normalizes to self.
        assert_eq!(cap_class_to_evidence("super-trusted", &p), "self");
    }

    #[test]
    fn aggregate_is_deterministic_and_order_insensitive_where_promised() {
        let c = cp(7, 100, "sha256:aa");
        let s1 = session(
            "runtime",
            10,
            &["Bash(git:*)", "Edit(*)"],
            "2026-07-01T00:00:00Z",
        );
        let s2 = session("self", 5, &["Edit(*)", "Read(*)"], "2026-07-06T00:00:00Z");

        let a = aggregate_profile("agent://x", &c, &[s1.clone(), s2.clone()], "T1");
        let b = aggregate_profile("agent://x", &c, &[s1, s2], "T2");

        // computed_at differs; every aggregate field must be identical.
        for k in [
            "sessions_total",
            "sessions_self",
            "sessions_runtime",
            "sessions_countersigned",
            "actions_total",
            "approvals_total",
            "tools_exercised",
            "span_first",
            "span_last",
            "checkpoint_root",
            "checkpoint_tree_size",
        ] {
            assert_eq!(a[k], b[k], "field {k} must be deterministic");
        }
        assert_eq!(a["sessions_total"], 2);
        assert_eq!(a["sessions_runtime"], 1);
        assert_eq!(a["actions_total"], 15);
        assert_eq!(a["approvals_total"], 2);
        // tools: sorted distinct union
        assert_eq!(
            a["tools_exercised"],
            serde_json::json!(["Bash(git:*)", "Edit(*)", "Read(*)"])
        );
        assert_eq!(a["span_first"], "2026-07-01T00:00:00Z");
        assert_eq!(a["span_last"], "2026-07-06T00:00:00Z");
    }

    #[test]
    fn inflated_claim_is_detected_by_recompute() {
        let c = cp(7, 100, "sha256:aa");
        let honest = aggregate_profile(
            "agent://x",
            &c,
            &[session("runtime", 10, &["Edit(*)"], "2026-07-01T00:00:00Z")],
            "T",
        );
        // The liar pads their numbers.
        let mut inflated = honest.clone();
        inflated["sessions_total"] = serde_json::json!(40);
        inflated["actions_total"] = serde_json::json!(9000);

        let recomputed = aggregate_profile(
            "agent://x",
            &c,
            &[session("runtime", 10, &["Edit(*)"], "2026-07-01T00:00:00Z")],
            "T2",
        );
        let mut mismatches = 0;
        for (k, rv) in recomputed.as_object().unwrap() {
            if k == "computed_at" {
                continue;
            }
            if inflated.get(k) != Some(rv) {
                mismatches += 1;
            }
        }
        assert_eq!(mismatches, 2, "exactly the two padded fields must mismatch");
    }
}
