use std::collections::HashMap;

use sha2::{Digest, Sha256};
use treeship_core::{
    attestation::{Envelope, Verifier},
    statements::{
        check_resolution,
        invitation::InvitationStatement,
        payload_type, payload_type_v2, resolve_grant_chain,
        session_participant::{verify_participant_envelope, SessionParticipantStatement},
        verify_effect, verify_grant_chain, verify_mandate, ActionStatement, ActionStatementV2,
        ApprovalScope, ApprovalStatement, DeadlineEvent, DecisionStatement, EffectConfidence,
        EffectFinality, EffectVerdict, HandoffStatement, MandateVerdict, NoRevocationSource,
        NoWitnessAuthority, ReceiptStatement, ResolutionStatus,
    },
    storage::Store,
    trust::TrustRootStore,
};

use crate::{ctx, printer::Printer};

/// Result of verifying one artifact.
struct ArtifactCheck {
    id: String,
    payload_type: String,
    actor_or_sys: String,
    outcome: Outcome,
    reason: Option<String>,
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Pass,
    Fail,
}

/// Rich per-step data extracted from each artifact in the chain.
struct StepInfo {
    index: usize,
    id: String,
    actor: String,
    action: String,
    timestamp: String,
    payload_type: String,
    // From meta.execution
    output_digest: Option<String>,
    output_lines: Option<u64>,
    exit_code: Option<i64>,
    elapsed_ms: Option<f64>,
    // From meta.state_changes
    files_changed: Option<u64>,
    // Approval info
    approver: Option<String>,
    approval_id: Option<String>,
    description: Option<String>,
    // Handoff info
    handoff_from: Option<String>,
    handoff_to: Option<String>,
    // Parent linkage
    parent_id: Option<String>,
    // Approval nonce on action
    approval_nonce: Option<String>,
    // Decision info
    decision_model: Option<String>,
    decision_tokens_in: Option<u64>,
    decision_tokens_out: Option<u64>,
    decision_summary: Option<String>,
    decision_confidence: Option<f64>,
    // action/v2 effect verdict (operational confidence, reconciled by
    // verify_effect). Present only for treeship/action/v2 receipts carrying an
    // effect block.
    effect_effective: Option<EffectConfidence>,
    effect_claimed: Option<EffectConfidence>,
    effect_downgraded: bool,
    effect_trusted_witnesses: usize,
    // action/v2 mandate verdict (authority: in scope, in window, not revoked).
    // Sibling of the effect verdict: effect asks "did it land", authority asks
    // "was it allowed". A receipt can be impeccably signed and still record an
    // action outside its grant.
    mandate_verdict: Option<MandateSummary>,
    // action/v2 delegation chain outcome, when the mandate carries ancestors.
    chain_summary: Option<ChainSummary>,
    // action/v2 lifecycle stage: how far the state change got, as opposed to
    // how well the effect is evidenced.
    effect_finality: Option<EffectFinality>,
    effect_finality_claimed: Option<EffectFinality>,
    // action/v2 resolution obligation, evaluated against the clock at print time.
    resolution: Option<ResolutionStatus>,
    // action/v2 runtime identity (who/what executed the action).
    runtime_model: Option<String>,
}

/// Delegation-chain outcome for display. Distinct from the mandate verdict:
/// the mandate asks whether THIS hop was inside its grant, the chain asks
/// whether the grant itself descends legitimately from a root.
#[derive(Clone)]
enum ChainSummary {
    /// No ancestors carried. A single-hop mandate makes no lineage claim, so
    /// there is nothing to check -- reported as absent, not as a pass.
    NotClaimed,
    /// Links resolved and every hop attenuates.
    Holds { hops: usize },
    /// Links resolved but a hop widens scope, extends expiry, jumps depth, or
    /// changes audience.
    Widened(String),
    /// The carried set could not be assembled into a chain at all.
    Unresolvable(String),
}

/// Flattened mandate outcome for display. `Unverified` carries the layers we
/// could not check rather than silently reading as a pass.
#[derive(Clone)]
enum MandateSummary {
    Pass,
    Unverified(Vec<String>),
    Fail(Vec<String>),
}

/// Human label for an effect confidence level.
///
/// NOTE: this does *not* match the wire form, despite what this comment used to
/// claim. `EffectConfidence` serializes `snake_case`, so a receipt carries
/// `not_verified` while `--format json` reports `not-verified`. A consumer
/// round-tripping between the two breaks on exactly that value.
///
/// Left as-is deliberately: changing it is a breaking change to a field
/// `--format json` has emitted since v0.21, and that is a decision to make on
/// purpose rather than as a side effect of adding a neighbouring field. New
/// labels (see `finality_label`) follow the wire form.
fn effect_label(c: EffectConfidence) -> &'static str {
    match c {
        EffectConfidence::Verified => "verified",
        EffectConfidence::Partial => "partial",
        EffectConfidence::Ambiguous => "ambiguous",
        EffectConfidence::Unknown => "unknown",
        EffectConfidence::NotVerified => "not-verified",
    }
}

/// Reconciled effect verdict for an envelope, if it is a treeship/action/v2
/// receipt that actually carries an effect block. `None` for any other
/// artifact (or a v2 action with no effect), so callers surface the effect
/// line only where there is an effect to judge. Uses [`NoWitnessAuthority`]:
/// the CLI wires no witness trust yet, so witnesses give no evidence lift --
/// the honest, fail-closed default across every output format.
fn v2_effect_verdict(env: &Envelope) -> Option<EffectVerdict> {
    if env.payload_type != payload_type_v2("action") {
        return None;
    }
    let stmt = env.unmarshal_statement::<ActionStatementV2>().ok()?;
    stmt.effect.as_ref()?;
    Some(verify_effect(&stmt, &NoWitnessAuthority))
}

/// Reconciled mandate verdict for an envelope, if it is a treeship/action/v2
/// receipt. `None` for anything else. Uses [`NoRevocationSource`]: the CLI
/// wires no revocation resolver yet, so that layer resolves Unknown and the
/// verdict degrades to Unverified -- claiming a grant is live because we never
/// looked would be exactly the false pass this verifier exists to refuse.
fn v2_mandate_summary(env: &Envelope, verifier: Option<&Verifier>) -> Option<MandateSummary> {
    if env.payload_type != payload_type_v2("action") {
        return None;
    }
    let stmt = env.unmarshal_statement::<ActionStatementV2>().ok()?;
    let mut verdict = match verify_mandate(&stmt, &NoRevocationSource) {
        MandateVerdict::Pass => MandateSummary::Pass,
        MandateVerdict::Unverified(r) => MandateSummary::Unverified(r),
        MandateVerdict::Fail(r) => MandateSummary::Fail(r),
    };

    // Holder binding needs something `verify_mandate` cannot see: the key that
    // actually signed this envelope. The statement names who was entitled to
    // act; only the envelope says who did.
    if let Some(expected) = stmt.mandate.grantee.as_deref().filter(|g| !g.is_empty()) {
        match signer_pubkey_b64(env, verifier) {
            Some(actual) if actual == expected => {}
            Some(actual) => {
                // A receipt signed by a key the grant did not name. Both
                // signatures can be genuine and this still be someone spending
                // authority that was never issued to them.
                let reason = format!(
                    "receipt was signed by {actual} but the grant names {expected} as its holder"
                );
                verdict = match verdict {
                    MandateSummary::Fail(mut r) => {
                        r.push(reason);
                        MandateSummary::Fail(r)
                    }
                    _ => MandateSummary::Fail(vec![reason]),
                };
            }
            None => {
                // The signing key is not resolvable here, so entitlement is a
                // layer we could not check -- reported, never assumed clear.
                let reason =
                    "grant names a holder, but the signing key could not be resolved to compare"
                        .to_string();
                verdict = match verdict {
                    MandateSummary::Fail(r) => MandateSummary::Fail(r),
                    MandateSummary::Unverified(mut r) => {
                        r.push(reason);
                        MandateSummary::Unverified(r)
                    }
                    MandateSummary::Pass => MandateSummary::Unverified(vec![reason]),
                };
            }
        }
    }
    Some(verdict)
}

/// Base64url-no-pad public key of whoever signed `env`, resolved through the
/// verifier's trusted key map. `None` when there is no verifier, no signature,
/// or the key id is not one we hold.
fn signer_pubkey_b64(env: &Envelope, verifier: Option<&Verifier>) -> Option<String> {
    let v = verifier?;
    let keyid = env.signatures.first()?.keyid.as_str();
    let key = v.public_key(keyid)?;
    use base64::Engine as _;
    Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.to_bytes()))
}

/// Resolve and judge the delegation chain behind a v2 action's mandate.
///
/// Two steps that only mean something together: `resolve_grant_chain` derives
/// the order from signed parent links (so the carrier cannot choose which
/// pairs get compared), then `verify_grant_chain` checks attenuation across
/// those pairs. Order first, then invariants.
fn v2_chain_summary(env: &Envelope) -> Option<ChainSummary> {
    if env.payload_type != payload_type_v2("action") {
        return None;
    }
    let stmt = env.unmarshal_statement::<ActionStatementV2>().ok()?;
    if stmt.mandate.chain.is_empty() {
        return Some(ChainSummary::NotClaimed);
    }
    Some(match resolve_grant_chain(&stmt.mandate) {
        Err(e) => ChainSummary::Unresolvable(e.to_string()),
        Ok(chain) => match verify_grant_chain(chain.as_slice()) {
            Ok(()) => ChainSummary::Holds { hops: chain.len() },
            Err(e) => ChainSummary::Widened(e.to_string()),
        },
    })
}

/// Serialize an effect verdict for `--json` output.
fn effect_verdict_json(v: &EffectVerdict) -> serde_json::Value {
    let downgraded = v
        .claimed_confidence
        .map(|c| c != v.effective_confidence)
        .unwrap_or(false);
    // Finality is reported beside confidence, never merged into it. They
    // answer different questions -- how far the change got, and how well that
    // is evidenced -- and a receipt can be honest on one axis while
    // overclaiming the other.
    let finality_downgraded = v
        .claimed_finality
        .map(|c| Some(c) != v.effective_finality)
        .unwrap_or(false);
    serde_json::json!({
        "effective_confidence": effect_label(v.effective_confidence),
        "claimed_confidence": v.claimed_confidence.map(effect_label),
        "downgraded": downgraded,
        "trusted_witnesses": v.trusted_witnesses,
        "effective_finality": v.effective_finality.map(finality_label),
        "claimed_finality": v.claimed_finality.map(finality_label),
        "finality_downgraded": finality_downgraded,
        "notes": v.notes,
    })
}

/// Human label for a lifecycle stage, matching the wire snake_case.
fn finality_label(f: EffectFinality) -> &'static str {
    match f {
        EffectFinality::NotAttempted => "not_attempted",
        EffectFinality::Initiated => "initiated",
        EffectFinality::Finalized => "finalized",
        EffectFinality::Failed => "failed",
        EffectFinality::Indeterminate => "indeterminate",
    }
}

/// Serialize an effect's resolution obligation for `--json` output.
///
/// `indefinite` is carried as its own outcome rather than folded into
/// `resolved`: an unresolved effect with no declared deadline is the shape that
/// goes unnoticed for months, and the machine surface is where a monitor would
/// have to catch it.
fn resolution_status_json(s: &ResolutionStatus) -> serde_json::Value {
    match s {
        ResolutionStatus::Resolved => serde_json::json!({ "outcome": "resolved" }),
        ResolutionStatus::Indefinite => serde_json::json!({ "outcome": "indefinite" }),
        ResolutionStatus::Pending { seconds_remaining } => serde_json::json!({
            "outcome": "pending",
            "seconds_remaining": seconds_remaining,
        }),
        ResolutionStatus::Breached {
            on_deadline,
            seconds_overdue,
        } => serde_json::json!({
            "outcome": "breached",
            "on_deadline": match on_deadline {
                DeadlineEvent::Timeout => "timeout",
                DeadlineEvent::Escalate => "escalate",
                DeadlineEvent::Tombstone => "tombstone",
                DeadlineEvent::Inherit => "inherit",
            },
            "seconds_overdue": seconds_overdue,
        }),
        ResolutionStatus::BadDeadline => serde_json::json!({ "outcome": "bad_deadline" }),
    }
}

/// Evaluate the resolution obligation for a v2 action envelope at `now_unix`.
/// `None` for anything that is not a v2 action or carries no effect block.
fn v2_resolution_status(env: &Envelope, now_unix: i64) -> Option<ResolutionStatus> {
    if env.payload_type != payload_type_v2("action") {
        return None;
    }
    let stmt = env.unmarshal_statement::<ActionStatementV2>().ok()?;
    stmt.effect.as_ref().map(|e| check_resolution(e, now_unix))
}

/// Serialize the authority verdict for `--json` output.
///
/// `unverified` is a distinct outcome from `pass`, not a softer pass: it means
/// a layer could not be checked at all (today, revocation). Machine consumers
/// gating on this must be able to tell those apart, so the outcome string is
/// carried verbatim rather than collapsed to a boolean.
fn mandate_summary_json(m: &MandateSummary) -> serde_json::Value {
    match m {
        MandateSummary::Pass => serde_json::json!({
            "outcome": "pass",
            "reasons": [],
        }),
        MandateSummary::Unverified(reasons) => serde_json::json!({
            "outcome": "unverified",
            "reasons": reasons,
        }),
        MandateSummary::Fail(reasons) => serde_json::json!({
            "outcome": "fail",
            "reasons": reasons,
        }),
    }
}

/// Serialize the delegation-chain outcome for `--json` output.
///
/// `not_claimed` is reported rather than omitted: a mandate that carries no
/// ancestors made no lineage claim, which is different from one whose chain we
/// checked and accepted. Silence would let a consumer read the absence as a pass.
fn chain_summary_json(c: &ChainSummary) -> serde_json::Value {
    match c {
        ChainSummary::NotClaimed => serde_json::json!({
            "outcome": "not_claimed",
        }),
        ChainSummary::Holds { hops } => serde_json::json!({
            "outcome": "holds",
            "hops": hops,
        }),
        ChainSummary::Widened(why) => serde_json::json!({
            "outcome": "widened",
            "detail": why,
        }),
        ChainSummary::Unresolvable(why) => serde_json::json!({
            "outcome": "unresolvable",
            "detail": why,
        }),
    }
}

pub fn run(
    target: &str,
    no_chain: bool,
    max_depth: usize,
    full: bool,
    config: Option<&str>,
    printer: &Printer,
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

    // Local keys cover artifacts produced here; pinned roots cover artifacts
    // pulled or imported from trusted counterparties.
    let trust = TrustRootStore::open_default_or_empty()?;
    let verifier = crate::commands::verifier::from_local_and_trust(&ctx.keys, &trust)?
        .ok_or("no local or trusted verification keys are configured")?;

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
            if depth >= max_depth {
                break;
            }
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
            Ok(r) => r,
            Err(_) => {
                checks.push(ArtifactCheck {
                    id: id.clone(),
                    payload_type: "unknown".into(),
                    actor_or_sys: "\u{2014}".into(),
                    outcome: Outcome::Fail,
                    reason: Some("not found in local storage".to_string()),
                });
                continue;
            }
        };

        let check = verify_one(&verifier, &ctx.storage, &rec.envelope, id);
        chain_envelopes.push((id.clone(), rec.envelope));
        checks.push(check);
    }

    // Nonce binding: for each action with approval_nonce, find the matching
    // approval and verify the binding is valid.
    let nonce_checks = verify_nonce_bindings(&chain_envelopes, &ctx.storage, &ctx.config_path);
    checks.extend(nonce_checks);

    // Signed chain-linkage: the walk followed unsigned storage metadata, so
    // cross-check each child's signed parent_id before claiming the chain is
    // intact. A broken linkage is tampering even when every artifact verifies.
    let (linkage_ok, linkage_detail) = if no_chain {
        (true, String::new())
    } else {
        compute_chain_linkage(&chain_envelopes)
    };

    // Print results.
    let total = checks.len();
    let passed = checks.iter().filter(|c| c.outcome == Outcome::Pass).count();
    let failed = total - passed;

    if printer.format == crate::printer::Format::Json {
        // Effect verdicts are keyed by artifact id so the signature-focused
        // `checks` list can carry the operational-confidence verdict alongside
        // each v2 action without disturbing the nonce-binding synthetic checks.
        let effect_by_id: HashMap<String, serde_json::Value> = chain_envelopes
            .iter()
            .filter_map(|(id, env)| {
                v2_effect_verdict(env).map(|v| (id.clone(), effect_verdict_json(&v)))
            })
            .collect();

        // Authority and delegation-chain outcomes, keyed the same way. These
        // exist in the human output already; omitting them here would leave the
        // machine-readable surface -- the one CI gates actually consume --
        // unable to see that an action fell outside its grant.
        let authority_by_id: HashMap<String, serde_json::Value> = chain_envelopes
            .iter()
            .filter_map(|(id, env)| {
                v2_mandate_summary(env, Some(&verifier))
                    .map(|m| (id.clone(), mandate_summary_json(&m)))
            })
            .collect();
        let delegation_by_id: HashMap<String, serde_json::Value> = chain_envelopes
            .iter()
            .filter_map(|(id, env)| {
                v2_chain_summary(env).map(|c| (id.clone(), chain_summary_json(&c)))
            })
            .collect();

        // Resolution is time-dependent, so the clock is read once here and
        // passed down. Reading it per-envelope would let two effects in the
        // same run be judged against different "now"s.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let resolution_by_id: HashMap<String, serde_json::Value> = chain_envelopes
            .iter()
            .filter_map(|(id, env)| {
                v2_resolution_status(env, now_unix)
                    .map(|r| (id.clone(), resolution_status_json(&r)))
            })
            .collect();

        // Gate fields. `authority_ok` is false only for an outright Fail:
        // `unverified` means a layer could not be checked, and treating "did not
        // look" as "found a violation" would make the flag useless the moment
        // any receipt lacks a revocation resolver -- which is every receipt
        // today.
        //
        // But a lone boolean makes "checked and clean" indistinguishable from
        // "never checked", which is the shape a gate reading only this field
        // would mistake for safety. So the counts travel with it and the caller
        // picks its own policy: a CI job for a low-stakes read can accept
        // unverified, one gating a payment should not.
        let summaries: Vec<MandateSummary> = chain_envelopes
            .iter()
            .filter_map(|(_, env)| v2_mandate_summary(env, Some(&verifier)))
            .collect();
        let authority_ok = !summaries
            .iter()
            .any(|m| matches!(m, MandateSummary::Fail(_)));
        let authority_unverified = summaries
            .iter()
            .filter(|m| matches!(m, MandateSummary::Unverified(_)))
            .count();
        let authority_checked = summaries.len();

        let out: Vec<_> = checks
            .iter()
            .map(|c| {
                let mut obj = serde_json::json!({
                    "id":      c.id,
                    "outcome": if c.outcome == Outcome::Pass { "pass" } else { "fail" },
                    "reason":  c.reason,
                });
                if let Some(effect) = effect_by_id.get(&c.id) {
                    obj["effect"] = effect.clone();
                }
                if let Some(authority) = authority_by_id.get(&c.id) {
                    obj["authority"] = authority.clone();
                }
                if let Some(delegation) = delegation_by_id.get(&c.id) {
                    obj["delegation_chain"] = delegation.clone();
                }
                if let Some(resolution) = resolution_by_id.get(&c.id) {
                    obj["resolution"] = resolution.clone();
                }
                obj
            })
            .collect();
        printer.json(&serde_json::json!({
            "outcome": if failed == 0 && linkage_ok { "pass" } else { "fail" },
            "total": total, "passed": passed, "failed": failed,
            "chain_linkage_ok": linkage_ok,
            "chain_linkage_detail": if linkage_ok { serde_json::Value::Null } else { serde_json::json!(linkage_detail) },
            "authority_ok": authority_ok,
            // How many v2 mandates were judged, and how many of those could not
            // be fully checked. `authority_ok: true` with
            // `authority_unverified > 0` means nothing was caught, not that
            // nothing is wrong.
            "authority_checked": authority_checked,
            "authority_unverified": authority_unverified,
            "checks": out,
        }));
        if failed > 0 || !linkage_ok {
            std::process::exit(1);
        }
        return Ok(());
    }

    // --- Full chain timeline display ---
    if full {
        let chain_ok = print_full_timeline(
            &chain_envelopes,
            &checks,
            &ctx.storage,
            &verifier,
            printer,
            target,
            linkage_ok,
            &linkage_detail,
        );
        if failed > 0 || !chain_ok {
            std::process::exit(1);
        }
        return Ok(());
    }

    // --- Improved short output ---
    let chain_count = chain_envelopes.len();
    if !linkage_ok {
        printer.warn(
            "chain SIGNED LINKAGE BROKEN — possible tampering",
            &[("detail", &linkage_detail)],
        );
        printer.blank();
        std::process::exit(1);
    }
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

            // Whether the actor is proven (signed by the actor's registered,
            // AgentCert-pinned per-agent key) or merely asserted (free-text
            // label signed by the shared key). The signer is the envelope's key.
            let signer_kid = env
                .signatures
                .first()
                .map(|s| s.keyid.clone())
                .unwrap_or_default();
            let proof = |actor: &str| -> (&'static str, String) {
                let label = if crate::commands::capability::actor_proven(&ctx, actor, &signer_kid) {
                    "proven (key-bound)".to_string()
                } else {
                    "asserted".to_string()
                };
                ("actor proof", label)
            };

            if let Ok(action) = env.unmarshal_statement::<ActionStatement>() {
                fields.push(("actor", action.actor.clone()));
                fields.push(proof(&action.actor));
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
                fields.push(proof(&handoff.from));
                fields.push(("time", handoff.timestamp.clone()));
            } else if let Ok(receipt) = env.unmarshal_statement::<ReceiptStatement>() {
                fields.push(("system", receipt.system.clone()));
                fields.push(("time", receipt.timestamp.clone()));
            } else if let Ok(decision) = env.unmarshal_statement::<DecisionStatement>() {
                fields.push(("actor", decision.actor.clone()));
                fields.push(proof(&decision.actor));
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
        printer.failure(
            "verification failed",
            &[
                ("outcome", "fail"),
                ("passed", &passed.to_string()),
                ("failed", &failed.to_string()),
            ],
        );

        // Per-artifact detail.
        for c in &checks {
            let icon = if c.outcome == Outcome::Pass {
                "  \u{2713}"
            } else {
                "  \u{2717}"
            };
            let short_type = c
                .payload_type
                .strip_prefix("application/vnd.treeship.")
                .and_then(|s| s.strip_suffix(".v1+json"))
                .unwrap_or(&c.payload_type);
            let line = format!(
                "{icon}  {}  {short_type}  {}",
                &c.id[..16.min(c.id.len())],
                c.actor_or_sys
            );
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

/// Verify the SIGNED linkage of a chain: each child's parent_id (read from
/// its verified envelope) must name the artifact walked as its parent. The
/// walk follows UNSIGNED storage metadata, editable by a local attacker to
/// truncate or rearrange a chain of individually-valid artifacts; this is the
/// check that turns "no tampering detected" from a claim into a fact. `chain`
/// is in walk order (root first). Returns (ok, detail-on-first-break).
fn compute_chain_linkage(chain: &[(String, Envelope)]) -> (bool, String) {
    for pair in chain.windows(2) {
        let (parent_id, _) = &pair[0];
        let (child_id, child_env) = &pair[1];
        let signed_parent = child_env
            .unmarshal_statement::<serde_json::Value>()
            .ok()
            .and_then(|v| {
                v.get("parentId")
                    .or_else(|| v.get("parent_id"))
                    // session-participant/v1 names the signed edge after the
                    // protocol object it extends. Treat that invitation ref as
                    // its parent instead of trusting unsigned storage metadata.
                    .or_else(|| v.get("invitation_ref"))
                    // receipt.v1 (the session record minted by
                    // `mint_session_record`) carries no top-level parentId. It
                    // names the session-close artifact it seals as its signed
                    // `subject.artifactId`, and storage records that same id as
                    // the parent. That IS a signed edge -- it is inside the
                    // DSSE payload -- so reading it here is not a relaxation:
                    // a mismatch still fails below. Before this, every receipt
                    // landing mid-chain reported "possible tampering" on
                    // correctly-signed evidence.
                    .or_else(|| {
                        v.get("subject")
                            .and_then(|s| s.get("artifactId").or_else(|| s.get("artifact_id")))
                    })
                    .and_then(|p| p.as_str())
                    .map(str::to_string)
            });
        if signed_parent.as_deref() != Some(parent_id.as_str()) {
            return (
                false,
                format!(
                    "{} claims parent {}, walked from {}",
                    &child_id[..child_id.len().min(16)],
                    signed_parent.as_deref().unwrap_or("(none)"),
                    &parent_id[..parent_id.len().min(16)]
                ),
            );
        }
    }
    (true, String::new())
}

fn print_full_timeline(
    chain: &[(String, Envelope)],
    checks: &[ArtifactCheck],
    storage: &Store,
    verifier: &Verifier,
    printer: &Printer,
    target: &str,
    linkage_ok: bool,
    linkage_detail: &str,
) -> bool {
    // Returns whether the CHAIN is intact (no gaps + signed linkage). The
    // caller must exit nonzero when this is false, even if every individual
    // artifact verified — a broken linkage is tampering.
    let passed = checks.iter().filter(|c| c.outcome == Outcome::Pass).count();
    let failed = checks.len() - passed;

    // Build step info for each artifact in chain.
    let steps: Vec<StepInfo> = chain
        .iter()
        .enumerate()
        .map(|(i, (id, env))| extract_step_info(i + 1, id, env, storage, Some(verifier)))
        .collect();

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
    let _nonce_checks: Vec<&ArtifactCheck> = checks
        .iter()
        .filter(|c| c.payload_type == "nonce-binding")
        .collect();

    printer.info("  Verification summary");
    let rule = "\u{2500}".repeat(BOX_WIDTH);
    printer.info(&format!("  {rule}"));

    // Signatures
    let sig_status = if checks
        .iter()
        .any(|c| c.outcome == Outcome::Fail && c.payload_type != "nonce-binding")
    {
        printer.red("\u{2717}  signatures      FAILED")
    } else {
        printer.green(&format!(
            "\u{2713}  signatures      all {} Ed25519 signatures valid",
            sig_count
        ))
    };
    printer.info(&format!("  {sig_status}"));

    // Content IDs
    let id_fail = checks.iter().any(|c| {
        c.outcome == Outcome::Fail
            && c.reason
                .as_deref()
                .is_some_and(|r| r.contains("ID mismatch"))
    });
    let id_status = if id_fail {
        printer.red("\u{2717}  content IDs     ID mismatch detected")
    } else {
        printer.green(&format!(
            "\u{2713}  content IDs     all {} artifact IDs match content",
            sig_count
        ))
    };
    printer.info(&format!("  {id_status}"));

    // Chain integrity: two independent properties.
    //   (a) no gaps  — every artifact in the walk was found and verified.
    //   (b) linkage  — each child's SIGNED parent_id (inside its verified
    //       envelope) equals its parent's id. The walk itself follows the
    //       UNSIGNED `parent_id` storage metadata, which a local attacker can
    //       edit to truncate or rearrange a chain of individually-valid
    //       artifacts; without (b), "no tampering detected" would be a check
    //       we never ran. We only claim tamper-freedom when (b) holds.
    let no_gaps = !checks.iter().any(|c| {
        c.outcome == Outcome::Fail && c.reason.as_deref().is_some_and(|r| r.contains("not found"))
    });
    let chain_ok = no_gaps && linkage_ok;
    let chain_status = if chain_ok {
        printer.green("\u{2713}  chain integrity no gaps, signed linkage verified")
    } else if !no_gaps {
        printer.red("\u{2717}  chain integrity gaps detected in chain")
    } else {
        printer.red(&format!(
            "\u{2717}  chain integrity SIGNED LINKAGE BROKEN — possible tampering ({linkage_detail})"
        ))
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
    let approval_checks: Vec<&ArtifactCheck> = checks
        .iter()
        .filter(|c| c.payload_type.starts_with("nonce-binding"))
        .collect();
    if !approval_checks.is_empty() {
        let any_fail = approval_checks.iter().any(|c| c.outcome == Outcome::Fail);
        let any_unscoped = approval_checks
            .iter()
            .any(|c| c.payload_type == "nonce-binding-unscoped");
        let any_scoped = approval_checks
            .iter()
            .any(|c| c.payload_type == "nonce-binding-scoped");

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
                printer.green(
                    "\u{2713}  approval scope   actor / action / subject matched approval scope"
                )
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
        let journal_check = checks
            .iter()
            .find(|c| c.payload_type == "replay-local-journal");
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
    chain_ok
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
        format!("{} . approval", step.actor)
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
        let lines_str = step
            .output_lines
            .map(|n| format!("{} lines", n))
            .unwrap_or_default();
        let exit_str = step
            .exit_code
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

    // Runtime identity (action/v2): what executed the action.
    if let Some(ref model) = step.runtime_model {
        print_box_line(&format!("runtime: {}", model), printer);
    }

    // Authority verdict (action/v2): was this action inside its grant, in
    // window, and not revoked? Printed before effect: an out-of-scope action
    // that definitely landed is worse news than one that maybe did not.
    match &step.mandate_verdict {
        Some(MandateSummary::Pass) => {
            print_box_line("authority: in scope, in window, not revoked", printer);
        }
        Some(MandateSummary::Unverified(reasons)) => {
            print_box_line(
                &format!("authority: unverified ({})", reasons.join("; ")),
                printer,
            );
        }
        Some(MandateSummary::Fail(reasons)) => {
            print_box_line(
                &format!("authority: INVALID ({})", reasons.join("; ")),
                printer,
            );
        }
        None => {}
    }

    // Delegation chain (action/v2). Printed under authority: a mandate can be
    // perfectly in scope for a grant that was never legitimately delegated.
    match &step.chain_summary {
        Some(ChainSummary::Holds { hops }) => {
            print_box_line(
                &format!("chain:     {hops} hop(s), attenuation holds"),
                printer,
            );
        }
        Some(ChainSummary::Widened(why)) => {
            print_box_line(&format!("chain:     WIDENED ({why})"), printer);
        }
        Some(ChainSummary::Unresolvable(why)) => {
            print_box_line(&format!("chain:     unresolvable ({why})"), printer);
        }
        // No ancestors carried: say nothing rather than imply a single-hop
        // mandate passed a check that never ran.
        Some(ChainSummary::NotClaimed) | None => {}
    }

    // Effect verdict (action/v2): operational confidence, reconciled against
    // evidence. Distinct from the signature check -- a valid signature over a
    // Verified claim still reads not-verified here when nothing backs it.
    if let Some(effective) = step.effect_effective {
        let mut line = format!("effect: {}", effect_label(effective));
        if step.effect_downgraded {
            if let Some(claimed) = step.effect_claimed {
                line.push_str(&format!(
                    "  (actor claimed {}, downgraded: no independent evidence)",
                    effect_label(claimed)
                ));
            }
        } else if step.effect_trusted_witnesses > 0 {
            line.push_str(&format!(
                "  ({} trusted witness{})",
                step.effect_trusted_witnesses,
                if step.effect_trusted_witnesses == 1 {
                    ""
                } else {
                    "es"
                }
            ));
        }
        print_box_line(&line, printer);
    }

    // Lifecycle stage (action/v2), printed under effect because it answers a
    // different question: effect grades the evidence, this says how far the
    // change actually got. "Accepted but never committed" is invisible when
    // those collapse into one line.
    if let Some(stage) = step.effect_finality {
        let mut line = format!("state:  {}", finality_label(stage));
        if let Some(claimed) = step.effect_finality_claimed {
            if Some(claimed) != step.effect_finality {
                line.push_str(&format!(
                    "  (actor claimed {}, downgraded: no independent evidence)",
                    finality_label(claimed)
                ));
            }
        }
        print_box_line(&line, printer);
    }

    // Resolution obligation. Only worth a line when something is still owed --
    // a resolved effect has nothing outstanding, and saying so every time
    // would bury the two cases that matter.
    match &step.resolution {
        Some(ResolutionStatus::Indefinite) => {
            print_box_line(
                "owed:   unresolved with no deadline (nothing will ever fire)",
                printer,
            );
        }
        Some(ResolutionStatus::Breached {
            on_deadline,
            seconds_overdue,
        }) => {
            print_box_line(
                &format!(
                    "owed:   OVERDUE by {}s, declared action: {}",
                    seconds_overdue,
                    match on_deadline {
                        DeadlineEvent::Timeout => "timeout",
                        DeadlineEvent::Escalate => "escalate",
                        DeadlineEvent::Tombstone => "tombstone",
                        DeadlineEvent::Inherit => "inherit",
                    }
                ),
                printer,
            );
        }
        Some(ResolutionStatus::Pending { seconds_remaining }) => {
            print_box_line(
                &format!("owed:   unresolved, {seconds_remaining}s left to resolve"),
                printer,
            );
        }
        Some(ResolutionStatus::BadDeadline) => {
            print_box_line("owed:   unresolved, deadline unparseable", printer);
        }
        Some(ResolutionStatus::Resolved) | None => {}
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
    let elapsed_str = step
        .elapsed_ms
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

fn determine_connector(
    current: &StepInfo,
    next: &StepInfo,
    _chain: &[(String, Envelope)],
) -> String {
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

fn extract_step_info(
    index: usize,
    id: &str,
    env: &Envelope,
    storage: &Store,
    verifier: Option<&Verifier>,
) -> StepInfo {
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
        effect_effective: None,
        effect_claimed: None,
        effect_downgraded: false,
        mandate_verdict: None,
        chain_summary: None,
        effect_finality: None,
        effect_finality_claimed: None,
        resolution: None,
        effect_trusted_witnesses: 0,
        runtime_model: None,
    };

    // Try action/v2 FIRST: a v2 payload also parses as v1 (serde ignores the
    // extra mandate/effect fields), so dispatch on the envelope payloadType
    // before the v1 attempt or the effect verdict is silently skipped.
    if env.payload_type == payload_type_v2("action") {
        if let Ok(stmt) = env.unmarshal_statement::<ActionStatementV2>() {
            info.actor = stmt.actor.clone();
            info.action = stmt.action.clone();
            info.timestamp = stmt.timestamp.clone();
            info.parent_id = stmt.parent_id.clone();
            if let Some(rt) = &stmt.runtime {
                info.runtime_model = rt.model.clone();
            }
            // Surface the effect line only when there is an effect to judge.
            info.mandate_verdict = v2_mandate_summary(env, verifier);
            info.chain_summary = v2_chain_summary(env);
            if let Some(verdict) = v2_effect_verdict(env) {
                info.effect_effective = Some(verdict.effective_confidence);
                info.effect_claimed = verdict.claimed_confidence;
                info.effect_trusted_witnesses = verdict.trusted_witnesses;
                info.effect_downgraded = verdict
                    .claimed_confidence
                    .map(|c| c != verdict.effective_confidence)
                    .unwrap_or(false);
                info.effect_finality = verdict.effective_finality;
                info.effect_finality_claimed = verdict.claimed_finality;
            }
            info.resolution = v2_resolution_status(
                env,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0),
            );
            if let Some(meta) = &stmt.meta {
                extract_meta_fields(&mut info, meta);
            }
            return info;
        }
    }

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
        if i > 0 && (bytes.len() - i).is_multiple_of(3) {
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

fn verify_one(
    verifier: &Verifier,
    storage: &Store,
    envelope: &Envelope,
    id: &str,
) -> ArtifactCheck {
    let actor_or_sys = extract_actor(envelope);
    let pt = envelope.payload_type.clone();

    // Participant envelopes deliberately carry canonical protocol signatures,
    // not ordinary DSSE PAE signatures: joining agent first, host second. The
    // generic verifier therefore rejects a correctly countersigned join. Route
    // this typed envelope through its protocol verifier and authenticate the
    // referenced invitation through the normal trust universe.
    if pt == payload_type("session-participant") {
        return verify_session_participant(verifier, storage, envelope, id, actor_or_sys);
    }

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

fn verify_session_participant(
    verifier: &Verifier,
    storage: &Store,
    envelope: &Envelope,
    id: &str,
    actor_or_sys: String,
) -> ArtifactCheck {
    let pt = envelope.payload_type.clone();
    let fail = |reason: String| ArtifactCheck {
        id: id.to_string(),
        payload_type: pt.clone(),
        actor_or_sys: actor_or_sys.clone(),
        outcome: Outcome::Fail,
        reason: Some(reason),
    };

    let participant: SessionParticipantStatement = match envelope.unmarshal_statement() {
        Ok(statement) => statement,
        Err(e) => return fail(format!("participant payload invalid: {e}")),
    };
    let invitation_record = match storage.read(&participant.invitation_ref) {
        Ok(record) => record,
        Err(e) => {
            return fail(format!(
                "referenced invitation {} is unavailable: {e}",
                participant.invitation_ref
            ))
        }
    };
    let invitation_result = match verifier.verify(&invitation_record.envelope) {
        Ok(result) => result,
        Err(e) => return fail(format!("invitation is not trusted: {e}")),
    };
    if invitation_result.artifact_id != participant.invitation_ref {
        return fail(format!(
            "invitation id mismatch: expected {}, derived {}",
            participant.invitation_ref, invitation_result.artifact_id
        ));
    }
    let invitation: InvitationStatement = match invitation_record.envelope.unmarshal_statement() {
        Ok(statement) => statement,
        Err(e) => return fail(format!("invitation payload invalid: {e}")),
    };
    if let Err(e) = verify_participant_envelope(envelope, &invitation.issuer) {
        return fail(e.to_string());
    }

    // The join command intentionally keeps the pending artifact id stable when
    // the host appends signature #2. Recreate the pending envelope to retain a
    // content-address check without falsely hashing the finalized bytes.
    let mut pending = envelope.clone();
    pending.signatures.truncate(1);
    let pending_bytes = match serde_json::to_vec(&pending) {
        Ok(bytes) => bytes,
        Err(e) => return fail(format!("participant envelope encoding failed: {e}")),
    };
    let digest = Sha256::digest(pending_bytes);
    let derived_id = format!("art_{}", hex::encode(&digest[..16]));
    if derived_id != id {
        return fail(format!(
            "participant id mismatch: stored as {id}, derived {derived_id}"
        ));
    }

    ArtifactCheck {
        id: id.to_string(),
        payload_type: pt,
        actor_or_sys,
        outcome: Outcome::Pass,
        reason: None,
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
            Ok(a) => a,
            Err(_) => continue,
        };
        let nonce = match &action.approval_nonce {
            Some(n) => n.clone(),
            None => continue, // no approval binding claimed
        };

        // Look up the approval: first in chain, then in storage.
        let approval = if let Some(a) = approvals_by_nonce.get(&nonce) {
            a.clone()
        } else {
            match find_approval_by_nonce(&nonce, storage) {
                Some(a) => a,
                None => {
                    checks.push(ArtifactCheck {
                        id: id.clone(),
                        payload_type: "nonce-binding".into(),
                        actor_or_sys: action.actor.clone(),
                        outcome: Outcome::Fail,
                        reason: Some(format!(
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
                    id: id.clone(),
                    payload_type: "nonce-binding".into(),
                    actor_or_sys: action.actor.clone(),
                    outcome: Outcome::Fail,
                    reason: Some(format!("approval expired at {} (now: {})", expires, now)),
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
                        id: id.clone(),
                        payload_type: "nonce-binding".into(),
                        actor_or_sys: action.actor.clone(),
                        outcome: Outcome::Fail,
                        reason: Some(reason),
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
                id: id.clone(),
                payload_type: "nonce-binding".into(),
                actor_or_sys: action.actor.clone(),
                outcome: Outcome::Fail,
                reason: Some(format!(
                    "nonce already consumed by {} in this package (package-local replay)",
                    short_id(prev)
                )),
            });
            continue;
        }
        nonce_consumed_by.insert(nonce.clone(), id.clone());

        // Binding + scope (if any) valid.
        checks.push(ArtifactCheck {
            id: id.clone(),
            payload_type: scope_tag.into(),
            actor_or_sys: action.actor.clone(),
            outcome: Outcome::Pass,
            reason: None,
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
                        id: id.clone(),
                        payload_type: "replay-local-journal".into(),
                        actor_or_sys: action.actor.clone(),
                        outcome,
                        reason: Some(detail),
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
pub(crate) fn check_scope_violation(
    scope: &ApprovalScope,
    action: &ActionStatement,
) -> Option<String> {
    if !scope.allowed_actors.is_empty() && !scope.allowed_actors.contains(&action.actor) {
        return Some(format!(
            "actor '{}' not in approval's allowed_actors: {:?}",
            action.actor, scope.allowed_actors
        ));
    }

    if !scope.allowed_actions.is_empty() && !scope.allowed_actions.contains(&action.action) {
        return Some(format!(
            "action '{}' not in approval's allowed_actions: {:?}",
            action.action, scope.allowed_actions
        ));
    }

    if !scope.allowed_subjects.is_empty() {
        // Match on whichever subject reference the action carries.
        // URI is the canonical form; artifact_id is a chain-internal
        // form. Either may appear in allowed_subjects.
        let observed = action
            .subject
            .uri
            .clone()
            .or_else(|| action.subject.artifact_id.clone())
            .or_else(|| action.subject.digest.clone());
        let matches = match observed.as_deref() {
            Some(s) => scope.allowed_subjects.iter().any(|allowed| allowed == s),
            None => false,
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
                "approval scope expired at {} (now: {})",
                valid_until, now
            ));
        }
    }

    // `scope.extra` carries additional signed constraints (documented example:
    // a max payment amount). This verifier does not know how to evaluate them,
    // and a verifier that cannot check a constraint must NOT report the action
    // as in-scope — otherwise a grant limited to `{"max_amount": 100}` would
    // verify as "scoped and enforced" while a $1M action passes. Fail closed:
    // an unenforceable constraint is itself a scope violation here, so the
    // operator is told compliance was not confirmed rather than trusting it.
    if let Some(extra) = &scope.extra {
        let non_empty = match extra {
            serde_json::Value::Object(m) => !m.is_empty(),
            serde_json::Value::Null => false,
            _ => true,
        };
        if non_empty {
            return Some(format!(
                "approval scope carries extra constraints this verifier cannot evaluate ({extra}); \
                 compliance NOT confirmed"
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

#[cfg(test)]
mod tests {
    use super::*;
    use treeship_core::statements::{ActionStatement, ApprovalScope, SubjectRef};

    // ── signed chain linkage: receipt.v1 subject edge ──────────────────
    //
    // `mint_session_record` writes the session-close artifact id BOTH as the
    // unsigned storage `parent_id` and as the signed `subject.artifactId`.
    // The linkage check must read the signed one. Regression guard for the
    // false "possible tampering" every mid-chain receipt used to report.

    /// Build a real signed receipt.v1 envelope whose subject names `subject`.
    fn signed_receipt(subject: Option<&str>) -> Envelope {
        use treeship_core::attestation::{sign, Ed25519Signer};
        use treeship_core::statements::ReceiptStatement;

        let mut stmt = ReceiptStatement::new("system://treeship-session", "session.v1");
        stmt.subject = subject.map(|id| SubjectRef {
            artifact_id: Some(id.to_string()),
            ..Default::default()
        });
        let signer = Ed25519Signer::generate("key_receipt_test").unwrap();
        sign("application/vnd.treeship.receipt.v1+json", &stmt, &signer)
            .unwrap()
            .envelope
    }

    #[test]
    fn receipt_subject_artifact_id_counts_as_signed_parent() {
        let parent = "art_1bd9b5b82f7a3de9994f462b2f886800";
        let chain = vec![
            (parent.to_string(), signed_receipt(None)),
            ("art_child".to_string(), signed_receipt(Some(parent))),
        ];
        let (ok, detail) = compute_chain_linkage(&chain);
        assert!(ok, "receipt subject edge should satisfy linkage: {detail}");
    }

    #[test]
    fn receipt_subject_naming_another_artifact_still_breaks() {
        // The subject is an ACCEPTED field, not a bypass: pointing it at
        // something other than the walked parent must still fail, or this
        // change would have turned a tampering check into a rubber stamp.
        let chain = vec![
            ("art_real_parent".to_string(), signed_receipt(None)),
            (
                "art_child".to_string(),
                signed_receipt(Some("art_somewhere_else")),
            ),
        ];
        let (ok, detail) = compute_chain_linkage(&chain);
        assert!(!ok, "a subject naming a different artifact must break");
        assert!(detail.contains("art_somewhere_else"), "detail: {detail}");
    }

    #[test]
    fn receipt_without_subject_still_breaks() {
        // A receipt that names no parent at all cannot prove it belongs
        // where storage put it. Absence is not permission.
        let chain = vec![
            ("art_real_parent".to_string(), signed_receipt(None)),
            ("art_child".to_string(), signed_receipt(None)),
        ];
        let (ok, detail) = compute_chain_linkage(&chain);
        assert!(!ok, "missing subject must not pass linkage");
        assert!(detail.contains("(none)"), "detail: {detail}");
    }

    // ── action/v2 effect verdict wiring ────────────────────────────────
    #[test]
    fn v2_receipt_effect_verdict_reaches_step_info_and_downgrades() {
        use treeship_core::attestation::{sign, Ed25519Signer};
        use treeship_core::statements::{
            payload_type_v2, ActionStatementV2, Effect, EffectConfidence, Mandate, Revocation,
        };

        let mandate = Mandate {
            grant_id: "grant_1".into(),
            grantor: "key_parent".into(),
            grantee: None,
            issuer_sig: None,
            objective_hash: Some("sha256:abc".into()),
            scope: vec!["payments.charge".into()],
            audience: "acme".into(),
            parent_request_id: None,
            delegation_depth: 0,
            issued_at: "2026-07-20T10:00:00Z".into(),
            expiry: "2026-07-20T11:00:00Z".into(),
            max_delegation: 3,
            revocation: Revocation {
                path: "hub://acme/revocations".into(),
                revoked_at: None,
            },
            chain: Vec::new(),
        };
        let mut stmt = ActionStatementV2::new("agent://worker", "payments.charge", mandate);
        // Verified claim with NO independent evidence: must downgrade.
        stmt.effect = Some(Effect {
            output_hash: Some("sha256:out".into()),
            effect_confidence: Some(EffectConfidence::Verified),
            ..Default::default()
        });

        let signer = Ed25519Signer::generate("agent_worker").unwrap();
        let env = sign(&payload_type_v2("action"), &stmt, &signer)
            .unwrap()
            .envelope;

        // A v2 payload also parses as v1; this proves the dispatch runs the
        // effect verdict rather than silently taking the v1 branch.
        let dir = std::env::temp_dir().join("ts_verify_v2_effect_test");
        let store = Store::open(&dir).unwrap();
        let info = extract_step_info(0, "art_test", &env, &store, None);

        assert_eq!(info.actor, "agent://worker");
        assert_eq!(
            info.effect_claimed,
            Some(EffectConfidence::Verified),
            "claim should be captured"
        );
        assert_eq!(
            info.effect_effective,
            Some(EffectConfidence::NotVerified),
            "unbacked Verified must downgrade"
        );
        assert!(info.effect_downgraded, "downgrade flag must be set");
        assert_eq!(info.effect_trusted_witnesses, 0);

        // Same verdict must surface in the --json path via the shared helper.
        let verdict = v2_effect_verdict(&env).expect("v2 action with effect");
        let j = effect_verdict_json(&verdict);
        assert_eq!(j["effective_confidence"], "not-verified");
        assert_eq!(j["claimed_confidence"], "verified");
        assert_eq!(j["downgraded"], true);
        assert!(j["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n.as_str().unwrap().contains("downgraded")));

        // A non-v2 artifact yields no effect verdict at all.
        let v1 = act("agent://x", "tool.call", None);
        let v1_env = sign(
            &treeship_core::statements::payload_type("action"),
            &v1,
            &signer,
        )
        .unwrap()
        .envelope;
        assert!(v2_effect_verdict(&v1_env).is_none());
    }

    fn act(actor: &str, action: &str, subject_uri: Option<&str>) -> ActionStatement {
        let mut a = ActionStatement::new(actor, action);
        if let Some(uri) = subject_uri {
            a.subject = SubjectRef {
                uri: Some(uri.into()),
                ..Default::default()
            };
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

    // ── check_scope_violation: extra (unenforceable) constraints ───────
    #[test]
    fn scope_extra_constraint_fails_closed() {
        // A grant limited to `{"max_amount": 100}` must NOT verify as
        // "scoped and enforced" — this verifier can't evaluate the ceiling,
        // so it must report the action as out-of-scope rather than trusting
        // an unchecked constraint.
        let scope = ApprovalScope {
            extra: Some(serde_json::json!({ "max_amount": 100 })),
            ..Default::default()
        };
        let action = act("agent://payer", "payments.charge", None);
        let r = check_scope_violation(&scope, &action);
        assert!(
            r.is_some(),
            "unenforceable extra constraint must fail closed"
        );
        assert!(r.unwrap().contains("cannot evaluate"));
    }

    #[test]
    fn scope_empty_extra_object_passes() {
        // An empty `extra: {}` carries no constraint, so it must not trip
        // the fail-closed path.
        let scope = ApprovalScope {
            extra: Some(serde_json::json!({})),
            ..Default::default()
        };
        let action = act("agent://payer", "payments.charge", None);
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
        let action = act(
            "agent://deployer",
            "deploy.production",
            Some("env://staging"),
        );
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
        let action = act(
            "agent://deployer",
            "deploy.production",
            Some("env://production"),
        );
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
        action.subject = SubjectRef {
            artifact_id: Some("art_abc123".into()),
            ..Default::default()
        };
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
            allowed_actors: vec!["agent://deployer".into()],
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
            allowed_actors: vec!["agent://deployer".into()],
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
        let scope = ApprovalScope {
            max_actions: Some(1),
            ..Default::default()
        };
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

    // ── action/v2 mandate (authority) wiring ───────────────────────────
    #[test]
    fn v2_mandate_authority_reaches_step_info() {
        use treeship_core::attestation::{sign, Ed25519Signer};
        use treeship_core::statements::{payload_type_v2, ActionStatementV2, Mandate, Revocation};

        let mandate = |scope: Vec<String>| Mandate {
            grant_id: "grant_1".into(),
            grantor: "key_parent".into(),
            grantee: None,
            issuer_sig: None,
            objective_hash: None,
            scope,
            audience: "acme".into(),
            parent_request_id: None,
            delegation_depth: 0,
            issued_at: "2026-07-20T10:00:00Z".into(),
            expiry: "2026-07-20T11:00:00Z".into(),
            max_delegation: 3,
            revocation: Revocation {
                path: "hub://acme/revocations".into(),
                revoked_at: None,
            },
            chain: Vec::new(),
        };
        let signer = Ed25519Signer::generate("agent_worker").unwrap();
        let dir = std::env::temp_dir().join("ts_verify_v2_mandate_test");
        let store = Store::open(&dir).unwrap();

        // In scope: the revocation layer is still unresolvable (the CLI wires
        // no resolver), so the honest verdict is Unverified -- never Pass.
        let mut ok = ActionStatementV2::new(
            "agent://worker",
            "payments.charge",
            mandate(vec!["payments.charge".into()]),
        );
        ok.timestamp = "2026-07-20T10:30:00Z".into();
        ok.audience = Some("acme".into());
        let ok_env = sign(&payload_type_v2("action"), &ok, &signer)
            .unwrap()
            .envelope;
        let info = extract_step_info(0, "art_ok", &ok_env, &store, None);
        match info.mandate_verdict {
            Some(MandateSummary::Unverified(ref r)) => {
                assert!(
                    !r.is_empty(),
                    "unverified must name the layer it could not check"
                );
            }
            other => panic!(
                "expected Unverified without a revocation resolver, got {:?}",
                other.is_some()
            ),
        }

        // Out of scope: a signature over an unauthorized action must not read
        // as authorized anywhere in the output.
        let mut bad = ActionStatementV2::new(
            "agent://worker",
            "payments.refund",
            mandate(vec!["payments.charge".into()]),
        );
        bad.timestamp = "2026-07-20T10:30:00Z".into();
        bad.audience = Some("acme".into());
        let bad_env = sign(&payload_type_v2("action"), &bad, &signer)
            .unwrap()
            .envelope;
        let bad_info = extract_step_info(1, "art_bad", &bad_env, &store, None);
        match bad_info.mandate_verdict {
            Some(MandateSummary::Fail(ref r)) => {
                assert!(
                    r.iter().any(|x| x.contains("scope")),
                    "reason should name scope: {r:?}"
                );
            }
            _ => panic!("an out-of-scope action must produce a Fail verdict"),
        }

        // v1 artifacts carry no mandate and must not gain an authority line.
        let v1 = act("agent://x", "tool.call", None);
        let v1_env = sign(
            &treeship_core::statements::payload_type("action"),
            &v1,
            &signer,
        )
        .unwrap()
        .envelope;
        assert!(
            v2_mandate_summary(&v1_env, None).is_none(),
            "v1 receipts must not claim anything about authority"
        );
    }

    // ── action/v2 delegation chain wiring ──────────────────────────────
    #[test]
    fn v2_chain_summary_reports_holds_widened_and_absent() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use treeship_core::attestation::{sign, Ed25519Signer, Signer as _};
        use treeship_core::statements::{
            payload_type_v2, ActionStatementV2, Grant, Mandate, Revocation,
        };

        let signer = Ed25519Signer::generate("issuer").unwrap();
        let pk = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());

        let mk = |scope: Vec<&str>, depth: u32, parent: Option<&str>| -> Grant {
            let mut g = Grant {
                grant_id: String::new(),
                grantor: pk.clone(),
                grantee: None,
                issuer_sig: None,
                scope: scope.into_iter().map(String::from).collect(),
                audience: "acme".into(),
                parent_request_id: None,
                parent_grant_id: parent.map(String::from),
                delegation_depth: depth,
                issued_at: "2026-07-20T10:00:00Z".into(),
                expiry: "2026-07-20T11:00:00Z".into(),
                max_delegation: 3,
                objective_hash: None,
            };
            g.grant_id = g.derive_grant_id();
            g.issuer_sig = Some(g.sign_canonical(&signer).unwrap());
            g
        };

        let mandate_for = |leaf: &Grant, chain: Vec<Grant>| Mandate {
            grant_id: leaf.grant_id.clone(),
            grantor: pk.clone(),
            grantee: None,
            issuer_sig: leaf.issuer_sig.clone(),
            objective_hash: None,
            scope: leaf.scope.clone(),
            audience: "acme".into(),
            parent_request_id: None,
            delegation_depth: leaf.delegation_depth,
            issued_at: "2026-07-20T10:00:00Z".into(),
            expiry: "2026-07-20T11:00:00Z".into(),
            max_delegation: 3,
            revocation: Revocation {
                path: "hub://acme/revocations".into(),
                revoked_at: None,
            },
            chain,
        };

        let envelope_for = |m: Mandate, action: &str| {
            let mut st = ActionStatementV2::new("agent://worker", action, m);
            st.timestamp = "2026-07-20T10:30:00Z".into();
            st.audience = Some("acme".into());
            sign(&payload_type_v2("action"), &st, &signer)
                .unwrap()
                .envelope
        };

        // Holds: child narrows the parent's scope at depth+1.
        let root = mk(vec!["payments.*"], 0, None);
        let leaf = mk(vec!["payments.charge"], 1, Some(&root.grant_id));
        let env = envelope_for(
            mandate_for(&leaf, vec![leaf.clone(), root.clone()]), // carrier order: leaf first
            "payments.charge",
        );
        match v2_chain_summary(&env) {
            Some(ChainSummary::Holds { hops }) => assert_eq!(hops, 2),
            other => panic!("expected Holds, got {}", chain_label(&other)),
        }

        // Widened: child claims scope the parent never had. Must not pass
        // just because every individual grant is validly signed.
        let wroot = mk(vec!["payments.charge"], 0, None);
        let wleaf = mk(vec!["payments.*"], 1, Some(&wroot.grant_id));
        let wenv = envelope_for(
            mandate_for(&wleaf, vec![wroot.clone(), wleaf.clone()]),
            "payments.charge",
        );
        assert!(
            matches!(v2_chain_summary(&wenv), Some(ChainSummary::Widened(_))),
            "a scope-widening hop must be reported"
        );

        // Truncated: the leaf points at a parent that was not carried.
        let tenv = envelope_for(mandate_for(&leaf, vec![leaf.clone()]), "payments.charge");
        assert!(
            matches!(v2_chain_summary(&tenv), Some(ChainSummary::Unresolvable(_))),
            "a missing ancestor must be unresolvable, not silently rooted"
        );

        // No ancestors carried: no claim, so no line.
        let nenv = envelope_for(mandate_for(&leaf, vec![]), "payments.charge");
        assert!(matches!(
            v2_chain_summary(&nenv),
            Some(ChainSummary::NotClaimed)
        ));

        // v1 artifacts have no chain concept at all.
        let v1 = act("agent://x", "tool.call", None);
        let v1_env = sign(
            &treeship_core::statements::payload_type("action"),
            &v1,
            &signer,
        )
        .unwrap()
        .envelope;
        assert!(v2_chain_summary(&v1_env).is_none());
    }

    fn chain_label(c: &Option<ChainSummary>) -> String {
        match c {
            Some(ChainSummary::Holds { hops }) => format!("Holds({hops})"),
            Some(ChainSummary::Widened(w)) => format!("Widened({w})"),
            Some(ChainSummary::Unresolvable(w)) => format!("Unresolvable({w})"),
            Some(ChainSummary::NotClaimed) => "NotClaimed".into(),
            None => "None".into(),
        }
    }

    // ── --json surface ─────────────────────────────────────────────────
    // The human output already shows authority and chain. These lock the
    // machine-readable shape, because that is what CI gates read: a verifier
    // whose most consequential verdict is invisible to `--format json` reports
    // an out-of-scope action as clean.

    #[test]
    fn authority_json_distinguishes_pass_unverified_and_fail() {
        let pass = mandate_summary_json(&MandateSummary::Pass);
        assert_eq!(pass["outcome"], "pass");
        assert_eq!(pass["reasons"].as_array().unwrap().len(), 0);

        // Unverified must not serialize as a pass: "we did not look" and "we
        // looked and it was fine" are different facts.
        let unver = mandate_summary_json(&MandateSummary::Unverified(vec![
            "revocation unresolvable".into(),
        ]));
        assert_eq!(unver["outcome"], "unverified");
        assert_eq!(unver["reasons"][0], "revocation unresolvable");

        let fail = mandate_summary_json(&MandateSummary::Fail(vec!["out of scope".into()]));
        assert_eq!(fail["outcome"], "fail");
        assert_eq!(fail["reasons"][0], "out of scope");
    }

    #[test]
    fn chain_json_reports_not_claimed_rather_than_omitting_it() {
        // Absence of a lineage claim is itself the answer. If this serialized
        // to null/omitted, a consumer would read "no chain problems" from a
        // receipt whose chain was never checked.
        let nc = chain_summary_json(&ChainSummary::NotClaimed);
        assert_eq!(nc["outcome"], "not_claimed");

        let holds = chain_summary_json(&ChainSummary::Holds { hops: 3 });
        assert_eq!(holds["outcome"], "holds");
        assert_eq!(holds["hops"], 3);

        let widened = chain_summary_json(&ChainSummary::Widened("scope widens at hop 0->1".into()));
        assert_eq!(widened["outcome"], "widened");
        assert_eq!(widened["detail"], "scope widens at hop 0->1");

        let unres = chain_summary_json(&ChainSummary::Unresolvable(
            "parent grant is missing".into(),
        ));
        assert_eq!(unres["outcome"], "unresolvable");
        assert_eq!(unres["detail"], "parent grant is missing");
    }

    #[test]
    fn unresolved_effect_reaches_step_info_as_indefinite() {
        // End to end through a signed envelope, not just the serializer: an
        // effect that never says it landed and declares no deadline is the
        // 181-day pending row, and it has to be visible on the step card.
        use treeship_core::attestation::{sign, Ed25519Signer};
        use treeship_core::statements::{
            payload_type_v2, ActionStatementV2, Effect, EffectFinality, Mandate, Revocation,
        };

        let mandate = Mandate {
            grant_id: "grant_1".into(),
            grantor: "key_parent".into(),
            grantee: None,
            issuer_sig: None,
            objective_hash: None,
            scope: vec!["payments.charge".into()],
            audience: "acme".into(),
            parent_request_id: None,
            delegation_depth: 0,
            issued_at: "2026-07-20T10:00:00Z".into(),
            expiry: "2026-07-20T11:00:00Z".into(),
            max_delegation: 3,
            revocation: Revocation {
                path: "hub://acme/revocations".into(),
                revoked_at: None,
            },
            chain: Vec::new(),
        };
        let signer = Ed25519Signer::generate("agent_worker").unwrap();
        let dir = std::env::temp_dir().join("ts_verify_resolution_test");
        let store = Store::open(&dir).unwrap();

        let mut stmt = ActionStatementV2::new("agent://worker", "payments.charge", mandate);
        stmt.timestamp = "2026-07-20T10:30:00Z".into();
        stmt.audience = Some("acme".into());
        stmt.effect = Some(Effect {
            output_hash: Some("sha256:out".into()),
            // Accepted, not committed, nothing scheduled to fire.
            finality: Some(EffectFinality::Initiated),
            ..Default::default()
        });
        let env = sign(&payload_type_v2("action"), &stmt, &signer)
            .unwrap()
            .envelope;

        let info = extract_step_info(0, "art_pending", &env, &store, None);
        assert_eq!(
            info.effect_finality,
            Some(EffectFinality::Initiated),
            "the lifecycle stage must reach the step card"
        );
        assert!(
            matches!(info.resolution, Some(ResolutionStatus::Indefinite)),
            "an open effect with no deadline must report Indefinite, got {:?}",
            info.resolution.is_some()
        );
    }

    #[test]
    fn effect_json_carries_finality_beside_confidence() {
        use treeship_core::statements::{EffectFinality, EffectVerdict};

        // The two axes must both appear and stay distinguishable. A consumer
        // that can only see confidence cannot tell an accepted-but-uncommitted
        // write from a committed one.
        let v = EffectVerdict {
            effective_confidence: EffectConfidence::Partial,
            claimed_confidence: Some(EffectConfidence::Partial),
            trusted_witnesses: 0,
            notes: vec![],
            effective_finality: Some(EffectFinality::Indeterminate),
            claimed_finality: Some(EffectFinality::Finalized),
        };
        let j = effect_verdict_json(&v);
        assert_eq!(j["effective_confidence"], "partial");
        assert_eq!(j["downgraded"], false, "confidence was not downgraded");
        assert_eq!(j["effective_finality"], "indeterminate");
        assert_eq!(j["claimed_finality"], "finalized");
        assert_eq!(
            j["finality_downgraded"], true,
            "the finality downgrade must be visible independently of confidence"
        );
    }

    #[test]
    fn resolution_json_names_indefinite_and_breached() {
        use treeship_core::statements::DeadlineEvent;

        // `indefinite` is the pending-forever shape and must not serialize as
        // anything that reads like "fine".
        let indef = resolution_status_json(&ResolutionStatus::Indefinite);
        assert_eq!(indef["outcome"], "indefinite");

        let breached = resolution_status_json(&ResolutionStatus::Breached {
            on_deadline: DeadlineEvent::Escalate,
            seconds_overdue: 1234,
        });
        assert_eq!(breached["outcome"], "breached");
        assert_eq!(breached["on_deadline"], "escalate");
        assert_eq!(breached["seconds_overdue"], 1234);

        assert_eq!(
            resolution_status_json(&ResolutionStatus::Resolved)["outcome"],
            "resolved"
        );
        assert_eq!(
            resolution_status_json(&ResolutionStatus::BadDeadline)["outcome"],
            "bad_deadline"
        );
    }

    #[test]
    fn chain_errors_render_as_prose_not_debug_structs() {
        use treeship_core::statements::{ChainResolveError, GrantChainError};

        // These strings reach the operator verbatim. A Debug-formatted
        // `AncestorMissing { parent_grant_id: "grn_..." }` is a leaked internal
        // representation, not a diagnosis.
        let e = ChainResolveError::AncestorMissing {
            parent_grant_id: "grn_abc123".into(),
        };
        let s = e.to_string();
        assert!(s.contains("grn_abc123"), "must name the grant: {s}");
        assert!(!s.contains('{'), "must not be Debug-formatted: {s}");

        let g = GrantChainError::ScopeWidened { parent: 1 };
        let gs = g.to_string();
        assert!(
            gs.contains("scope"),
            "must name the violated invariant: {gs}"
        );
        assert!(!gs.contains('{'), "must not be Debug-formatted: {gs}");
    }
}
