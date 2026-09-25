//! `treeship judge`: the judge slot, from the command line.
//!
//! State plus typed questions in, typed answers out, held to a threshold,
//! and the decision signed as `judgement.v1`. The built-in judge is the
//! deterministic rules judge in `treeship_core::judge`; `--judge-url` sends
//! the same request to any HTTP judge that speaks the contract (a decision
//! model, an LLM judge, a classifier), so one receipt shape covers all of
//! them. The gate opts in with `TREESHIP_JUDGE=1` (rules) or
//! `TREESHIP_JUDGE=<url>`.
//!
//! No model is in the decision path unless the operator points at one. The
//! rules judge is replayable: a verifier re-running it on the receipt's
//! state gets the receipt's answer.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use serde_json::Value;
use treeship_core::{
    attestation::sign,
    judge::{
        check_answers, decide, digest, judgement_payload, questions_digest, rules_questions,
        Decision, Judge, JudgeError, JudgeRequest, JudgeResponse, Question, QuestionType,
        RulesJudge, ToolCallState,
    },
    statements::{payload_type, ReceiptStatement, SubjectRef},
    storage::Record,
};

use crate::{ctx, printer::Printer};
use treeship_core::judge::digest_bytes;

pub const SYSTEM: &str = "system://treeship-judge";

pub struct JudgeArgs {
    /// The harness's tool name. Required unless `resolve` is set.
    pub tool: Option<String>,
    pub capability: Option<String>,
    /// The tool input as JSON, or `@<file>`.
    pub input: Option<String>,
    /// Question keys to ask (default: every rules question).
    pub questions: Vec<String>,
    /// A JSON file of typed questions `{key: {type, instructions, options}}`.
    pub questions_file: Option<String>,
    pub judge_url: Option<String>,
    pub threshold: f64,
    pub set_by: Option<String>,
    pub bound: Option<f64>,
    pub subject: Option<String>,
    pub attest: bool,
    /// Exit 2 on `deny` and 3 on `ask`, so a shell gate can read the decision
    /// from the exit code. Off by default: the command is a query, and its
    /// decision is in the output.
    pub enforce: bool,
    /// `id@version` of the decision contract the judgement ran under.
    pub contract: Option<String>,
    /// Write the canonical state the receipt's `state_digest` commits to.
    pub state_out: Option<String>,
    /// Resolve an escalated or refused judgement instead of judging: the
    /// art_ id of the judgement.v1 receipt.
    pub resolve: Option<String>,
    /// Who decided (human://alice, or an agent:// for a stronger judge).
    pub by: Option<String>,
    /// allow | deny | route
    pub decision: Option<String>,
    pub route: Option<String>,
    pub reason: Option<String>,
    pub config: Option<String>,
}

/// `id@version` -> (id, Some(version)); `id` -> (id, None).
fn parse_contract(raw: &str) -> Result<(String, Option<String>), String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("--contract must not be empty".into());
    }
    match raw.split_once('@') {
        Some((id, v)) if !id.is_empty() && !v.is_empty() => {
            Ok((id.to_string(), Some(v.to_string())))
        }
        Some(_) => Err(format!(
            "--contract {raw:?}: use id@version, e.g. ticket-router@3"
        )),
        None => Ok((raw.to_string(), None)),
    }
}

/// `treeship judge --resolve <judgement> --by human://alice --decision allow`:
/// the human label, as its own signed artifact chained onto the session and
/// naming the judgement it resolves. A field a machine fills in would be the
/// self-report Treeship argues against; a receipt signed under the decider's
/// URI is a claim the decider made.
/// The resolution this store already holds for a judgement: its id, who
/// decided, and what.
fn existing_resolution(ctx: &ctx::Ctx, judgement_id: &str) -> Option<(String, String, String)> {
    let pt = treeship_core::statements::payload_type("receipt");
    for entry in ctx.storage.list_by_type(&pt) {
        let Ok(rec) = ctx.storage.read(&entry.id) else {
            continue;
        };
        let Ok(stmt) = rec.envelope.unmarshal_statement::<ReceiptStatement>() else {
            continue;
        };
        if stmt.kind != "judgement.resolution.v1" {
            continue;
        }
        let Some(p) = stmt.payload.as_ref() else {
            continue;
        };
        if p.get("judgement").and_then(|v| v.as_str()) != Some(judgement_id) {
            continue;
        }
        let by = p
            .get("by")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        let decision = p
            .get("decision")
            .and_then(|v| v.as_str())
            .unwrap_or("?")
            .to_string();
        return Some((entry.id.clone(), by, decision));
    }
    None
}

fn resolve(
    ctx: &ctx::Ctx,
    args: &JudgeArgs,
    judgement_id: &str,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let by = args
        .by
        .as_deref()
        .ok_or_else(|| crate::exit::usage("--by <URI> is required: who decided (human://alice)"))?;
    if !by.contains("://") {
        return Err(format!("--by must be a URI such as human://{by}").into());
    }
    let decision = args
        .decision
        .as_deref()
        .ok_or_else(|| crate::exit::usage("--decision is required: allow, deny or route"))?;
    if !matches!(decision, "allow" | "deny" | "route") {
        return Err(format!("--decision {decision:?}: use allow, deny or route").into());
    }
    if decision == "route" && args.route.is_none() {
        return Err("--decision route needs --route <name>".into());
    }
    let id = ctx.storage.resolve_id(judgement_id)?;
    let rec = ctx.storage.read(&id)?;
    let stmt: ReceiptStatement = rec.envelope.unmarshal_statement()?;
    if stmt.kind != "judgement.v1" {
        return Err(format!("{id} is a {} receipt, not a judgement.v1", stmt.kind).into());
    }
    if let Some((existing, by, decision)) = existing_resolution(ctx, &id) {
        return Err(format!(
            "{id} is already resolved: {existing} by {by} decided {decision}. A second resolution would contradict the record; the standing one is the decision"
        )
        .into());
    }
    let jp = stmt.payload.clone().unwrap_or(Value::Null);
    let outcome = jp.get("outcome").and_then(|v| v.as_str()).unwrap_or("");
    let effect = jp
        .get("effect")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let resolved_at = crate::commands::session::now_rfc3339();

    let mut payload = serde_json::json!({
        "schema": "judgement.resolution.v1",
        "judgement": id,
        "by": by,
        "decision": decision,
        "resolved_at": resolved_at,
    });
    if let Some(r) = &args.route {
        payload["route"] = Value::String(r.clone());
    }
    if let Some(r) = &args.reason {
        payload["reason"] = Value::String(r.clone());
    }
    // What this decision replaces, when it differs from what the judge's
    // answer led to.
    let contradicts = matches!(
        (decision, effect.as_deref()),
        ("allow", Some("deny"))
            | ("allow", Some("ask"))
            | ("deny", Some("allow"))
            | ("deny", Some("warn"))
    );
    if contradicts {
        payload["overrides"] = Value::String(effect.clone().unwrap_or_default());
    }
    treeship_core::predicates::validate("judgement.resolution.v1", Some(&payload))
        .map_err(|e| format!("predicate validation failed: {e}"))?;

    // Chain: onto the session head inside a session (the same rule the
    // judgements follow), else onto the judgement itself.
    let mut parent: Option<String> = None;
    if let Some(manifest) = crate::commands::session::load_session() {
        parent =
            crate::commands::session::session_chain_head(ctx, manifest.root_artifact_id.as_deref());
    }
    if parent.is_none() {
        parent = Some(id.clone());
    }
    let mut r = ReceiptStatement::new(by, "judgement.resolution.v1");
    r.payload = Some(payload);
    r.parent_id = parent.clone();
    r.subject = Some(SubjectRef {
        artifact_id: Some(id.clone()),
        ..Default::default()
    });
    let signer = ctx.keys.default_signer()?;
    let pt = payload_type("receipt");
    let result = sign(&pt, &r, signer.as_ref())?;
    ctx.storage.write(&Record {
        artifact_id: result.artifact_id.clone(),
        digest: result.digest.clone(),
        payload_type: pt,
        key_id: signer.key_id().to_string(),
        signed_at: r.timestamp.clone(),
        parent_id: parent,
        envelope: result.envelope,
        hub_url: None,
        anchors: Vec::new(),
    })?;
    let _ = std::fs::write(
        Path::new(&ctx.config.storage_dir).join(".last"),
        &result.artifact_id,
    );

    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "status": "ok",
            "resolution": result.artifact_id,
            "judgement": id,
            "by": by,
            "decision": decision,
            "route": args.route,
            "judgement_outcome": outcome,
            "judgement_effect": effect,
            "overrides": contradicts,
        }));
        return Ok(());
    }
    printer.success(
        "judgement resolved",
        &[
            ("resolution", result.artifact_id.as_str()),
            ("judgement", id.as_str()),
            ("by", by),
            ("decision", decision),
            (
                "was",
                &format!(
                    "{outcome}{}",
                    effect
                        .as_deref()
                        .map(|e| format!(" ({e})"))
                        .unwrap_or_default()
                ),
            ),
        ],
    );
    if contradicts {
        printer.info("  this decision overrides the judge's; the receipt records both");
    }
    Ok(())
}

/// The exit code `--enforce` maps an effect to; `None` means exit 0.
fn enforce_exit(effect: Option<&str>) -> Option<i32> {
    match effect {
        Some("deny") => Some(2),
        Some("ask") => Some(3),
        _ => None,
    }
}

/// One HTTP judge that speaks the contract: `POST` the request, read the
/// response. Bounded timeout, no retry; a judge that cannot answer is an
/// error the caller decides about, never a silent allow.
struct HttpJudge {
    url: String,
}

impl Judge for HttpJudge {
    fn judge(&self, request: &JudgeRequest) -> Result<JudgeResponse, JudgeError> {
        let started = std::time::Instant::now();
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .build();
        let resp = agent
            .post(&self.url)
            .set("Content-Type", "application/json")
            .send_json(
                serde_json::to_value(request)
                    .map_err(|e| JudgeError::Unavailable(e.to_string()))?,
            )
            .map_err(|e| JudgeError::Unavailable(e.to_string()))?;
        // The judge's own id for this answer, from the header if it sets
        // one; the body may carry it too.
        let header_id = [
            "x-typesafe-request-id",
            "x-request-id",
            "x-judge-request-id",
        ]
        .iter()
        .find_map(|h| resp.header(h).map(str::to_string));
        let mut raw = Vec::new();
        resp.into_reader()
            .read_to_end(&mut raw)
            .map_err(|e| JudgeError::Unavailable(e.to_string()))?;
        let mut parsed: JudgeResponse = serde_json::from_slice(&raw)
            .map_err(|e| JudgeError::BadAnswer(format!("response is not a judge answer: {e}")))?;
        if parsed.latency_ms.is_none() {
            parsed.latency_ms = Some(started.elapsed().as_millis() as u64);
        }
        if parsed.request_id.is_none() {
            parsed.request_id = header_id;
        }
        // Committed to as received: the exact bytes, before any parsing.
        parsed.response_digest = Some(digest_bytes(&raw));
        Ok(parsed)
    }
}

fn read_json_arg(raw: &str, what: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let text = if let Some(path) = raw.strip_prefix('@') {
        std::fs::read_to_string(path)
            .map_err(|e| format!("could not read {what} file {path}: {e}"))?
    } else {
        raw.to_string()
    };
    serde_json::from_str(&text).map_err(|e| format!("{what} is not valid JSON: {e}").into())
}

/// The workspace root the config lives under (`<root>/.treeship/config.json`).
fn workspace_root(config_path: &Path) -> Option<String> {
    let dir = config_path.parent()?;
    let root = if dir.file_name().map(|n| n == ".treeship").unwrap_or(false) {
        dir.parent()?
    } else {
        dir
    };
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    Some(root.to_string_lossy().to_string())
}

fn rank(effect: Option<&str>) -> u8 {
    match effect {
        Some("deny") => 4,
        Some("ask") => 3,
        Some("warn") => 2,
        Some("allow") => 1,
        _ => 0,
    }
}

pub fn judge(args: JudgeArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    if !(0.0..=1.0).contains(&args.threshold) {
        return Err("--threshold must be between 0 and 1".into());
    }
    let ctx = ctx::open(args.config.as_deref())?;
    if let Some(id) = args.resolve.clone() {
        return resolve(&ctx, &args, &id, printer);
    }
    let tool = args.tool.clone().ok_or_else(|| {
        crate::exit::usage("--tool <NAME> is required (or --resolve <judgement id> to resolve one)")
    })?;
    let contract = args.contract.as_deref().map(parse_contract).transpose()?;

    let input = match &args.input {
        Some(raw) => read_json_arg(raw, "--input")?,
        None => Value::Object(Default::default()),
    };
    let state = ToolCallState {
        tool: tool.clone(),
        capability: args.capability.clone(),
        input,
        workspace_root: workspace_root(&ctx.config_path),
        network_scope: crate::commands::declare::read_network_scope(),
        amount_bound: args.bound,
    };

    // Questions: the rules set by default, a subset by key, or a typed file.
    let mut questions: BTreeMap<String, Question> = if let Some(path) = &args.questions_file {
        let v = read_json_arg(&format!("@{path}"), "--questions-file")?;
        serde_json::from_value(v).map_err(|e| {
            format!("--questions-file is not {{key: {{type, instructions, options}}}}: {e}")
        })?
    } else {
        rules_questions()
    };
    if !args.questions.is_empty() {
        let all = std::mem::take(&mut questions);
        for k in &args.questions {
            match all.get(k) {
                Some(q) => {
                    questions.insert(k.clone(), q.clone());
                }
                None if args.judge_url.is_some() => {
                    // An outside judge may know questions the rules do not.
                    questions.insert(
                        k.clone(),
                        Question {
                            kind: QuestionType::Noul,
                            instructions: String::new(),
                            options: Vec::new(),
                        },
                    );
                }
                None => {
                    return Err(format!(
                        "no rule answers question {k:?}. The rules judge answers: {}",
                        rules_questions()
                            .keys()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                    .into())
                }
            }
        }
    }
    if questions.is_empty() {
        return Err("no questions to ask".into());
    }

    let request = JudgeRequest {
        state: serde_json::to_value(&state)?,
        questions,
    };
    let response = match &args.judge_url {
        Some(url) => HttpJudge { url: url.clone() }.judge(&request)?,
        None => RulesJudge.judge(&request)?,
    };
    check_answers(&request, &response)?;

    let state_digest = digest(&request.state);
    if let Some(path) = &args.state_out {
        // The receipt carries only the digest; the caller holds the state.
        // This is the file a verifier needs to re-run the rules judge, or
        // to check that an outside judge was shown what the receipt says.
        std::fs::write(path, treeship_core::judge::canonical_bytes(&request.state))
            .map_err(|e| format!("could not write --state-out {path}: {e}"))?;
    }
    let questions_digest = questions_digest(&request.questions);
    let set_by = args.set_by.clone().unwrap_or_else(|| "default".to_string());
    let judged_at = crate::commands::session::now_rfc3339();

    // One decision per question; the strongest effect wins overall.
    let mut decisions: BTreeMap<String, Decision> = BTreeMap::new();
    for (key, q) in &request.questions {
        decisions.insert(
            key.clone(),
            decide(q, &response.answers[key], args.threshold),
        );
    }
    let overall = decisions
        .values()
        .max_by_key(|d| rank(d.effect.as_deref()))
        .cloned()
        .unwrap_or(Decision {
            outcome: "ignored".into(),
            effect: None,
            applies_to: "noul".into(),
        });
    let deciders: Vec<&String> = decisions
        .iter()
        .filter(|(_, d)| {
            d.effect.is_some() && d.effect == overall.effect && rank(d.effect.as_deref()) > 1
        })
        .map(|(k, _)| k)
        .collect();

    // Chain: inside a session, onto its head (the same rule `attest receipt
    // --chain` follows); outside one, onto the subject when it is an artifact.
    let mut receipts: Vec<String> = Vec::new();
    if args.attest {
        let mut parent: Option<String> = None;
        if let Some(manifest) = crate::commands::session::load_session() {
            parent = crate::commands::session::session_chain_head(
                &ctx,
                manifest.root_artifact_id.as_deref(),
            );
        }
        if parent.is_none() {
            parent = args.subject.clone().filter(|s| s.starts_with("art_"));
        }
        let signer = ctx.keys.default_signer()?;
        let pt = payload_type("receipt");
        // One receipt per question, each chained onto the one before it, so
        // the session chain stays linear: a fork of siblings under the same
        // head leaves all but one of them "never chained" to a strict verify.
        for (key, q) in &request.questions {
            let payload = judgement_payload(
                &response.judge,
                &state_digest,
                &questions_digest,
                key,
                q,
                &response.answers[key],
                args.threshold,
                &set_by,
                &decisions[key],
                response.latency_ms,
                &judged_at,
            );
            let mut payload = payload;
            if let Some(d) = &response.response_digest {
                payload["response_digest"] = Value::String(d.clone());
            }
            if let Some(rid) = &response.request_id {
                payload["judge"]["request_id"] = Value::String(rid.clone());
            }
            if let Some((cid, cver)) = &contract {
                let mut c = serde_json::json!({ "id": cid });
                if let Some(v) = cver {
                    c["version"] = Value::String(v.clone());
                }
                payload["contract"] = c;
            }
            treeship_core::predicates::validate("judgement.v1", Some(&payload))
                .map_err(|e| format!("predicate validation failed: {e}"))?;
            let mut stmt = ReceiptStatement::new(SYSTEM, "judgement.v1");
            stmt.payload = Some(payload);
            stmt.parent_id = parent.clone();
            if let Some(s) = &args.subject {
                stmt.subject = Some(SubjectRef {
                    artifact_id: Some(s.clone()),
                    ..Default::default()
                });
            }
            let result = sign(&pt, &stmt, signer.as_ref())?;
            ctx.storage.write(&Record {
                artifact_id: result.artifact_id.clone(),
                digest: result.digest.clone(),
                payload_type: pt.clone(),
                key_id: signer.key_id().to_string(),
                signed_at: stmt.timestamp.clone(),
                parent_id: parent.clone(),
                envelope: result.envelope,
                hub_url: None,
                anchors: Vec::new(),
            })?;
            parent = Some(result.artifact_id.clone());
            receipts.push(result.artifact_id);
        }
        if let Some(last) = receipts.last() {
            let _ = std::fs::write(Path::new(&ctx.config.storage_dir).join(".last"), last);
        }
    }

    if printer.format == crate::printer::Format::Json {
        // The same answers as Reason premises under the `model-judged`
        // authority class: id = the signed receipt when there is one, the
        // predicate names the question, the arguments are the subject and
        // the typed answer. A program admits them per predicate; see
        // Reason's AUTHORITY.md, "Model-judged evidence".
        let subject = args.subject.clone().unwrap_or_else(|| tool.clone());
        let reason_facts: Vec<Value> = request
            .questions
            .iter()
            .enumerate()
            .filter_map(|(i, (k, q))| {
                let a = &response.answers[k];
                let answer = match q.kind {
                    QuestionType::Noul => {
                        if a.noul.unwrap_or(0.0) >= args.threshold {
                            "yes".to_string()
                        } else {
                            "no".to_string()
                        }
                    }
                    QuestionType::Choice => a.choice.clone()?,
                    QuestionType::Score => return None,
                };
                Some(serde_json::json!({
                    "id": receipts.get(i).cloned().unwrap_or_else(|| format!("judgement:{k}")),
                    "predicate": format!("judged_{k}"),
                    "arguments": [subject, answer],
                    "authority": "model-judged",
                    "observed_at": judged_at,
                }))
            })
            .collect();
        let answers: serde_json::Map<String, Value> = request
            .questions
            .keys()
            .map(|k| {
                let a = &response.answers[k];
                let d = &decisions[k];
                (
                    k.clone(),
                    serde_json::json!({
                        "noul": a.noul, "choice": a.choice, "score": a.score,
                        "confidence": a.confidence, "outcome": d.outcome, "effect": d.effect,
                    }),
                )
            })
            .collect();
        printer.json(&serde_json::json!({
            "status": "ok",
            "judge": response.judge,
            "effect": overall.effect,
            "outcome": overall.outcome,
            "decided_by": deciders,
            "threshold": args.threshold,
            "answers": answers,
            "state_digest": state_digest,
            "questions_digest": questions_digest,
            "receipts": receipts,
            "reason_facts": reason_facts,
            "contract": contract.as_ref().map(|(id, v)| serde_json::json!({ "id": id, "version": v })),
            "response_digest": response.response_digest,
            "request_id": response.request_id,
            "state_out": args.state_out,
        }));
        if args.enforce {
            if let Some(code) = enforce_exit(overall.effect.as_deref()) {
                std::process::exit(code);
            }
        }
        return Ok(());
    }

    let kind = response
        .judge
        .kind
        .clone()
        .unwrap_or_else(|| "unknown".into());
    let replay = match response.judge.replayable {
        Some(true) => "replayable",
        Some(false) => "not replayable",
        None => "replayability unstated",
    };
    printer.info(&format!(
        "judge:      {} ({kind}, {replay})",
        response.judge.model
    ));
    printer.info(&format!(
        "tool:       {}{}",
        tool,
        args.capability
            .as_deref()
            .map(|c| format!(" ({c})"))
            .unwrap_or_default()
    ));
    printer.info(&format!("threshold:  {} (set by {set_by})", args.threshold));
    printer.blank();
    for (key, q) in &request.questions {
        let a = &response.answers[key];
        let d = &decisions[key];
        let shown = match q.kind {
            QuestionType::Noul => format!("{:.2}", a.noul.unwrap_or(0.0)),
            QuestionType::Choice => a.choice.clone().unwrap_or_default(),
            QuestionType::Score => format!("{}", a.score.unwrap_or(0.0)),
        };
        printer.info(&format!(
            "  {key:<24} {shown:>6}  {}{}",
            d.outcome,
            d.effect
                .as_deref()
                .map(|e| format!(" ({e})"))
                .unwrap_or_default()
        ));
    }
    printer.blank();
    match overall.effect.as_deref() {
        Some("deny") => printer.warn(
            &format!(
                "refused: {}",
                deciders
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            &[],
        ),
        Some("ask") => printer.warn("escalate: the answer needs a human", &[]),
        Some("warn") => printer.warn("warn", &[]),
        Some("allow") => printer.info("effect:     allow"),
        _ => printer.info("effect:     none (answers recorded, not acted on)"),
    }
    if !receipts.is_empty() {
        printer.info(&format!(
            "receipts:   {} judgement.v1 signed ({})",
            receipts.len(),
            receipts.join(", ")
        ));
    } else if !args.attest {
        printer.hint("add --attest to sign each answer as a judgement.v1 receipt (--subject <art_…> chains it onto the action)");
    }
    if args.enforce {
        if let Some(code) = enforce_exit(overall.effect.as_deref()) {
            std::process::exit(code);
        }
    }
    Ok(())
}
