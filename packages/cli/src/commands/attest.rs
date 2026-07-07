use serde_json::Value;
use treeship_core::{
    attestation::{sign, Signer},
    journal::{self, Journal},
    statements::{
        ActionStatement, ApprovalScope, ApprovalStatement, ApprovalUse, DecisionStatement,
        EndorsementStatement, HandoffStatement, ReceiptStatement,
        SubjectRef, TYPE_APPROVAL_USE, payload_type, nonce_digest,
    },
    storage::Record,
    trust::{TrustRootKind, TrustRootStore},
};

use crate::commands::verify::{check_scope_violation, find_approval_by_nonce, now_rfc3339};
use crate::{ctx, printer::Printer};
use treeship_core::session::event::EventType;

/// Receipt kinds that are minted only by a dedicated command from sealed
/// evidence and must never be hand-signed through the generic attest path
/// (AUD-06). Returns the owning command for the error message, or None if the
/// kind is freely attestable.
pub(crate) fn close_only_kind_owner(kind: &str) -> Option<&'static str> {
    match kind {
        // session.v1 records carry a self-declared `attestation_class` that
        // `session close` derives from consumed approvals / tool runtimes.
        "session.v1" => Some("treeship session close"),
        _ => None,
    }
}

/// Resolve which key signs for a given actor URI. An `agent://<name>` whose
/// agent card carries a registered per-agent key that is pinned under
/// AgentCert signs with **that** key, so the actor is provable (the receipt's
/// signer is the agent's certified key). Every other actor, and any agent
/// without a registered/pinned key, signs with the ship's default key, exactly
/// as before. This is the load-bearing half of per-actor signing.
pub(crate) fn resolve_actor_signer(
    ctx: &ctx::Ctx,
    actor: &str,
) -> Result<Box<dyn Signer>, Box<dyn std::error::Error>> {
    let agents_dir = crate::commands::cards::agents_dir_for(&ctx.config_path);
    let Some(key_id) = crate::commands::cards::registered_key_for_actor(&agents_dir, actor)
    else {
        return Ok(ctx.keys.default_signer()?);
    };
    // Only sign as the agent if its key is actually pinned under AgentCert.
    let pinned = TrustRootStore::open_default_or_empty()?
        .roots()
        .iter()
        .any(|r| r.key_id == key_id && r.kind == TrustRootKind::AgentCert);
    if !pinned {
        return Ok(ctx.keys.default_signer()?);
    }
    // Sign with the agent's own key; fall back to default if the entry is gone.
    Ok(ctx
        .keys
        .signer(&key_id)
        .or_else(|_| ctx.keys.default_signer())?)
}

// --- action -----------------------------------------------------------------

pub struct ActionArgs {
    pub actor:           String,
    pub action:          String,
    pub input_digest:    Option<String>,
    pub output_digest:   Option<String>,
    pub content_uri:     Option<String>,
    pub parent_id:       Option<String>,
    pub approval_nonce:  Option<String>,
    /// Set together with --approval-nonce: a retry with the same key
    /// collapses to the existing journal entry instead of allocating a
    /// new one. See attest::action() for the precise crash-recovery
    /// semantics.
    pub idempotency_key: Option<String>,
    pub meta:            Option<String>,
    pub out:             Option<String>,
    pub config:          Option<String>,
}

pub fn action(args: ActionArgs, printer: &Printer) -> Result<String, Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;

    let mut meta: Option<Value> = args.meta.as_deref()
        .map(|m| serde_json::from_str(m))
        .transpose()
        .map_err(|e| format!("--meta is not valid JSON: {e}"))?;

    let subject = SubjectRef {
        digest:      args.input_digest.clone(),
        uri:         args.content_uri.clone(),
        artifact_id: None,
    };

    let mut stmt = ActionStatement::new(&args.actor, &args.action);
    stmt.subject        = subject;
    stmt.parent_id      = args.parent_id.clone();
    stmt.approval_nonce = args.approval_nonce.clone();

    // ----------------------------------------------------------------------
    // Consume-before-action (v0.9.9 PR 3)
    //
    // When --approval-nonce is set, we resolve the matching grant, run
    // the same scope checks `verify_nonce_bindings` runs, then RESERVE
    // an ApprovalUse in the local journal BEFORE signing the action.
    //
    // Crash semantics ("reserved counts as consumed"): if the process
    // dies between the journal write and the action signature, the use
    // remains on disk. A retry with the SAME --idempotency-key collapses
    // to that record and finishes signing the action against it. A retry
    // WITHOUT an idempotency key (or with a different one) sees the
    // earlier use as already-consumed and refuses if max_uses would be
    // exceeded -- the explicit safer-by-default behavior.
    //
    // Cheap rejections (missing grant, scope mismatch, expired) happen
    // BEFORE the journal lock so they don't contend on the lock when
    // they're going to fail anyway.
    // ----------------------------------------------------------------------
    let consumed_use_id = if let Some(ref raw_nonce) = args.approval_nonce {
        Some(consume_approval(
            &ctx,
            raw_nonce,
            &stmt,
            args.idempotency_key.as_deref(),
            printer,
        )?)
    } else {
        None
    };

    // If we recorded a use, link the use_id into the action's meta so
    // verify can cross-reference (PR 4 reads this on package verify).
    if let Some(ref use_id) = consumed_use_id {
        let mut obj = match meta.take() {
            Some(Value::Object(map)) => map,
            Some(_other) => return Err("--meta must be a JSON object when --approval-nonce is set".into()),
            None => serde_json::Map::new(),
        };
        obj.insert("approval_use_id".into(), Value::String(use_id.clone()));
        meta = Some(Value::Object(obj));
    }
    if let Some(ref output_digest) = args.output_digest {
        let mut obj = match meta.take() {
            Some(Value::Object(map)) => map,
            Some(_other) => return Err("--meta must be a JSON object when --output-digest is set".into()),
            None => serde_json::Map::new(),
        };
        obj.insert("output_digest".into(), Value::String(output_digest.clone()));
        meta = Some(Value::Object(obj));
    }
    stmt.meta = meta;

    // Sign with the actor's own key when it has a registered, pinned one;
    // otherwise the ship's default key (unchanged behavior).
    let signer = resolve_actor_signer(&ctx, &args.actor)?;
    let pt     = payload_type("action");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    // Store locally.
    let record = Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt.clone(),
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    args.parent_id.clone(),
        envelope:     result.envelope.clone(),
        hub_url:      None,
    };
    ctx.storage.write(&record)?;
    write_last(&ctx.config.storage_dir, &result.artifact_id);

    // Backfill action_artifact_id onto the journal record once the
    // action is signed. The reserved use already counts; this just
    // upgrades the record from "reserved" to "committed" by linking
    // the action it authorized.
    if consumed_use_id.is_some() {
        if let Err(e) = backfill_action_artifact_id(
            &ctx,
            consumed_use_id.as_deref().unwrap(),
            &result.artifact_id,
        ) {
            // Backfill failure is recoverable (the journal still
            // records the use; the link can be re-derived from the
            // by-grant index). Surface a warning rather than failing
            // the whole action.
            printer.warn(
                "could not backfill action_artifact_id onto journal record",
                &[("error", &e.to_string())],
            );
        }
    }

    // Optional: write raw DSSE envelope to file or stdout.
    if let Some(path) = &args.out {
        let json = result.envelope.to_json()?;
        if path == "-" {
            println!("{}", String::from_utf8_lossy(&json));
        } else {
            std::fs::write(path, &json)?;
        }
    }

    // Build display fields.
    let signed_str = stmt.timestamp.clone();
    let mut fields: Vec<(&str, String)> = vec![
        ("id",     result.artifact_id.clone()),
        ("actor",  args.actor.clone()),
        ("action", args.action.clone()),
        ("signed", signed_str),
    ];
    if let Some(d) = &args.output_digest {
        fields.push(("out-digest", d.clone()));
    }
    if let Some(p) = &args.parent_id {
        fields.push(("parent", p.clone()));
    }

    let field_refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    printer.success("action attested", &field_refs);
    printer.hint(&format!("treeship verify {}", result.artifact_id));
    printer.blank();
    Ok(result.artifact_id)
}

// --- approval ---------------------------------------------------------------

pub struct ApprovalArgs {
    pub approver:         String,
    pub subject_id:       Option<String>,
    pub description:      Option<String>,
    pub expires:          Option<String>,
    /// Scope: actor URIs allowed to consume this approval.
    pub allowed_actors:   Vec<String>,
    /// Scope: action labels allowed under this approval.
    pub allowed_actions:  Vec<String>,
    /// Scope: subject URIs allowed as the action target.
    pub allowed_subjects: Vec<String>,
    /// Scope: max consumption count (signed for future ledger enforcement).
    pub max_uses:         Option<u32>,
    /// Explicit opt-in to an unscoped approval. Required when no
    /// scope axis is populated; without it the command refuses since
    /// unscoped approvals are footguns.
    pub unscoped:         bool,
    pub config:           Option<String>,
}

pub fn approval(args: ApprovalArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;

    // Build scope from CLI flags. An all-empty scope is treated as "no
    // scope" -- but we refuse to mint such an approval unless the
    // operator explicitly typed --unscoped, since the verify pass will
    // (correctly) flag it as proving nothing about authorization.
    let scope = ApprovalScope {
        max_actions:      args.max_uses,
        valid_until:      None,
        allowed_actors:   args.allowed_actors.clone(),
        allowed_actions:  args.allowed_actions.clone(),
        allowed_subjects: args.allowed_subjects.clone(),
        extra:            None,
    };
    let scope_for_stmt = if scope.is_unscoped() {
        if !args.unscoped {
            return Err(
                "approval has no scope (no --allowed-actor / --allowed-action / --allowed-subject / --max-uses). \
                 Pass --unscoped to mint a bearer approval explicitly, or add a scope constraint."
                .into(),
            );
        }
        None
    } else {
        Some(scope)
    };

    // Generate a cryptographically random nonce for approval binding.
    let nonce = {
        let mut b = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut b);
        b.iter().fold(String::new(), |mut s, byte| {
            s.push_str(&format!("{:02x}", byte));
            s
        })
    };

    let mut stmt = ApprovalStatement::new(&args.approver, &nonce);
    stmt.description = args.description.clone();
    stmt.expires_at  = args.expires.clone();
    stmt.scope       = scope_for_stmt;
    if let Some(id) = &args.subject_id {
        stmt.subject.artifact_id = Some(id.clone());
    }

    let signer = ctx.keys.default_signer()?;
    let pt     = payload_type("approval");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    None,
        envelope:     result.envelope,
        hub_url:      None,
    })?;
    write_last(&ctx.config.storage_dir, &result.artifact_id);

    printer.success("approval attested", &[
        ("id",       &result.artifact_id),
        ("approver", &args.approver),
        ("nonce",    &nonce),
        ("signed",   &stmt.timestamp),
    ]);
    if stmt.scope.is_none() {
        printer.hint("scope: none (unscoped/bearer approval -- proves binding only, not actor/action/subject authorization)");
    } else if let Some(ref s) = stmt.scope {
        let mut parts = Vec::new();
        if !s.allowed_actors.is_empty()   { parts.push(format!("actors={:?}", s.allowed_actors)); }
        if !s.allowed_actions.is_empty()  { parts.push(format!("actions={:?}", s.allowed_actions)); }
        if !s.allowed_subjects.is_empty() { parts.push(format!("subjects={:?}", s.allowed_subjects)); }
        if let Some(n) = s.max_actions    { parts.push(format!("max_uses={n}")); }
        printer.hint(&format!("scope: {}", parts.join(", ")));
    }
    printer.hint(&format!("nonce: {}  (echo this in --approval-nonce when you attest the action)", nonce));
    printer.blank();
    Ok(())
}

// --- handoff ----------------------------------------------------------------

pub struct HandoffArgs {
    pub from:        String,
    pub to:          String,
    pub artifacts:   Vec<String>,
    pub approvals:   Vec<String>,
    pub obligations: Vec<String>,
    pub config:      Option<String>,
}

pub fn handoff(args: HandoffArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;

    let mut stmt = HandoffStatement::new(&args.from, &args.to, args.artifacts.clone());
    stmt.approval_ids = args.approvals.clone();
    stmt.obligations  = args.obligations.clone();

    // The handing-off agent (`from`) signs; use its own key when registered.
    let signer = resolve_actor_signer(&ctx, &args.from)?;
    let pt     = payload_type("handoff");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    args.artifacts.first().cloned(),
        envelope:     result.envelope,
        hub_url:      None,
    })?;
    write_last(&ctx.config.storage_dir, &result.artifact_id);

    printer.success("handoff attested", &[
        ("id",        &result.artifact_id),
        ("from",      &args.from),
        ("to",        &args.to),
        ("artifacts", &args.artifacts.join(", ")),
        ("signed",    &stmt.timestamp),
    ]);
    printer.hint(&format!("treeship verify {}", result.artifact_id));
    printer.blank();
    Ok(())
}

// --- receipt ----------------------------------------------------------------

pub struct ReceiptArgs {
    pub system:         String,
    pub kind:           String,
    pub subject_id:     Option<String>,
    pub payload:        Option<String>,
    pub payload_file:   Option<String>,
    pub payload_digest: Option<String>,
    pub config:         Option<String>,
}

pub fn receipt(args: ReceiptArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;

    let payload_text = match (&args.payload, &args.payload_file) {
        (Some(payload), None) => Some(payload.clone()),
        (None, Some(path)) => Some(std::fs::read_to_string(path)
            .map_err(|e| format!("could not read --payload-file {path}: {e}"))?),
        (None, None) => None,
        (Some(_), Some(_)) => return Err("--payload and --payload-file cannot be used together".into()),
    };
    let payload_val: Option<Value> = payload_text.as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| format!("receipt payload is not valid JSON: {e}"))?;

    // AUD-06: some receipt kinds are minted ONLY by a command that derives
    // every field from sealed session evidence (e.g. `session close` computes
    // `attestation_class` from consumed approvals / tool runtimes). Letting a
    // caller hand-sign them through the generic attest path is a trust-ladder
    // laundering vector: an attacker mints `session.v1` with
    // `attestation_class:"countersigned"` and an inflated `action_count`, no
    // countersignature or runtime evidence, and it aggregates into the highest
    // trust classes. Refuse those kinds here.
    if let Some(owner) = close_only_kind_owner(&args.kind) {
        return Err(format!(
            "kind '{}' is minted only by `{owner}` from sealed session evidence; \
             it cannot be hand-signed via `attest receipt`. This prevents forging a \
             work-history record with a self-declared attestation_class. \
             See docs/specs/work-history.md.",
            args.kind
        ).into());
    }

    // Typed-predicate validation: if `kind` is a registered predicate, the
    // payload must conform to its schema before we sign. Unregistered kinds
    // attest sign-on-submit, exactly as before (backward compatible). This
    // runs before signing and does not touch the signature path.
    treeship_core::predicates::validate(&args.kind, payload_val.as_ref())
        .map_err(|e| format!("predicate validation failed: {e}"))?;

    let mut stmt = ReceiptStatement::new(&args.system, &args.kind);
    stmt.payload = payload_val;
    stmt.payload_digest = args.payload_digest.clone();
    if let Some(id) = &args.subject_id {
        stmt.subject = Some(SubjectRef {
            artifact_id: Some(id.clone()),
            ..Default::default()
        });
    }

    let signer = ctx.keys.default_signer()?;
    let pt     = payload_type("receipt");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    args.subject_id.clone(),
        envelope:     result.envelope,
        hub_url:      None,
    })?;
    write_last(&ctx.config.storage_dir, &result.artifact_id);

    printer.success("receipt attested", &[
        ("id",     &result.artifact_id),
        ("system", &args.system),
        ("kind",   &args.kind),
        ("signed", &stmt.timestamp),
    ]);
    printer.hint(&format!("treeship verify {}", result.artifact_id));
    printer.blank();
    Ok(())
}

// --- card -------------------------------------------------------------------

pub struct CardArgs {
    pub agent:        String,
    pub tools:        Vec<String>,
    pub models:       Vec<String>,
    pub keyid:        Option<String>,
    pub owner:        Option<String>,
    pub version:      String,
    pub policy_ref:   Option<String>,
    /// Path to a harness config (e.g. a Claude Code settings.json) whose
    /// `permissions.allow` list is the agent's real, wired tool set. Those
    /// capabilities are stamped `captured` -- read from config, not declared.
    pub from_harness: Option<String>,
    /// Path to an explicit operator-supplied capability list (a JSON array of
    /// tool strings, or `{ "tools": [...] }`). The runtime companion to
    /// `--from-harness`: where `--from-harness` *captures* tools observed in a
    /// config, this records an operator's *declaration*. Entries are stamped
    /// `declared` with the file as their `source`, never presented as captured.
    pub tools_json:   Option<String>,
    /// Path to an A2A `AgentCard` JSON. The agent's own published `skills` are
    /// mapped to capabilities and stamped `discovered` with the AgentCard's
    /// `url` as their `source` -- read from the agent's own descriptor, a real
    /// provenance source distinct from operator-`declared` and harness-
    /// `captured`. Protocol-level `capabilities` (streaming, ...) are not the
    /// agent's domain capabilities and are excluded.
    pub from_a2a:     Option<String>,
    pub config:       Option<String>,
}

/// Read a harness config's `permissions.allow` list -- the deterministic
/// capture source for a capability card. Today: the Claude Code settings.json
/// shape (`{ "permissions": { "allow": [...] } }`).
fn read_harness_allow(path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read --from-harness {path}: {e}"))?;
    let json: Value = serde_json::from_str(&text)
        .map_err(|e| format!("--from-harness {path} is not valid JSON: {e}"))?;
    let allow = json
        .get("permissions")
        .and_then(|p| p.get("allow"))
        .and_then(|a| a.as_array())
        .ok_or_else(|| format!("--from-harness {path} has no permissions.allow array"))?;
    Ok(allow
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect())
}

/// Read an operator-supplied capability list for `--tools-json`. Accepts either
/// a bare JSON array of strings (`["deploy.run", "db.query"]`) or an object
/// with a `tools` array (`{ "tools": [...] }`). This is an explicit operator
/// declaration, not a capture: the caller stamps the result `declared`.
fn read_tools_json(path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read --tools-json {path}: {e}"))?;
    parse_tools_json(&text, path)
}

/// Pure parser for `--tools-json` content, split from IO so it is unit-testable.
fn parse_tools_json(text: &str, path: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let json: Value = serde_json::from_str(text)
        .map_err(|e| format!("--tools-json {path} is not valid JSON: {e}"))?;
    let arr = match &json {
        Value::Array(a) => a,
        Value::Object(o) => o
            .get("tools")
            .and_then(|t| t.as_array())
            .ok_or_else(|| format!("--tools-json {path} object has no `tools` array"))?,
        _ => {
            return Err(format!(
                "--tools-json {path} must be a JSON array of strings or {{ \"tools\": [...] }}"
            )
            .into())
        }
    };
    let tools: Vec<String> = arr
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    if tools.is_empty() {
        return Err(format!("--tools-json {path} contains no tool strings").into());
    }
    Ok(tools)
}

#[cfg(test)]
mod tools_json_tests {
    use super::parse_tools_json;

    #[test]
    fn parses_bare_array() {
        let got = parse_tools_json(r#"["deploy.run", "db.query"]"#, "x").unwrap();
        assert_eq!(got, vec!["deploy.run", "db.query"]);
    }

    #[test]
    fn parses_object_with_tools() {
        let got = parse_tools_json(r#"{ "tools": ["a", "b"] }"#, "x").unwrap();
        assert_eq!(got, vec!["a", "b"]);
    }

    #[test]
    fn rejects_non_array_non_object() {
        assert!(parse_tools_json(r#""just a string""#, "x").is_err());
    }

    #[test]
    fn rejects_object_without_tools_array() {
        assert!(parse_tools_json(r#"{ "nope": 1 }"#, "x").is_err());
    }

    #[test]
    fn rejects_empty_and_non_string_entries() {
        assert!(parse_tools_json(r#"[]"#, "x").is_err());
        // non-string entries are filtered, leaving nothing -> error
        assert!(parse_tools_json(r#"[1, 2, 3]"#, "x").is_err());
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(parse_tools_json("{not json", "x").is_err());
    }
}

/// Read an A2A `AgentCard` for `--from-a2a`. Returns the agent's declared
/// `skills` (as capability strings) and the `source` to record on each, the
/// AgentCard's own `url` when present, else the file path. The agent's `skills`
/// are its *domain* capabilities; protocol-level `capabilities` (streaming,
/// pushNotifications, ...) are deliberately excluded, they describe transport,
/// not what the agent does.
fn read_a2a_skills(path: &str) -> Result<(Vec<String>, String), Box<dyn std::error::Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("could not read --from-a2a {path}: {e}"))?;
    parse_a2a_skills(&text, path)
}

/// Pure parser for an A2A AgentCard, split from IO so it is unit-testable. Each
/// skill's `id` is the capability string (stable identifier); the AgentCard's
/// `url` is the provenance source (where the descriptor was published).
fn parse_a2a_skills(text: &str, path: &str) -> Result<(Vec<String>, String), Box<dyn std::error::Error>> {
    let json: Value = serde_json::from_str(text)
        .map_err(|e| format!("--from-a2a {path} is not valid JSON: {e}"))?;
    let obj = json
        .as_object()
        .ok_or_else(|| format!("--from-a2a {path} is not a JSON object (expected an AgentCard)"))?;
    // Source: the agent's own published URL, falling back to the file path.
    let source = obj
        .get("url")
        .and_then(|u| u.as_str())
        .map(|u| format!("a2a:{u}"))
        .unwrap_or_else(|| format!("a2a-card:{path}"));
    let skills = obj
        .get("skills")
        .and_then(|s| s.as_array())
        .ok_or_else(|| format!("--from-a2a {path} has no `skills` array"))?;
    let mut tools: Vec<String> = Vec::new();
    for skill in skills {
        // A2A skills carry a stable `id`; use it as the capability string.
        if let Some(id) = skill.get("id").and_then(|v| v.as_str()) {
            if !id.is_empty() && !tools.contains(&id.to_string()) {
                tools.push(id.to_string());
            }
        }
    }
    if tools.is_empty() {
        return Err(format!("--from-a2a {path}: no skills with an `id` to map").into());
    }
    Ok((tools, source))
}

#[cfg(test)]
mod a2a_card_tests {
    use super::parse_a2a_skills;

    #[test]
    fn maps_skills_to_tools_with_url_source() {
        let card = r#"{
            "name": "trader", "version": "1.0", "url": "https://agents.example/trader",
            "capabilities": { "streaming": true },
            "skills": [
                { "id": "stock.trade", "name": "Stock Trading" },
                { "id": "report.analyze", "name": "Report Analysis" }
            ]
        }"#;
        let (tools, source) = parse_a2a_skills(card, "x").unwrap();
        assert_eq!(tools, vec!["stock.trade", "report.analyze"]);
        assert_eq!(source, "a2a:https://agents.example/trader");
    }

    #[test]
    fn excludes_protocol_capabilities() {
        // `capabilities.streaming` etc. must NOT become capability strings.
        let card = r#"{ "name": "x", "version": "1", "url": "u",
            "capabilities": { "streaming": true, "pushNotifications": true },
            "skills": [{ "id": "only.skill", "name": "S" }] }"#;
        let (tools, _) = parse_a2a_skills(card, "x").unwrap();
        assert_eq!(tools, vec!["only.skill"]);
    }

    #[test]
    fn falls_back_to_path_source_when_no_url() {
        let card = r#"{ "name": "x", "version": "1", "skills": [{ "id": "s" }] }"#;
        let (_, source) = parse_a2a_skills(card, "card.json").unwrap();
        assert_eq!(source, "a2a-card:card.json");
    }

    #[test]
    fn rejects_missing_skills() {
        assert!(parse_a2a_skills(r#"{ "name": "x", "url": "u" }"#, "x").is_err());
    }

    #[test]
    fn rejects_skills_without_ids() {
        assert!(parse_a2a_skills(r#"{ "skills": [{ "name": "no id" }] }"#, "x").is_err());
    }

    #[test]
    fn rejects_non_object() {
        assert!(parse_a2a_skills(r#"["not", "a", "card"]"#, "x").is_err());
    }
}

/// Mint a signed agent_card.v1 capability card from typed flags. Thin, typed
/// wrapper over the agent_card.v1 predicate: builds the payload, validates it,
/// signs it, and reports whether the card is key-bound at mint time.
pub fn card(args: CardArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;
    // Sign the card with the agent's own key when it has a registered, pinned
    // one, so the card and the agent's actions share a signer and the card is
    // key-bound. Falls back to the ship's default key.
    let signer = resolve_actor_signer(&ctx, &args.agent)?;
    // Default the card's keyid to the signing key, so a freshly minted card is
    // key-bound-eligible by default (pin it under AgentCert to make it strong).
    let keyid = args.keyid.clone().unwrap_or_else(|| signer.key_id().to_string());

    // Capability set: --tools entries are declared; --from-harness entries are
    // captured from the agent's real config and stamped with their provenance.
    let mut all_tools = args.tools.clone();
    let mut provenance = serde_json::Map::new();
    let mut captured_count = 0usize;
    let mut declared_count = 0usize;
    if let Some(path) = &args.from_harness {
        let source = format!("harness:{path}#permissions.allow");
        for tool in read_harness_allow(path)? {
            if !all_tools.contains(&tool) {
                all_tools.push(tool.clone());
            }
            provenance.insert(
                tool,
                serde_json::json!({ "grade": "captured", "source": source }),
            );
        }
        captured_count = provenance.len();
    }

    // --tools-json: an explicit operator declaration. Stamped `declared` (not
    // captured) with the file as its source, so the card records *that* these
    // are an operator's claim and *where* it came from. A capability already
    // captured from a harness keeps the stronger `captured` grade.
    if let Some(path) = &args.tools_json {
        let source = format!("operator:{path}");
        for tool in read_tools_json(path)? {
            if !all_tools.contains(&tool) {
                all_tools.push(tool.clone());
            }
            if !provenance.contains_key(&tool) {
                provenance.insert(
                    tool,
                    serde_json::json!({ "grade": "declared", "source": source }),
                );
                declared_count += 1;
            }
        }
    }

    // --from-a2a: the agent's own A2A AgentCard skills. Stamped `discovered`
    // (read from the agent's published descriptor) with the AgentCard's url as
    // source -- a real provenance source, distinct from operator-`declared` and
    // weaker than receipt-`exercised`. A capability already captured or declared
    // keeps its existing grade; discovery does not overwrite a stronger source.
    let mut discovered_count = 0usize;
    if let Some(path) = &args.from_a2a {
        let (skills, source) = read_a2a_skills(path)?;
        for tool in skills {
            if !all_tools.contains(&tool) {
                all_tools.push(tool.clone());
            }
            if !provenance.contains_key(&tool) {
                provenance.insert(
                    tool,
                    serde_json::json!({ "grade": "discovered", "source": source }),
                );
                discovered_count += 1;
            }
        }
    }

    let mut capabilities = serde_json::Map::new();
    capabilities.insert("tools".into(), serde_json::json!(all_tools));
    if !args.models.is_empty() {
        capabilities.insert("models".into(), serde_json::json!(args.models));
    }

    let mut card = serde_json::Map::new();
    card.insert("schema".into(), serde_json::json!("agent_card.v1"));
    card.insert("agent".into(), serde_json::json!(args.agent));
    card.insert("keyid".into(), serde_json::json!(keyid));
    if let Some(owner) = &args.owner {
        card.insert("owner".into(), serde_json::json!(owner));
    }
    card.insert("version".into(), serde_json::json!(args.version));
    card.insert("capabilities".into(), Value::Object(capabilities));
    if let Some(policy_ref) = &args.policy_ref {
        card.insert("policy_ref".into(), serde_json::json!(policy_ref));
    }
    if !provenance.is_empty() {
        card.insert("capability_provenance".into(), Value::Object(provenance));
    }
    let payload = Value::Object(card);

    // Validate against the registered agent_card.v1 schema before signing.
    treeship_core::predicates::validate("agent_card.v1", Some(&payload))
        .map_err(|e| format!("invalid capability card: {e}"))?;

    let mut stmt = ReceiptStatement::new("system://registry", "agent_card.v1");
    stmt.payload = Some(payload);

    let pt = payload_type("receipt");
    let result = sign(&pt, &stmt, signer.as_ref())?;
    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    None,
        envelope:     result.envelope,
        hub_url:      None,
    })?;
    write_last(&ctx.config.storage_dir, &result.artifact_id);

    let trust = treeship_core::trust::TrustRootStore::open_default_or_empty()?;
    let key_bound = crate::commands::capability::is_key_bound(&keyid, signer.key_id(), &trust);

    let tools_str = all_tools.join(", ");
    let mut prov_parts = vec![format!("{captured_count} of {} captured from harness", all_tools.len())];
    if declared_count > 0 {
        prov_parts.push(format!("{declared_count} operator-declared (--tools-json)"));
    }
    if discovered_count > 0 {
        prov_parts.push(format!("{discovered_count} discovered from A2A AgentCard"));
    }
    let captured_str = prov_parts.join(", ");
    printer.success("capability card attested", &[
        ("id",        &result.artifact_id),
        ("agent",     &args.agent),
        ("key-bound", if key_bound { "yes (AgentCert)" } else { "no (self-asserted)" }),
        ("tools",     &tools_str),
        ("provenance", &captured_str),
    ]);
    printer.hint(&format!("treeship verify-capability {}", result.artifact_id));
    printer.blank();
    Ok(())
}

// --- decision ---------------------------------------------------------------

pub struct DecisionArgs {
    pub actor:         String,
    pub model:         Option<String>,
    pub model_version: Option<String>,
    pub provider:      Option<String>,
    pub tokens_in:     Option<u64>,
    pub tokens_out:    Option<u64>,
    pub prompt_digest: Option<String>,
    pub summary:       Option<String>,
    pub confidence:    Option<f64>,
    pub parent_id:     Option<String>,
    pub config:        Option<String>,
}

pub fn decision(args: DecisionArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;
    // The deciding agent signs; use its own key when registered.
    let signer = resolve_actor_signer(&ctx, &args.actor)?;

    let mut stmt = DecisionStatement::new(&args.actor);
    stmt.model = args.model.clone();
    stmt.model_version = args.model_version.clone();
    stmt.provider = args.provider.clone();
    stmt.tokens_in = args.tokens_in;
    stmt.tokens_out = args.tokens_out;
    stmt.prompt_digest = args.prompt_digest.clone();
    stmt.summary = args.summary.clone();
    stmt.confidence = args.confidence;

    // Auto-chain: resolve parent from explicit flag > TREESHIP_PARENT env > .last file
    let parent = resolve_parent(&ctx, args.parent_id.clone());
    stmt.parent_id = parent.clone();

    let pt = payload_type("decision");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    parent,
        envelope:     result.envelope,
        hub_url:      None,
    })?;

    // Write .last for auto-chaining
    write_last(&ctx.config.storage_dir, &result.artifact_id);

    // v0.10.2: also emit a SessionEvent::AgentDecision into the active
    // session's event log (best-effort). Without this, model/provider
    // attribution lived only on the signed artifact -- the session
    // receipt's agent_graph saw the actor but had no idea what
    // model/provider they were running. Now `treeship attest decision
    // --actor agent://x --model kimi-k2 --provider moonshot` flows
    // through to the session timeline and `agents` array directly.
    //
    // Best-effort: failure to emit (no active session, lock contention,
    // missing .treeship dir) MUST NOT fail the action. The signed
    // artifact and storage write above already succeeded; the session
    // event is a derived view, not the source of truth.
    emit_decision_session_event(&args, &result.artifact_id);

    printer.success("decision attested", &[
        ("id",    &result.artifact_id),
        ("actor", &args.actor),
        ("model", args.model.as_deref().unwrap_or("not specified")),
    ]);
    if let Some(ref summary) = args.summary {
        printer.dim_info(&format!("  summary: {}", summary));
    }
    if let Some(conf) = args.confidence {
        printer.dim_info(&format!("  confidence: {}%", (conf * 100.0) as u32));
    }
    printer.hint(&format!("treeship verify {}", result.artifact_id));
    printer.blank();
    Ok(())
}

/// v0.10.2 helper: mirror a freshly-signed `attest decision` into the
/// active session's event log so the receipt composer / agent_graph
/// can attribute model + provider + tokens. Best-effort -- a missing
/// session, lock contention, or write failure must not bubble up to
/// fail the artifact path.
///
/// Without this, model/provider attribution lives only on the signed
/// artifact and the session report says "agent X did N decisions"
/// with the model/provider columns empty. Wiring it here closes the
/// gap that v0.10.1's compatibility audit flagged.
fn emit_decision_session_event(args: &DecisionArgs, artifact_id: &str) {
    // Resolve env-var fallbacks so an integration that exports
    // TREESHIP_MODEL once at session start still gets attribution
    // even if the per-call --model isn't passed. Mirrors the logic
    // in commands/session.rs::event for agent.decision.
    let model = args.model.clone()
        .or_else(|| std::env::var("TREESHIP_MODEL").ok());
    let provider = args.provider.clone()
        .or_else(|| std::env::var("TREESHIP_PROVIDER").ok());
    let tokens_in = args.tokens_in
        .or_else(|| std::env::var("TREESHIP_TOKENS_IN").ok().and_then(|s| s.parse().ok()));
    let tokens_out = args.tokens_out
        .or_else(|| std::env::var("TREESHIP_TOKENS_OUT").ok().and_then(|s| s.parse().ok()));

    // If the operator gave us nothing about the inference (no model,
    // no provider, no tokens, no summary, no confidence), there's
    // nothing useful to put in the session event. The signed artifact
    // already exists; skip the empty event.
    if model.is_none() && provider.is_none() && tokens_in.is_none() && tokens_out.is_none()
        && args.summary.is_none() && args.confidence.is_none()
    {
        return;
    }

    let et = EventType::AgentDecision {
        model,
        tokens_in,
        tokens_out,
        provider,
        summary: args.summary.clone(),
        confidence: args.confidence,
    };

    // Best-effort: ignore all errors. The artifact path already
    // succeeded; this is a derived view.
    let _ = crate::commands::session::append_active_session_event(
        et,
        Some(&args.actor),
        Some(&args.actor.replace("agent://", "")),
        Some(artifact_id),
        "attest-cli",
    );
}

// --- endorsement -----------------------------------------------------------

pub struct EndorsementArgs {
    pub endorser:   String,
    pub subject_id: String,
    pub kind:       String,
    pub rationale:  Option<String>,
    pub expires:    Option<String>,
    pub policy_ref: Option<String>,
    pub meta:       Option<String>,
    pub parent_id:  Option<String>,
    pub out:        Option<String>,
    pub config:     Option<String>,
}

pub fn endorsement(args: EndorsementArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;

    let meta: Option<Value> = args.meta.as_deref()
        .map(|m| serde_json::from_str(m))
        .transpose()
        .map_err(|e| format!("--meta is not valid JSON: {e}"))?;

    let parent = resolve_parent(&ctx, args.parent_id.clone());

    let mut stmt = EndorsementStatement::new(&args.endorser, &args.kind);
    stmt.subject = SubjectRef {
        artifact_id: Some(args.subject_id.clone()),
        digest: None,
        uri: None,
    };
    stmt.rationale  = args.rationale.clone();
    stmt.expires_at = args.expires.clone();
    stmt.policy_ref = args.policy_ref.clone();
    stmt.meta       = meta;

    let signer = ctx.keys.default_signer()?;
    let pt     = payload_type("endorsement");
    let result = sign(&pt, &stmt, signer.as_ref())?;

    ctx.storage.write(&Record {
        artifact_id:  result.artifact_id.clone(),
        digest:       result.digest.clone(),
        payload_type: pt,
        key_id:       signer.key_id().to_string(),
        signed_at:    stmt.timestamp.clone(),
        parent_id:    parent,
        envelope:     result.envelope.clone(),
        hub_url:      None,
    })?;

    // Write .last for auto-chaining
    write_last(&ctx.config.storage_dir, &result.artifact_id);

    if let Some(path) = &args.out {
        let json = result.envelope.to_json()?;
        if path == "-" {
            println!("{}", String::from_utf8_lossy(&json));
        } else {
            std::fs::write(path, &json)?;
        }
    }

    printer.success("endorsement attested", &[
        ("id",       &result.artifact_id),
        ("endorser", &args.endorser),
        ("subject",  &args.subject_id),
        ("kind",     &args.kind),
    ]);
    if let Some(ref rationale) = args.rationale {
        printer.dim_info(&format!("  rationale: {}", rationale));
    }
    printer.hint(&format!("treeship verify {}", result.artifact_id));
    printer.blank();
    Ok(())
}

// --- helpers ----------------------------------------------------------------

/// Resolve parent_id with priority: explicit flag > TREESHIP_PARENT env > .last file
fn resolve_parent(ctx: &ctx::Ctx, explicit: Option<String>) -> Option<String> {
    if explicit.is_some() {
        return explicit;
    }
    if let Ok(env_parent) = std::env::var("TREESHIP_PARENT") {
        if !env_parent.is_empty() {
            return Some(env_parent);
        }
    }
    let last_path = std::path::Path::new(&ctx.config.storage_dir).join(".last");
    if let Ok(contents) = std::fs::read_to_string(&last_path) {
        let trimmed = contents.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }
    None
}

/// Resolve the journal directory for the active workspace -- pairs with
/// the same config_path the cards / harnesses stores use.
fn journal_dir_for(ctx: &ctx::Ctx) -> std::path::PathBuf {
    ctx.config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("journals")
        .join("approval-use")
}

/// Look up a grant's artifact_id by its raw nonce. Mirrors what
/// `verify::find_approval_by_nonce` does, but returns the artifact_id
/// alongside the parsed statement so we can stamp it on the journal
/// record. Reusing find_approval_by_nonce for the parse + then walking
/// storage a second time would be wasteful; we walk once here and
/// return both.
fn resolve_grant_by_nonce(
    ctx: &ctx::Ctx,
    raw_nonce: &str,
) -> Option<(String, ApprovalStatement)> {
    let approval_type = payload_type("approval");
    for entry in ctx.storage.list_by_type(&approval_type) {
        if let Ok(rec) = ctx.storage.read(&entry.id) {
            if let Ok(approval) = rec.envelope.unmarshal_statement::<ApprovalStatement>() {
                if approval.nonce == raw_nonce {
                    return Some((entry.id, approval));
                }
            }
        }
    }
    None
}

/// Reserve an ApprovalUse in the journal before signing the action.
///
/// Returns the `use_id` so the caller can:
///   * stamp it into the action's meta as `approval_use_id`
///   * backfill `action_artifact_id` onto the same journal record once
///     the action signs
///
/// Order of checks (cheap before expensive, scope before journal lock):
///   1. resolve grant by nonce          → fail fast if no such grant
///   2. check expiry                    → fail fast if expired
///   3. check scope                     → fail fast on actor/action/subject
///   4. compute nonce_digest
///   5. acquire journal lock (LockBusy if held)
///   6. idempotency-key short-circuit   → return existing use_id
///   7. check_replay                    → refuse on max_uses exceeded
///   8. write reserved ApprovalUse      → action_artifact_id = None
fn consume_approval(
    ctx: &ctx::Ctx,
    raw_nonce: &str,
    action: &ActionStatement,
    idempotency_key: Option<&str>,
    printer: &Printer,
) -> Result<String, Box<dyn std::error::Error>> {
    // 1. Resolve grant.
    let (grant_id, grant) = match resolve_grant_by_nonce(ctx, raw_nonce) {
        Some(found) => found,
        None => return Err(format!(
            "approval_nonce '{}...' set but no matching ApprovalStatement in local storage",
            &raw_nonce[..16.min(raw_nonce.len())],
        ).into()),
    };

    // 2. Expiry on the grant envelope itself.
    if let Some(ref expires) = grant.expires_at {
        let now = now_rfc3339();
        if *expires < now {
            return Err(format!(
                "approval grant {grant_id} expired at {expires} (now: {now})",
            ).into());
        }
    }

    // 3. Scope check (reuses the verify pass's logic so binding /
    // scope / consume all read from one source of truth).
    if let Some(ref scope) = grant.scope {
        if !scope.is_unscoped() {
            if let Some(reason) = check_scope_violation(scope, action) {
                return Err(format!("approval scope refused this action: {reason}").into());
            }
        }
    }

    let max_uses = grant.scope.as_ref().and_then(|s| s.max_actions);
    let nonce_digest = nonce_digest(raw_nonce);

    // 4-8. Journal-side: acquire lock, idempotency check, replay check,
    // reserve. Pulled into a helper so the lock scope is tight.
    reserve_in_journal(
        ctx,
        &grant_id,
        &grant,
        action,
        nonce_digest,
        max_uses,
        idempotency_key,
        printer,
    )
}

#[allow(clippy::too_many_arguments)]
fn reserve_in_journal(
    ctx: &ctx::Ctx,
    grant_id: &str,
    grant: &ApprovalStatement,
    action: &ActionStatement,
    nonce_digest: String,
    max_uses: Option<u32>,
    idempotency_key: Option<&str>,
    printer: &Printer,
) -> Result<String, Box<dyn std::error::Error>> {
    let dir = journal_dir_for(ctx);
    let j = Journal::new(&dir);

    // Idempotency-key short-circuit. Read existing uses for the grant
    // (the journal's by-grant index is the small list we need). If a
    // prior use carries the same idempotency_key, we reuse its use_id
    // -- the action signer will sign a fresh action against the same
    // reserved record. This is the crash-recovery primitive: a flaky
    // network or crashed CLI can retry safely.
    if let Some(key) = idempotency_key {
        let existing = journal::list_uses_for_grant(&j, grant_id)?;
        if let Some(prior) = existing.iter().find(|u| u.idempotency_key.as_deref() == Some(key)) {
            printer.dim_info(&format!(
                "  idempotency: reusing existing use_id {}", prior.use_id,
            ));
            return Ok(prior.use_id.clone());
        }
    }

    // The replay check + use_number derivation + append happen as one
    // atomic operation inside `journal::reserve_use`. v0.9.9 PR 3 split
    // these into separate calls (check_replay outside, append_use
    // inside its own lock), which let two parallel attests both pass
    // the replay check before either acquired the append lock --
    // bypassing `max_uses=1`. v0.9.10 closes the race.
    //
    // `use_number` is stamped by `reserve_use` from the grant-wide
    // count observed inside the lock; the value we put here is just a
    // placeholder.
    let use_number = 0u32;

    // Use_id is a fresh UUID-style hex token. Same shape as nonces.
    let use_id = {
        use rand::RngCore;
        let mut b = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut b);
        let mut hex = String::with_capacity(2 * b.len() + 4);
        hex.push_str("use_");
        for byte in &b {
            use std::fmt::Write;
            let _ = write!(hex, "{byte:02x}");
        }
        hex
    };

    // sha256 of the canonical-JSON envelope of the grant -- we don't
    // have the raw envelope here, but the artifact_id is itself a
    // content-addressed digest of that envelope, so we record it as
    // the grant_digest. PR 4 will validate this against the package's
    // copy of the grant.
    let grant_digest = grant_id.to_string();

    let record = ApprovalUse {
        type_:                  TYPE_APPROVAL_USE.into(),
        use_id:                 use_id.clone(),
        grant_id:               grant_id.to_string(),
        grant_digest,
        nonce_digest,
        actor:                  action.actor.clone(),
        action:                 action.action.clone(),
        subject:                action
            .subject
            .uri
            .clone()
            .or_else(|| action.subject.artifact_id.clone())
            .or_else(|| action.subject.digest.clone())
            .unwrap_or_default(),
        session_id:             None, // PR 5 wires this from active session
        action_artifact_id:     None, // backfilled after signing
        receipt_digest:         None,
        use_number,
        max_uses,
        idempotency_key:        idempotency_key.map(str::to_string),
        created_at:             now_rfc3339(),
        expires_at:             None,
        previous_record_digest: String::new(), // append_use stamps this
        record_digest:          String::new(), // append_use stamps this
        signature:              None,
        signature_alg:          None,
        signing_key_id:         None,
    };

    let head = journal::reserve_use(&j, record, max_uses).map_err(|e| -> Box<dyn std::error::Error> {
        format!("could not reserve approval use in journal: {e}").into()
    })?;
    // reserve_use stamped use_number inside the lock; recover it from
    // the just-written record so the user-visible message is accurate.
    let actual_use_number = journal::list_uses_for_grant(&j, grant_id)
        .ok()
        .and_then(|uses| uses.iter().find(|u| u.use_id == use_id).map(|u| u.use_number))
        .unwrap_or(0);
    let _ = head;

    printer.dim_info(&format!(
        "  approval use reserved: {use_id} (use {actual_use_number}/{})",
        max_uses.map(|m| m.to_string()).unwrap_or_else(|| "unbounded".into()),
    ));

    Ok(use_id)
}

/// After signing the action, rewrite the matching journal record so
/// `action_artifact_id` points at the freshly-signed action. The use
/// record's content changes, so its `record_digest` and downstream
/// chain links would change too -- which would invalidate journal
/// integrity. Instead we update a sidecar map (kept inside the index
/// directory) that the verify pass reads alongside the chain.
fn backfill_action_artifact_id(
    ctx: &ctx::Ctx,
    use_id: &str,
    action_artifact_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = journal_dir_for(ctx);
    let backfill_dir = dir.join("indexes").join("backfill");
    std::fs::create_dir_all(&backfill_dir)?;
    let path = backfill_dir.join(format!("{use_id}.txt"));
    std::fs::write(&path, action_artifact_id)?;
    Ok(())
}

/// Write the artifact_id to {storage_dir}/.last for auto-chaining.
fn write_last(storage_dir: &str, artifact_id: &str) {
    let last_path = std::path::Path::new(storage_dir).join(".last");
    let _ = std::fs::write(&last_path, artifact_id);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&last_path, std::fs::Permissions::from_mode(0o600));
    }
}

#[cfg(test)]
mod aud06_tests {
    use super::close_only_kind_owner;

    // AUD-06: session.v1 must be refused by the generic attest path so a
    // work-history record with a self-declared attestation_class cannot be
    // hand-signed.
    #[test]
    fn session_v1_is_close_only() {
        assert_eq!(close_only_kind_owner("session.v1"), Some("treeship session close"));
    }

    #[test]
    fn ordinary_kinds_are_freely_attestable() {
        assert_eq!(close_only_kind_owner("note.v1"), None);
        assert_eq!(close_only_kind_owner("deploy"), None);
        assert_eq!(close_only_kind_owner(""), None);
    }
}
