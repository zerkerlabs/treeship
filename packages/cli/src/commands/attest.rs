use serde_json::Value;
use treeship_core::{
    attestation::sign,
    journal::{self, Journal},
    statements::{
        ActionStatement, ApprovalScope, ApprovalStatement, ApprovalUse, DecisionStatement,
        EndorsementStatement, HandoffStatement, ReceiptStatement, ReplayCheckLevel,
        SubjectRef, TYPE_APPROVAL_USE, payload_type, nonce_digest,
    },
    storage::Record,
};

use crate::commands::verify::{check_scope_violation, find_approval_by_nonce, now_rfc3339};
use crate::{ctx, printer::Printer};

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
    stmt.meta = meta;

    let signer = ctx.keys.default_signer()?;
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

    let signer = ctx.keys.default_signer()?;
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
    pub system:     String,
    pub kind:       String,
    pub subject_id: Option<String>,
    pub payload:    Option<String>,
    pub config:     Option<String>,
}

pub fn receipt(args: ReceiptArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;

    let payload_val: Option<Value> = args.payload.as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e| format!("--payload is not valid JSON: {e}"))?;

    let mut stmt = ReceiptStatement::new(&args.system, &args.kind);
    stmt.payload = payload_val;
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

// --- decision ---------------------------------------------------------------

pub struct DecisionArgs {
    pub actor:         String,
    pub model:         Option<String>,
    pub model_version: Option<String>,
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
    let signer = ctx.keys.default_signer()?;

    let mut stmt = DecisionStatement::new(&args.actor);
    stmt.model = args.model.clone();
    stmt.model_version = args.model_version.clone();
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

    // Replay check BEFORE writing. check_replay reports
    // ReplayCheckLevel::NotPerformed when no journal exists yet, which
    // for a first-use is fine -- we proceed to write and the journal
    // gets created on first append. When journal exists, "passed"
    // false means max_uses would be exceeded.
    let replay = journal::check_replay(&j, grant_id, &nonce_digest, max_uses)?;
    if matches!(replay.level, ReplayCheckLevel::LocalJournal) {
        if matches!(replay.passed, Some(false)) {
            return Err(format!(
                "approval grant {grant_id} would exceed max_uses ({} of {})",
                replay.use_number.map(|n| n.saturating_sub(1)).unwrap_or(0),
                replay.max_uses.map(|m| m.to_string()).unwrap_or_else(|| "?".into()),
            ).into());
        }
    }

    // Compute use_number from the existing record list (the list above
    // already counted them; but we re-derive here to keep this function
    // self-contained when called without the idempotency-key path).
    let prior_count = journal::list_uses_for_grant(&j, grant_id)?.len() as u32;
    let use_number = prior_count.saturating_add(1);

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

    journal::append_use(&j, record).map_err(|e| -> Box<dyn std::error::Error> {
        format!("could not reserve approval use in journal: {e}").into()
    })?;

    printer.dim_info(&format!(
        "  approval use reserved: {use_id} (use {use_number}/{})",
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
