/// Returns the canonical MIME payloadType for a statement type suffix.
///
/// ```
/// use treeship_core::statements::payload_type;
/// assert_eq!(
///     payload_type("action"),
///     "application/vnd.treeship.action.v1+json"
/// );
/// ```
pub fn payload_type(suffix: &str) -> String {
    format!("application/vnd.treeship.{}.v1+json", suffix)
}

pub const TYPE_ACTION:      &str = "treeship/action/v1";
pub const TYPE_APPROVAL:    &str = "treeship/approval/v1";
pub const TYPE_HANDOFF:     &str = "treeship/handoff/v1";
pub const TYPE_ENDORSEMENT: &str = "treeship/endorsement/v1";
pub const TYPE_RECEIPT:     &str = "treeship/receipt/v1";
pub const TYPE_BUNDLE:      &str = "treeship/bundle/v1";
pub const TYPE_DECISION:    &str = "treeship/decision/v1";

// v0.9.9 Approval Authority schemas. See `approval_use` for details on
// the journal-side record types and the `replay_check` metadata shape
// that verify uses to report what level of replay check actually ran.
mod approval_use;
pub use approval_use::{
    ApprovalRevocation, ApprovalUse, CheckpointKind, HubCheckpointVerification,
    JournalCheckpoint, ReplayCheck, ReplayCheckLevel,
    TYPE_APPROVAL_REVOCATION, TYPE_APPROVAL_USE, TYPE_JOURNAL_CHECKPOINT,
    approval_revocation_record_digest, approval_use_record_digest,
    journal_checkpoint_record_digest, nonce_digest, verify_hub_checkpoint_signature,
};

use serde::{Deserialize, Serialize};

/// A reference to content being attested, approved, or receipted.
/// At least one field should be set.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SubjectRef {
    /// Content hash: "sha256:<hex>" or "sha3:<hex>"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    /// External URI to the content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,

    /// ID of another Treeship artifact
    #[serde(rename = "artifactId", skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
}

/// Scope constraints on an approval — *who* may perform *what* against
/// *which subject*, *how many times*, and *until when*.
///
/// Treeship's verify pass enforces these constraints statelessly (every
/// field except `max_actions` can be checked from the signed envelope
/// alone). `max_actions` is signed into the grant so a future ledger /
/// Hub layer can enforce single-use across the global view; for now it
/// is descriptive, and verify reports the replay-check posture honestly
/// rather than claiming enforcement that did not happen.
///
/// An empty `allowed_*` list means "no constraint on that axis."
/// All-empty scope is equivalent to no scope at all (an unscoped /
/// bearer approval) — which `verify` flags with a warning so callers
/// know the binding is the only thing being attested.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApprovalScope {
    /// Maximum number of actions this approval authorises. Signed into
    /// the grant for future stateful enforcement; not yet checked
    /// statelessly.
    #[serde(rename = "maxActions", skip_serializing_if = "Option::is_none")]
    pub max_actions: Option<u32>,

    /// ISO 8601 timestamp after which the approval is no longer valid.
    /// Independent of `ApprovalStatement.expires_at` so a single approval
    /// can have an outer "key valid until X" and a tighter "scope valid
    /// until Y" if the operator wants both. Verify enforces both.
    #[serde(rename = "validUntil", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<String>,

    /// Actor URIs permitted to consume this approval. Empty = no
    /// constraint on actor.
    #[serde(rename = "allowedActors", skip_serializing_if = "Vec::is_empty", default)]
    pub allowed_actors: Vec<String>,

    /// Action labels permitted under this approval. Empty = no
    /// constraint on action.
    #[serde(rename = "allowedActions", skip_serializing_if = "Vec::is_empty", default)]
    pub allowed_actions: Vec<String>,

    /// Subject URIs permitted as the target of an action under this
    /// approval. Matched against `ActionStatement.subject.uri` (or
    /// `artifact_id` for chain-internal subjects). Empty = no
    /// constraint on subject.
    #[serde(rename = "allowedSubjects", skip_serializing_if = "Vec::is_empty", default)]
    pub allowed_subjects: Vec<String>,

    /// Arbitrary additional constraints (e.g. max payment amount).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

impl ApprovalScope {
    /// True when no constraint axis is populated. An unscoped approval
    /// proves only nonce binding -- it does NOT bind actor, action, or
    /// subject. Verify warns when this is true so the audit reader
    /// knows the limit of what was signed.
    pub fn is_unscoped(&self) -> bool {
        self.max_actions.is_none()
            && self.valid_until.is_none()
            && self.allowed_actors.is_empty()
            && self.allowed_actions.is_empty()
            && self.allowed_subjects.is_empty()
            && self.extra.is_none()
    }
}

/// Records that an actor performed an action.
///
/// This is the most common statement type — every tool call, API request,
/// file write, or agent operation produces one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionStatement {
    /// Always `TYPE_ACTION`
    #[serde(rename = "type")]
    pub type_: String,

    /// RFC 3339 timestamp, set at sign time.
    pub timestamp: String,

    /// DID-style actor URI. e.g. "agent://researcher", "human://alice"
    pub actor: String,

    /// Dot-namespaced action label. e.g. "tool.call", "stripe.charge.create"
    pub action: String,

    #[serde(default, skip_serializing_if = "is_empty_subject")]
    pub subject: SubjectRef,

    /// Links this artifact to its parent in the chain.
    #[serde(rename = "parentId", skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,

    /// Must match the `nonce` field of the approval authorising this action.
    /// Provides cryptographic one-to-one binding between approval and action,
    /// preventing approval reuse across multiple actions.
    #[serde(rename = "approvalNonce", skip_serializing_if = "Option::is_none")]
    pub approval_nonce: Option<String>,

    #[serde(rename = "policyRef", skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

/// Records that an approver authorised an intent or action.
///
/// The `nonce` field is the cornerstone of approval security: the consuming
/// `ActionStatement` must echo the same nonce in its `approval_nonce` field.
/// This cryptographically binds each approval to exactly one action (or
/// `max_actions` actions when set), preventing approval reuse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalStatement {
    #[serde(rename = "type")]
    pub type_: String,
    pub timestamp: String,

    /// DID-style approver URI. e.g. "human://alice"
    pub approver: String,

    #[serde(default, skip_serializing_if = "is_empty_subject")]
    pub subject: SubjectRef,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// ISO 8601 expiry timestamp. None means no expiry.
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,

    /// Whether the receiving actor may re-delegate this approval.
    pub delegatable: bool,

    /// Random token. The consuming ActionStatement must set its
    /// `approval_nonce` field to this value. Generated by the SDK if
    /// not provided by the caller.
    pub nonce: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<ApprovalScope>,

    #[serde(rename = "policyRef", skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

/// Records that work moved from one actor/domain to another.
///
/// This is the core of Treeship's multi-agent trust story. A handoff
/// artifact proves custody transfer and carries inherited approvals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffStatement {
    #[serde(rename = "type")]
    pub type_: String,
    pub timestamp: String,

    /// Source actor URI
    pub from: String,
    /// Destination actor URI
    pub to: String,

    /// IDs of artifacts being transferred
    pub artifacts: Vec<String>,

    /// Approval artifact IDs the receiving actor inherits
    #[serde(rename = "approvalIds", default, skip_serializing_if = "Vec::is_empty")]
    pub approval_ids: Vec<String>,

    /// Constraints the receiving actor must satisfy
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub obligations: Vec<String>,

    pub delegatable: bool,

    #[serde(rename = "taskRef", skip_serializing_if = "Option::is_none")]
    pub task_ref: Option<String>,

    #[serde(rename = "policyRef", skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

/// Records that a signer asserts confidence about an existing artifact.
///
/// Used for post-hoc validation, compliance sign-off, countersignatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndorsementStatement {
    #[serde(rename = "type")]
    pub type_: String,
    pub timestamp: String,

    /// DID-style endorser URI
    pub endorser: String,
    pub subject: SubjectRef,

    /// Endorsement category: "validation", "compliance", "countersignature",
    /// "review", or any custom string.
    pub kind: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,

    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,

    #[serde(rename = "policyRef", skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

impl EndorsementStatement {
    pub fn new(endorser: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            type_: TYPE_ENDORSEMENT.into(),
            timestamp: now_rfc3339(),
            endorser: endorser.into(),
            subject: SubjectRef::default(),
            kind: kind.into(),
            rationale: None,
            expires_at: None,
            policy_ref: None,
            meta: None,
        }
    }
}

/// Records that an external system observed or confirmed an event.
///
/// Used for Stripe webhooks, RFC 3161 timestamps, inclusion proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptStatement {
    #[serde(rename = "type")]
    pub type_: String,
    pub timestamp: String,

    /// URI of the system producing this receipt.
    /// e.g. "system://stripe-webhook", "system://tsauthority"
    pub system: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<SubjectRef>,

    /// Receipt category: "confirmation", "timestamp", "inclusion", "webhook"
    pub kind: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,

    #[serde(rename = "payloadDigest", skip_serializing_if = "Option::is_none")]
    pub payload_digest: Option<String>,

    #[serde(rename = "policyRef", skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

/// A reference to one artifact within a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub id:     String,
    pub digest: String,
    #[serde(rename = "type")]
    pub type_:  String,
}

/// Groups a set of artifacts into a named, signed bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleStatement {
    #[serde(rename = "type")]
    pub type_: String,
    pub timestamp: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    pub artifacts: Vec<ArtifactRef>,

    #[serde(rename = "policyRef", skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

/// Records an agent's reasoning and decision context.
///
/// This is the "why" layer -- agents provide this explicitly to explain
/// inference decisions, model usage, and confidence levels.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionStatement {
    /// Always `TYPE_DECISION`
    #[serde(rename = "type")]
    pub type_: String,

    /// RFC 3339 timestamp, set at sign time.
    pub timestamp: String,

    /// DID-style actor URI. e.g. "agent://analyst"
    pub actor: String,

    /// Links this artifact to its parent in the chain.
    #[serde(rename = "parentId", skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,

    /// Model used for inference. e.g. "claude-opus-4"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    /// Model version if known.
    #[serde(rename = "modelVersion", skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,

    /// Number of input tokens consumed.
    #[serde(rename = "tokensIn", skip_serializing_if = "Option::is_none")]
    pub tokens_in: Option<u64>,

    /// Number of output tokens produced.
    #[serde(rename = "tokensOut", skip_serializing_if = "Option::is_none")]
    pub tokens_out: Option<u64>,

    /// SHA-256 digest of the full prompt (not the prompt itself).
    #[serde(rename = "promptDigest", skip_serializing_if = "Option::is_none")]
    pub prompt_digest: Option<String>,

    /// Human-readable summary of the decision.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// Confidence level 0.0-1.0 if the agent provides it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,

    /// Other options the agent considered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alternatives: Option<Vec<String>>,

    /// Arbitrary additional metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

// Helpers for skip_serializing_if
fn is_empty_subject(s: &SubjectRef) -> bool {
    s.digest.is_none() && s.uri.is_none() && s.artifact_id.is_none()
}

// --- Constructors ---

impl ActionStatement {
    pub fn new(actor: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            type_: TYPE_ACTION.into(),
            timestamp: now_rfc3339(),
            actor: actor.into(),
            action: action.into(),
            subject: SubjectRef::default(),
            parent_id: None,
            approval_nonce: None,
            policy_ref: None,
            meta: None,
        }
    }
}

impl ApprovalStatement {
    pub fn new(approver: impl Into<String>, nonce: impl Into<String>) -> Self {
        Self {
            type_: TYPE_APPROVAL.into(),
            timestamp: now_rfc3339(),
            approver: approver.into(),
            subject: SubjectRef::default(),
            description: None,
            expires_at: None,
            delegatable: false,
            nonce: nonce.into(),
            scope: None,
            policy_ref: None,
            meta: None,
        }
    }
}

impl HandoffStatement {
    pub fn new(
        from:      impl Into<String>,
        to:        impl Into<String>,
        artifacts: Vec<String>,
    ) -> Self {
        Self {
            type_: TYPE_HANDOFF.into(),
            timestamp: now_rfc3339(),
            from: from.into(),
            to: to.into(),
            artifacts,
            approval_ids: vec![],
            obligations: vec![],
            delegatable: false,
            task_ref: None,
            policy_ref: None,
            meta: None,
        }
    }
}

impl ReceiptStatement {
    pub fn new(system: impl Into<String>, kind: impl Into<String>) -> Self {
        Self {
            type_: TYPE_RECEIPT.into(),
            timestamp: now_rfc3339(),
            system: system.into(),
            subject: None,
            kind: kind.into(),
            payload: None,
            payload_digest: None,
            policy_ref: None,
            meta: None,
        }
    }
}

impl DecisionStatement {
    pub fn new(actor: impl Into<String>) -> Self {
        Self {
            type_: TYPE_DECISION.into(),
            timestamp: now_rfc3339(),
            actor: actor.into(),
            parent_id: None,
            model: None,
            model_version: None,
            tokens_in: None,
            tokens_out: None,
            prompt_digest: None,
            summary: None,
            confidence: None,
            alternatives: None,
            meta: None,
        }
    }
}

fn now_rfc3339() -> String {
    // std::time gives us duration since UNIX_EPOCH.
    // Format as ISO 8601 / RFC 3339 without pulling in chrono.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    unix_to_rfc3339(secs)
}

pub fn unix_to_rfc3339(secs: u64) -> String {
    // Minimal RFC 3339 formatter — no external deps.
    // Accurate for dates 1970–2099.
    let s = secs;
    let (y, mo, d, h, mi, sec) = seconds_to_ymd_hms(s);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, sec)
}

fn seconds_to_ymd_hms(s: u64) -> (u64, u64, u64, u64, u64, u64) {
    let sec  = s % 60;
    let mins = s / 60;
    let min  = mins % 60;
    let hrs  = mins / 60;
    let hour = hrs % 24;
    let days = hrs / 24;

    // Gregorian calendar calculation from day count
    let (y, m, d) = days_to_ymd(days);
    (y, m, d, hour, min, sec)
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Days since 1970-01-01
    let mut d = days;
    let mut year = 1970u64;
    loop {
        let dy = if is_leap(year) { 366 } else { 365 };
        if d < dy { break; }
        d -= dy;
        year += 1;
    }
    let months = if is_leap(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 1u64;
    for dm in months {
        if d < dm { break; }
        d -= dm;
        month += 1;
    }
    (year, month, d + 1)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{sign, Ed25519Signer, Verifier};

    #[test]
    fn payload_type_format() {
        assert_eq!(
            payload_type("action"),
            "application/vnd.treeship.action.v1+json"
        );
        assert_eq!(
            payload_type("approval"),
            "application/vnd.treeship.approval.v1+json"
        );
    }

    #[test]
    fn action_statement_sign_verify() {
        let signer   = Ed25519Signer::generate("key_test").unwrap();
        let verifier = Verifier::from_signer(&signer);

        let mut stmt = ActionStatement::new("agent://researcher", "tool.call");
        stmt.parent_id = Some("art_aabbccdd11223344aabbccdd11223344".into());

        let pt     = payload_type("action");
        let result = sign(&pt, &stmt, &signer).unwrap();

        assert!(result.artifact_id.starts_with("art_"));

        let vr = verifier.verify(&result.envelope).unwrap();
        assert_eq!(vr.artifact_id, result.artifact_id);

        // Decode and check the payload survived serialization
        let decoded: ActionStatement = result.envelope.unmarshal_statement().unwrap();
        assert_eq!(decoded.actor, "agent://researcher");
        assert_eq!(decoded.action, "tool.call");
        assert_eq!(decoded.type_, TYPE_ACTION);
    }

    #[test]
    fn approval_statement_with_nonce() {
        let signer = Ed25519Signer::generate("key_human").unwrap();

        let mut approval = ApprovalStatement::new("human://alice", "nonce_abc123");
        approval.description = Some("approve laptop purchase < $1500".into());
        approval.scope = Some(ApprovalScope {
            max_actions: Some(1),
            allowed_actions: vec!["stripe.payment_intent.create".into()],
            ..Default::default()
        });

        let pt     = payload_type("approval");
        let result = sign(&pt, &approval, &signer).unwrap();
        assert!(result.artifact_id.starts_with("art_"));

        let decoded: ApprovalStatement = result.envelope.unmarshal_statement().unwrap();
        assert_eq!(decoded.nonce, "nonce_abc123");
        assert_eq!(decoded.scope.unwrap().max_actions, Some(1));
    }

    #[test]
    fn approval_scope_full_grant_roundtrips() {
        // Every scope axis populated -- the full "allowed_actors +
        // allowed_actions + allowed_subjects + max_uses" grant must
        // serialize, sign, deserialize, and read back identically.
        let signer = Ed25519Signer::generate("key_piyush").unwrap();

        let mut approval = ApprovalStatement::new("human://piyush", "nonce_deadbeef");
        approval.description = Some("Deploy production after final review".into());
        approval.scope = Some(ApprovalScope {
            max_actions:      Some(1),
            valid_until:      None,
            allowed_actors:   vec!["agent://deployer".into()],
            allowed_actions:  vec!["deploy.production".into()],
            allowed_subjects: vec!["env://production".into()],
            extra:            None,
        });

        let pt = payload_type("approval");
        let result = sign(&pt, &approval, &signer).unwrap();
        let decoded: ApprovalStatement = result.envelope.unmarshal_statement().unwrap();
        let scope = decoded.scope.expect("scope must round-trip");

        assert_eq!(scope.allowed_actors,   vec!["agent://deployer".to_string()]);
        assert_eq!(scope.allowed_actions,  vec!["deploy.production".to_string()]);
        assert_eq!(scope.allowed_subjects, vec!["env://production".to_string()]);
        assert_eq!(scope.max_actions,      Some(1));
    }

    #[test]
    fn approval_scope_is_unscoped_predicate() {
        // Default scope = unscoped.
        assert!(ApprovalScope::default().is_unscoped());

        // Any single populated axis flips the predicate.
        assert!(!ApprovalScope { max_actions: Some(1), ..Default::default() }.is_unscoped());
        assert!(!ApprovalScope { valid_until: Some("2030-01-01T00:00:00Z".into()), ..Default::default() }.is_unscoped());
        assert!(!ApprovalScope { allowed_actors:   vec!["agent://x".into()], ..Default::default() }.is_unscoped());
        assert!(!ApprovalScope { allowed_actions:  vec!["doit".into()],      ..Default::default() }.is_unscoped());
        assert!(!ApprovalScope { allowed_subjects: vec!["env://prod".into()], ..Default::default() }.is_unscoped());
    }

    #[test]
    fn approval_scope_legacy_payloads_decode_with_empty_new_fields() {
        // Pre-0.9.6 payloads that omitted allowed_actors / allowed_subjects
        // must continue to deserialize cleanly. We construct the JSON shape
        // directly to simulate an envelope from an older signer.
        let legacy = serde_json::json!({
            "maxActions": 1,
            "allowedActions": ["stripe.payment_intent.create"]
        });
        let scope: ApprovalScope = serde_json::from_value(legacy).unwrap();
        assert_eq!(scope.max_actions, Some(1));
        assert_eq!(scope.allowed_actions, vec!["stripe.payment_intent.create".to_string()]);
        // New fields default to empty -- not present in legacy payload.
        assert!(scope.allowed_actors.is_empty());
        assert!(scope.allowed_subjects.is_empty());
        assert!(!scope.is_unscoped()); // because max_actions IS set
    }

    #[test]
    fn handoff_statement() {
        let signer = Ed25519Signer::generate("key_agent").unwrap();

        let handoff = HandoffStatement::new(
            "agent://researcher",
            "agent://checkout",
            vec!["art_aabbccdd11223344aabbccdd11223344".into()],
        );

        let pt     = payload_type("handoff");
        let result = sign(&pt, &handoff, &signer).unwrap();
        let decoded: HandoffStatement = result.envelope.unmarshal_statement().unwrap();

        assert_eq!(decoded.from, "agent://researcher");
        assert_eq!(decoded.to,   "agent://checkout");
        assert_eq!(decoded.artifacts.len(), 1);
    }

    #[test]
    fn receipt_statement() {
        let signer = Ed25519Signer::generate("key_system").unwrap();

        let mut receipt = ReceiptStatement::new("system://stripe-webhook", "confirmation");
        receipt.payload = Some(serde_json::json!({
            "eventId": "evt_abc123",
            "status": "succeeded"
        }));

        let pt     = payload_type("receipt");
        let result = sign(&pt, &receipt, &signer).unwrap();
        let decoded: ReceiptStatement = result.envelope.unmarshal_statement().unwrap();

        assert_eq!(decoded.system, "system://stripe-webhook");
        assert_eq!(decoded.kind,   "confirmation");
    }

    #[test]
    fn nonce_binding_survives_serialization() {
        let signer   = Ed25519Signer::generate("key_test").unwrap();

        // The nonce in the approval must survive a sign→verify→decode round-trip.
        // The verifier checks that action.approval_nonce == approval.nonce.
        let approval = ApprovalStatement::new("human://alice", "secure_nonce_xyz");
        let pt       = payload_type("approval");
        let signed   = sign(&pt, &approval, &signer).unwrap();

        let decoded: ApprovalStatement = signed.envelope.unmarshal_statement().unwrap();
        assert_eq!(decoded.nonce, "secure_nonce_xyz", "nonce must survive serialization");
    }

    #[test]
    fn decision_statement_sign_verify() {
        let signer = Ed25519Signer::generate("key_test").unwrap();
        let verifier = Verifier::from_signer(&signer);

        let mut stmt = DecisionStatement::new("agent://analyst");
        stmt.model = Some("claude-opus-4".into());
        stmt.tokens_in = Some(8432);
        stmt.tokens_out = Some(1247);
        stmt.summary = Some("Contract looks standard.".into());
        stmt.confidence = Some(0.91);

        let pt = payload_type("decision");
        let result = sign(&pt, &stmt, &signer).unwrap();

        assert!(result.artifact_id.starts_with("art_"));

        let vr = verifier.verify(&result.envelope).unwrap();
        assert_eq!(vr.artifact_id, result.artifact_id);

        // Decode and check the payload survived serialization
        let decoded: DecisionStatement = result.envelope.unmarshal_statement().unwrap();
        assert_eq!(decoded.actor, "agent://analyst");
        assert_eq!(decoded.model, Some("claude-opus-4".into()));
        assert_eq!(decoded.tokens_in, Some(8432));
        assert_eq!(decoded.tokens_out, Some(1247));
        assert_eq!(decoded.summary, Some("Contract looks standard.".into()));
        assert_eq!(decoded.confidence, Some(0.91));
        assert_eq!(decoded.type_, TYPE_DECISION);
    }

    #[test]
    fn different_statement_types_different_ids() {
        // Action and approval with identical fields but different types
        // must produce different artifact IDs — enforced by payloadType in PAE.
        let signer = Ed25519Signer::generate("key_test").unwrap();

        let action   = ActionStatement::new("agent://test", "do.thing");
        let approval = ApprovalStatement::new("human://test", "nonce_123");

        let r_action   = sign(&payload_type("action"),   &action,   &signer).unwrap();
        let r_approval = sign(&payload_type("approval"), &approval, &signer).unwrap();

        assert_ne!(r_action.artifact_id, r_approval.artifact_id);
    }

    #[test]
    fn timestamp_format() {
        let ts = unix_to_rfc3339(0);
        assert_eq!(ts, "1970-01-01T00:00:00Z");

        let ts2 = unix_to_rfc3339(1_000_000_000);
        assert_eq!(ts2, "2001-09-09T01:46:40Z");
    }
}
