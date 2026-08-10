//! `treeship/action/v2` -- the mandate / effect receipt.
//!
//! v1 proves *what an agent claims it did*, signed by its own key. That is
//! still self-report with a signature on it. v2 binds two additional blocks
//! into the signed payload:
//!
//! * `mandate` -- the per-hop authorization the action was exercised under
//!   (the grant it was minted from, its scope, audience, TTL, delegation
//!   depth, and how to check revocation). Lets a verifier answer "was this
//!   action *authorized*?", not just "was it signed?".
//! * `effect` -- what the action actually touched (input/output hashes, an
//!   optional externally-observed `readback`, cost, side effects, and a
//!   `context_snapshot` tying the action to the state it acted from). Lets a
//!   verifier move from "the agent narrated X" toward "X actually happened".
//!
//! Both blocks live inside the DSSE `payload` (the PAE-signed body), so an
//! attacker cannot strip or edit them without breaking the signature -- the
//! same binding guarantee the rest of the statement enjoys. A v2-aware
//! verifier that ignores them would be a silent open-fail; `verify_mandate`
//! is written to fail closed and to report `Unverified` (never `Pass`) when a
//! layer cannot be checked, mirroring the AUD-01 honesty posture used
//! elsewhere in the crate.
//!
//! ## Validity is judged at `signed_at`, not "now"
//!
//! A receipt signed while its grant was valid stays valid forever -- exactly
//! like a TLS certificate whose later revocation does not retroactively
//! invalidate everything it ever signed. So the TTL and revocation checks are
//! evaluated against `timestamp` (the instant the receipt was signed), and
//! `revoked_at` is a *timestamp*, never a boolean. This is the stillos /
//! Concordium correction promoted to an invariant.
//!
//! Build order (docs: receipt-v2 spec §9): this module lands step 1 (the
//! statement + canonical binding + fail-closed verifier) and step 2 (the
//! first-class grant object + attenuation checks). `receipt export`
//! emission, external revocation-timestamp resolvers, the ZMEM
//! `context_snapshot` provider, and the Hermes parent->child->tool demo are
//! later steps that build on these primitives.

use serde::{Deserialize, Serialize};

use super::invitation::{canonical_json_digest, parse_rfc3339_to_unix};
use super::SubjectRef;
use crate::attestation::{Signer, SignerError};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// Statement type tag for the mandate/effect receipt.
pub const TYPE_ACTION_V2: &str = "treeship/action/v2";

/// Canonical MIME payloadType for a v2 statement suffix. Distinct from the
/// v1 `payload_type` so the DSSE PAE domain-separates v1 from v2 signatures:
/// a v1-only verifier checking the signature of a v2 receipt still sees valid
/// signature math, but the differing payloadType (and `type` tag) is what
/// lets it recognize the receipt as v2 and surface the mandate blocks as
/// unverified rather than silently treating it as fully verified.
pub fn payload_type_v2(suffix: &str) -> String {
    format!("application/vnd.treeship.{}.v2+json", suffix)
}

// ---------------------------------------------------------------------------
// Schema -- mandate / effect blocks
// ---------------------------------------------------------------------------

/// How a verifier checks revocation-at-signing-time. `revoked_at` is a
/// timestamp (RFC 3339), never a boolean: a grant revoked at time T does not
/// retroactively invalidate a receipt signed before T.
///
/// The embedded `revoked_at` is authored by the same party that signed the
/// receipt, so it is only trustworthy for the *positive* direction (an honest
/// signer recording that the grant was later revoked). It MUST NOT be trusted
/// to assert non-revocation; that is the job of an external
/// [`RevocationSource`]. See [`verify_mandate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    /// Where a verifier resolves the revocation timestamp: `concordium://…`,
    /// `hub://…`, or `url_json://…`.
    pub path: String,

    /// RFC 3339 instant the grant was revoked, or `None` if not (yet) revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
}

/// The per-hop authorization an action was exercised under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mandate {
    /// Id of the capability grant this hop was minted from.
    pub grant_id: String,

    /// Who issued the grant (parent hop / operator). Ed25519 pubkey,
    /// base64url-no-pad, so a verifier can check `issuer_sig` offline.
    pub grantor: String,

    /// Grantor's signature over the grant's canonical bytes (see [`Grant`]).
    /// Optional in the receipt because a verifier may resolve the grant (and
    /// its signature) out of band by `grant_id`; when present it lets the
    /// grant chain be walked fully offline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_sig: Option<String>,

    /// Hash of the declared task/intent this hop serves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective_hash: Option<String>,

    /// Allowed action set. Each entry is an exact label (`payments.charge`)
    /// or a family glob (`payments.*`). An empty scope authorizes nothing.
    #[serde(default)]
    pub scope: Vec<String>,

    /// Who this grant is FOR. Prevents cross-audience replay (a grant minted
    /// for audience A cannot authorize an action against audience B).
    pub audience: String,

    /// The delegation edge this hop descends from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_request_id: Option<String>,

    /// Hops from the root grant. Caps re-delegation together with
    /// `max_delegation`.
    #[serde(default)]
    pub delegation_depth: u32,

    /// RFC 3339 instant the grant became valid.
    pub issued_at: String,

    /// RFC 3339 instant the grant expires (exclusive upper bound).
    pub expiry: String,

    /// Deepest this grant may be re-minted.
    #[serde(default)]
    pub max_delegation: u32,

    /// Revocation source + (optional) revoked-at timestamp.
    pub revocation: Revocation,

    /// Base64url-no-pad Ed25519 public key the grant was issued to, mirrored
    /// from `Grant::grantee` so a verifier can check the receipt's signer
    /// against it without resolving the chain.
    ///
    /// `None` means the grant was bearer. A verifier must report that rather
    /// than pass silently: a valid signature proves who signed the receipt and
    /// who issued the grant, never that the two are related.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grantee: Option<String>,

    /// Ancestors of this grant, root-first, each carrying its own
    /// `issuer_sig`. Optional and skipped when empty so existing v2 receipts
    /// keep byte-identical canonical bytes.
    ///
    /// Carried inline rather than fetched: `issuer_sig` already exists so one
    /// receipt can be checked offline, and that promise breaks the moment
    /// verifying a delegated action requires N network round-trips. The
    /// carrier's *ordering* is not trusted -- see `resolve_grant_chain`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain: Vec<Grant>,
}

/// A metered cost attached to an effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cost {
    pub unit: String,
    pub amount: u64,
}

/// An independent observation of an action's effect, made by someone other
/// than the actor. A witness is the raw material of effect verification: the
/// actor's own `effect_confidence` is a claim it can mint, but a witness
/// whose key is NOT the actor's, whose `signature` verifies against a trusted
/// root, and whose `observation` matches the effect is a signal the actor
/// could not have forged. Multiple independent witnesses are how a `Verified`
/// confidence earns its evidence beyond a single self-reported `readback`.
///
/// This struct is only the record. It carries NO independent weight on its
/// own: an unsigned witness, or one signed by the actor's own key, proves
/// nothing. The reconciliation -- does `observer` resolve to a trusted,
/// non-actor key? does `signature` verify over the canonical tuple? does
/// `observation` match the effect? -- happens in verify, never here. Do not
/// treat the mere presence of a witness as evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Witness {
    /// URI or key id of the observer, e.g. "agent://auditor", "key_9f2c".
    /// Verify resolves this to a trust root and requires it to differ from
    /// the action's actor.
    pub observer: String,
    /// `sha256:<hex>` of what the observer independently saw. Verify checks
    /// this equals the effect's own observed post-state (`readback` /
    /// `output_hash`); a witness that observed something else corroborates
    /// nothing.
    pub observation: String,
    /// RFC 3339 instant the observation was made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
    /// The observer's signature over its own (observer, observation,
    /// observed_at) tuple, verifiable against `observer`'s key. Absent means
    /// unsigned: verify gives it zero independent weight.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl Witness {
    /// True when the witness at least carries a signature to check. This is a
    /// necessary-not-sufficient precondition: verify still has to confirm the
    /// signature verifies, the observer is a trusted non-actor key, and the
    /// observation matches. A `true` here is NOT evidence by itself.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }
}

/// What the action actually touched. Descriptive; every field is optional
/// because not every action has cheap external ground truth. `readback` is
/// the strongest claim: a hash of externally-observed post-state the actor
/// did not author.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effect {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_hash: Option<String>,
    /// Hash of externally-observed post-state (DB readback, provider-API
    /// state fetch, on-chain balance, second-runtime observation) -- a signal
    /// the actor cannot mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readback: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_moved: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<Cost>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub side_effects: Vec<String>,
    /// Hash of the state the agent acted *from* (produced by ZMEM). Lets a
    /// verifier detect action on stale/poisoned context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_snapshot: Option<String>,
    /// The actor's honest self-declaration of whether the effect actually
    /// happened ("the ack is not the act"). This is a CLAIM, not proof: the
    /// verifier cross-checks it against the independent evidence above (a
    /// `readback` the actor could not mint), and a `Verified` claim carrying no
    /// such evidence is downgraded, never taken on faith. Absent means the
    /// actor made no effect claim at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_confidence: Option<EffectConfidence>,
    /// Independent observers who corroborate this effect. Each is a claim the
    /// actor bundled in; verify decides which (if any) are trustworthy signals
    /// the actor could not mint. An empty list -- the common case -- means the
    /// only effect evidence is the actor's own `readback`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witnesses: Vec<Witness>,
    /// How far the state change got, as distinct from how well it is evidenced.
    /// Optional and skipped when absent so existing v2 receipts keep
    /// byte-identical canonical bytes.
    ///
    /// A `Finalized` claim is capped by [`verify_effect`] the same way
    /// `EffectConfidence::Verified` is: both assert something definite, so both
    /// can be inflated, so both require evidence the actor could not mint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finality: Option<EffectFinality>,
    /// When an unresolved effect must resolve by, and what fires if it does
    /// not. Absent means no obligation was declared -- which
    /// [`check_resolution`] reports as `Indefinite` rather than passing over,
    /// because an unresolved effect with no deadline is the failure shape, not
    /// the safe default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<Resolution>,
}

/// How confident the actor is that an action's real-world effect happened,
/// separate from whether the receipt's signature is valid. Encodes the honest
/// middle ground the "ack is not the act" discourse keeps asking for: an agent
/// that cannot confirm the effect declares `Unknown` or `NotVerified` instead
/// of forcing a green success.
///
/// A verifier NEVER trusts `Verified` on the actor's word alone — see
/// [`Effect::has_independent_evidence`] and the effect-confidence check in
/// `treeship verify`, which reconciles this claim with the evidence present.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectConfidence {
    /// Independently confirmed: an external read-back or witness the actor
    /// could not mint shows the intended post-state.
    Verified,
    /// Some effect evidence, but incomplete (e.g. the sink accepted the write
    /// but nothing read the post-state back).
    Partial,
    /// The observed state is consistent with more than one outcome.
    Ambiguous,
    /// The actor could not determine whether the effect happened.
    Unknown,
    /// Attempted, but the effect was not independently verified — the common
    /// honest default: the tool returned ok and nothing read it back.
    NotVerified,
}

/// How far a state change actually got. Orthogonal to [`EffectConfidence`],
/// which grades the *evidence*: an effect can be `Finalized` with weak evidence,
/// or `Initiated` with excellent evidence that it is still pending.
///
/// Collapsing the two is a real production failure, not a theoretical one. A
/// receipt that reports a single `success: true` can be accurate in every field
/// and false as a composite: the write was accepted, acknowledged, assigned an
/// id, and served back on read -- and never committed. Every predicate held;
/// "done" did not. Separating the axes is what makes that claim expressible,
/// and the [`verify_effect`] cap on `Finalized` is what makes it checkable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectFinality {
    /// Authority was exercised but no state change was attempted -- a timeout
    /// or refusal before the call went out. This is the "no authority moved"
    /// receipt: an explicit signed negative, so absence stops being
    /// indistinguishable from a check that was never required.
    NotAttempted,
    /// The target accepted the change but has not confirmed it as final.
    /// Unresolved: an acknowledgement is not a commit.
    Initiated,
    /// The target confirmed the change is final.
    Finalized,
    /// Attempted, and definitively did not take effect.
    Failed,
    /// Attempted; whether it took effect could not be established. Distinct
    /// from `Initiated`, where the target at least said yes-but-not-yet. Here
    /// nobody knows, which is a state to escalate from, not to retry blindly.
    Indeterminate,
}

impl EffectFinality {
    /// Whether the lifecycle reached a terminal state. `Initiated` and
    /// `Indeterminate` are open: something is still owed. Only open effects can
    /// breach a resolution deadline.
    pub fn is_resolved(self) -> bool {
        matches!(self, Self::NotAttempted | Self::Finalized | Self::Failed)
    }
}

/// When an unresolved effect must resolve by, and what fires if it does not.
///
/// Exists because an effect that never resolves emits nothing forever, which is
/// strictly worse than a timeout: a timeout produces a countable transition,
/// and silence produces nothing for a monitor to catch. A declared deadline
/// turns "still pending after 181 days" from an invisible state into a
/// checkable one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resolution {
    /// RFC3339. After this instant an unresolved effect is stale by definition.
    pub deadline: String,
    /// What the declaring party said must happen once the deadline passes.
    pub on_deadline: DeadlineEvent,
}

/// The obligation that attaches when a resolution deadline passes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineEvent {
    /// Treat as timed out. The effect did not land; no authority moved.
    Timeout,
    /// Hand to a human or a higher authority. Do not decide automatically.
    Escalate,
    /// Mark dead and stop serving it as live state.
    Tombstone,
    /// The next agent in a handoff chain takes responsibility for resolving it.
    Inherit,
}

/// Whether an effect is still owed a resolution, and whether it is overdue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionStatus {
    /// The lifecycle reached a terminal state; a deadline is moot.
    Resolved,
    /// Unresolved with no declared deadline. Reported rather than passed over:
    /// this is precisely the pending-forever shape, and staying quiet about it
    /// is what let it survive unnoticed in the first place.
    Indefinite,
    /// Unresolved and inside its declared window.
    Pending { seconds_remaining: i64 },
    /// Unresolved and past its deadline. Carries the event the declaring party
    /// committed to, so a consumer knows which obligation it inherited.
    Breached {
        on_deadline: DeadlineEvent,
        seconds_overdue: i64,
    },
    /// A deadline was declared but does not parse, so nothing can be concluded
    /// from it. Fails toward "unknown", never toward "in window".
    BadDeadline,
}

/// Evaluate an effect's resolution obligation against a wall-clock instant.
///
/// Kept separate from [`verify_effect`] rather than folded into it: that
/// function is a pure reconciliation over bytes and stays deterministic, while
/// this one is time-dependent and the caller must supply `now_unix` explicitly.
/// A verifier that silently reached for the system clock would give different
/// answers on replay.
///
/// An effect with no finality declared is treated as unresolved. That is the
/// conservative reading: a receipt that never says where its state change got
/// to has not told us it landed.
pub fn check_resolution(effect: &Effect, now_unix: i64) -> ResolutionStatus {
    let resolved = effect
        .finality
        .map(EffectFinality::is_resolved)
        .unwrap_or(false);
    if resolved {
        return ResolutionStatus::Resolved;
    }

    let res = match &effect.resolution {
        Some(r) => r,
        None => return ResolutionStatus::Indefinite,
    };

    // `parse_rfc3339_to_unix` yields u64; compare in i64 so the difference is
    // signed and cannot wrap when the deadline sits either side of `now`.
    let deadline = match parse_rfc3339_to_unix(&res.deadline) {
        Some(t) if t <= i64::MAX as u64 => t as i64,
        _ => return ResolutionStatus::BadDeadline,
    };

    if now_unix > deadline {
        ResolutionStatus::Breached {
            on_deadline: res.on_deadline,
            seconds_overdue: now_unix - deadline,
        }
    } else {
        ResolutionStatus::Pending {
            seconds_remaining: deadline - now_unix,
        }
    }
}

impl Effect {
    /// True when the effect carries a signal the actor could not have minted
    /// itself (an external read-back). This is what lets a verifier honor a
    /// `Verified` confidence claim; without it, `Verified` is downgraded.
    ///
    /// Deliberately gated on `readback` alone, NOT on `witnesses`: a witness
    /// only becomes evidence once verify confirms its signature against a
    /// trusted non-actor key, which this pure-data check cannot do. Counting
    /// an unverified witness here would let the actor inflate its own ceiling
    /// with a fabricated observer -- exactly the "ok for the wrong reason" we
    /// refuse.
    pub fn has_independent_evidence(&self) -> bool {
        self.readback.is_some()
    }

    /// The witnesses that at least carry a signature verify can attempt to
    /// check. Callers must still run that check; a non-empty result is a
    /// precondition for witness-backed evidence, never evidence itself.
    pub fn signed_witnesses(&self) -> impl Iterator<Item = &Witness> {
        self.witnesses.iter().filter(|w| w.is_signed())
    }

    /// The strongest effect confidence the *evidence* supports, independent of
    /// what the actor claimed. `Verified` requires independent evidence;
    /// otherwise the honest ceiling is `NotVerified`. Callers reconcile this
    /// with `effect_confidence` (the claim): the effective verdict is the
    /// weaker of the two, so an actor can honestly downgrade but never inflate.
    pub fn evidence_ceiling(&self) -> EffectConfidence {
        if self.has_independent_evidence() {
            EffectConfidence::Verified
        } else {
            EffectConfidence::NotVerified
        }
    }
}

/// Who and what produced this action: the model runtime the actor was
/// executing under at sign time. Binding it into the signed statement lets a
/// verifier holding a pinned expectation ("this agent must run
/// claude-opus-4-8 with this tool schema and this system prompt") detect a
/// swapped model, an altered tool set, or a changed system prompt after the
/// fact. Where `effect` records *what* the action touched, this records *what
/// executed it*.
///
/// Every field is optional and actor-attested: it is signed by the actor's
/// key, so it is exactly as trustworthy as the actor, and it carries no
/// weight on its own. A verifier can only turn it into a Pass by reconciling
/// it against an out-of-band pinned expectation; absent means "not recorded"
/// (unverifiable), never a pass. The hashes are `sha256:<hex>` over the exact
/// bytes presented to the model, so equality is the whole check.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeIdentity {
    /// Model provider, e.g. "anthropic", "openai".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Model identifier the actor ran under, e.g. "claude-opus-4-8".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Hash of the exact tool schemas the agent had available this turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_schema_hash: Option<String>,
    /// Hash of the exact system prompt the agent ran under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system_prompt_hash: Option<String>,
}

impl RuntimeIdentity {
    /// True when no field is populated -- the runtime binding attests nothing,
    /// so a verifier has nothing to pin against an expectation. Verify treats
    /// this the same as an absent `runtime`: the runtime layer is
    /// unverifiable, not a pass.
    pub fn is_unbound(&self) -> bool {
        self.provider.is_none()
            && self.model.is_none()
            && self.tool_schema_hash.is_none()
            && self.system_prompt_hash.is_none()
    }
}

/// `treeship/action/v2` statement. Additive over v1: the v1 core fields are
/// unchanged; `audience`, `mandate`, `effect`, and `runtime` are new.
/// `mandate` is required (a v2 receipt with no mandate would just be a v1
/// receipt); `effect` and `runtime` are optional.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionStatementV2 {
    #[serde(rename = "type")]
    pub type_: String,

    /// RFC 3339 timestamp, set at sign time. This IS `signed_at`, the instant
    /// that gates mandate validity.
    pub timestamp: String,

    pub actor: String,
    pub action: String,

    /// Audience this action targeted. Checked against `mandate.audience` to
    /// block cross-audience replay. Absent means the signer did not record a
    /// target audience, which makes the audience layer unverifiable (not a
    /// pass).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,

    #[serde(default, skip_serializing_if = "subject_is_empty")]
    pub subject: SubjectRef,

    #[serde(rename = "parentId", skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,

    pub mandate: Mandate,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<Effect>,

    /// The model runtime the actor executed under. See [`RuntimeIdentity`].
    /// Absent means the signer recorded no runtime, which leaves the runtime
    /// layer unverifiable (not a pass).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<RuntimeIdentity>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

fn subject_is_empty(s: &SubjectRef) -> bool {
    s.digest.is_none() && s.uri.is_none() && s.artifact_id.is_none()
}

impl ActionStatementV2 {
    /// Construct a v2 action carrying the given mandate.
    pub fn new(actor: impl Into<String>, action: impl Into<String>, mandate: Mandate) -> Self {
        Self {
            type_: TYPE_ACTION_V2.into(),
            timestamp: super::unix_to_rfc3339(now_unix()),
            actor: actor.into(),
            action: action.into(),
            audience: None,
            subject: SubjectRef::default(),
            parent_id: None,
            mandate,
            effect: None,
            runtime: None,
            meta: None,
        }
    }
}

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Scope matching
// ---------------------------------------------------------------------------

/// True iff `action` is authorized by at least one entry of `scope`. An entry
/// is either an exact label or a family glob `foo.*` (which matches `foo` and
/// anything under `foo.`). A bare `*` is deliberately NOT a wildcard: an
/// unscoped "authorize everything" grant is exactly the open-fail this schema
/// exists to prevent.
pub fn action_in_scope(action: &str, scope: &[String]) -> bool {
    scope.iter().any(|entry| scope_entry_matches(entry, action))
}

fn scope_entry_matches(entry: &str, action: &str) -> bool {
    if let Some(prefix) = entry.strip_suffix(".*") {
        action == prefix || action.starts_with(&format!("{prefix}."))
    } else {
        entry == action
    }
}

// ---------------------------------------------------------------------------
// Revocation source
// ---------------------------------------------------------------------------

/// Result of resolving a grant's revocation state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationStatus {
    /// The source confirms the grant was not revoked.
    NotRevoked,
    /// The source reports the grant was revoked at this RFC 3339 instant.
    RevokedAt(String),
    /// The source could not be consulted (offline, no resolver configured,
    /// unknown path). Carries a human-readable reason.
    Unknown(String),
}

/// Resolves revocation-at-signing-time for a grant. Implementations back onto
/// Concordium, the Treeship Hub, or a signed `url_json` list (spec §9 step
/// 4). The embedded `mandate.revocation.revoked_at` is NOT an authority for
/// non-revocation, so verification defaults to [`NoRevocationSource`], which
/// reports `Unknown` and drives an honest `Unverified` verdict.
pub trait RevocationSource {
    fn status(&self, grant_id: &str, path: &str) -> RevocationStatus;
}

/// The default: no resolver is configured, so revocation is uncheckable.
pub struct NoRevocationSource;

impl RevocationSource for NoRevocationSource {
    fn status(&self, _grant_id: &str, path: &str) -> RevocationStatus {
        RevocationStatus::Unknown(format!("no revocation source configured for path '{path}'"))
    }
}

// ---------------------------------------------------------------------------
// Mandate verdict + verifier
// ---------------------------------------------------------------------------

/// Outcome of checking a v2 receipt's mandate. `Fail` and `Unverified` carry
/// human-readable reasons for audit output. Precedence: any checkable
/// violation makes the whole verdict `Fail`; otherwise any uncheckable layer
/// makes it `Unverified`; only when every layer is checkable and satisfied is
/// it `Pass`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MandateVerdict {
    Pass,
    Unverified(Vec<String>),
    Fail(Vec<String>),
}

impl MandateVerdict {
    pub fn is_pass(&self) -> bool {
        matches!(self, MandateVerdict::Pass)
    }
}

/// Verify the mandate layers of a v2 receipt, judged at `signed_at`
/// (`stmt.timestamp`). Fails closed: a malformed timestamp, an out-of-window
/// signature, an out-of-scope action, an audience mismatch, or a
/// revoked-before-signing grant all yield `Fail`. A layer that cannot be
/// checked (no audience recorded, no revocation resolver) yields `Unverified`
/// rather than a false `Pass`.
///
/// Signature validity is a precondition checked elsewhere (the DSSE envelope
/// verify); this function assumes the bytes are authentic and evaluates the
/// *authorization* the signed bytes assert.
pub fn verify_mandate(
    stmt: &ActionStatementV2,
    revocation: &dyn RevocationSource,
) -> MandateVerdict {
    let mut fail: Vec<String> = Vec::new();
    let mut unver: Vec<String> = Vec::new();

    if stmt.type_ != TYPE_ACTION_V2 {
        return MandateVerdict::Fail(vec![format!(
            "statement type '{}' is not {TYPE_ACTION_V2}",
            stmt.type_
        )]);
    }

    let m = &stmt.mandate;

    // signed_at is the gating instant. A receipt with an unparseable
    // timestamp cannot have its mandate evaluated -- fail closed.
    let signed_at = match parse_rfc3339_to_unix(&stmt.timestamp) {
        Some(t) => t,
        None => {
            return MandateVerdict::Fail(vec![format!(
                "timestamp '{}' is not RFC 3339",
                stmt.timestamp
            )])
        }
    };

    // -- scope: the action must be positively authorized.
    if m.scope.is_empty() {
        fail.push("mandate.scope is empty: it authorizes no action".into());
    } else if !action_in_scope(&stmt.action, &m.scope) {
        fail.push(format!(
            "action '{}' is not in mandate scope {:?}",
            stmt.action, m.scope
        ));
    }

    // -- audience: block cross-audience replay.
    if m.audience.trim().is_empty() {
        fail.push("mandate.audience is empty: the grant is not bound to an audience".into());
    } else {
        match &stmt.audience {
            Some(a) if a == &m.audience => {}
            Some(a) => fail.push(format!(
                "action audience '{a}' does not match mandate audience '{}'",
                m.audience
            )),
            None => unver
                .push("action recorded no audience; cannot confirm it matched the mandate".into()),
        }
    }

    // -- TTL: signed_at must be within [issued_at, expiry).
    match (
        parse_rfc3339_to_unix(&m.issued_at),
        parse_rfc3339_to_unix(&m.expiry),
    ) {
        (Some(issued), Some(expiry)) => {
            if expiry <= issued {
                fail.push(format!(
                    "mandate expiry '{}' is not after issued_at '{}'",
                    m.expiry, m.issued_at
                ));
            }
            if signed_at < issued {
                fail.push(format!(
                    "signed_at '{}' is before mandate issued_at '{}'",
                    stmt.timestamp, m.issued_at
                ));
            }
            if signed_at >= expiry {
                fail.push(format!(
                    "signed_at '{}' is at or after mandate expiry '{}'",
                    stmt.timestamp, m.expiry
                ));
            }
        }
        _ => fail.push(format!(
            "mandate issued_at '{}' / expiry '{}' are not both RFC 3339",
            m.issued_at, m.expiry
        )),
    }

    // -- revocation at signing time. The external source is the authority;
    // the embedded revoked_at is never trusted to assert non-revocation.
    match revocation.status(&m.grant_id, &m.revocation.path) {
        RevocationStatus::NotRevoked => {}
        RevocationStatus::RevokedAt(ts) => match parse_rfc3339_to_unix(&ts) {
            Some(revoked_at) => {
                if signed_at >= revoked_at {
                    fail.push(format!(
                        "grant was revoked at '{ts}'; signed_at '{}' is not before revocation",
                        stmt.timestamp
                    ));
                }
            }
            None => unver.push(format!("revocation timestamp '{ts}' is not RFC 3339")),
        },
        RevocationStatus::Unknown(reason) => {
            unver.push(format!("revocation could not be checked: {reason}"))
        }
    }

    // -- holder binding. A mandate with no `grantee` came from a bearer grant:
    // authentic, in scope, in window, and spendable by anyone who obtained the
    // grant bytes. The signature proves who issued the grant and who signed
    // this receipt; it never proves the two were related.
    //
    // Unverified rather than Fail: bearer is a legitimate mode, and the honest
    // report is that entitlement is a layer we could not check, not that a
    // violation was found. Silence here would let "correctly signed" read as
    // "the right party did this".
    if m.grantee.as_deref().unwrap_or("").is_empty() {
        unver.push(
            "grant names no grantee (bearer): any holder of the grant could have produced this"
                .into(),
        );
    }

    if !fail.is_empty() {
        MandateVerdict::Fail(fail)
    } else if !unver.is_empty() {
        MandateVerdict::Unverified(unver)
    } else {
        MandateVerdict::Pass
    }
}

// ---------------------------------------------------------------------------
// Effect verdict + verifier (operational confidence)
// ---------------------------------------------------------------------------

/// Decides whether a bundled [`Witness`] is a trustworthy, independent
/// corroboration of an effect. A real implementation MUST require all of:
/// the witness `signature` verifies against `observer`'s key in the trust
/// roots; `observer != actor` (a self-witness proves nothing); and
/// `observation` matches the effect's own observed post-state. The default
/// [`NoWitnessAuthority`] trusts nothing, so witnesses give zero evidence
/// lift until an authority is wired in -- fail closed, exactly like
/// [`NoRevocationSource`].
pub trait WitnessAuthority {
    fn is_trusted(&self, actor: &str, effect: &Effect, witness: &Witness) -> bool;
}

/// The default: no authority configured, so no witness is trusted and
/// witnesses contribute no evidence.
pub struct NoWitnessAuthority;

impl WitnessAuthority for NoWitnessAuthority {
    fn is_trusted(&self, _actor: &str, _effect: &Effect, _witness: &Witness) -> bool {
        false
    }
}

/// The reconciled operational-confidence outcome for a v2 receipt's effect,
/// kept deliberately separate from cryptographic validity (the DSSE
/// signature, checked elsewhere). A perfectly-signed receipt can still carry
/// an effect nobody independently confirmed; this verdict reports how much of
/// the *effect* the evidence actually supports, never how well it was signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectVerdict {
    /// The confidence the evidence supports after reconciliation. Equal to the
    /// actor's claim for every honest (non-`Verified`) claim; a `Verified`
    /// claim carrying no independent evidence is downgraded to `NotVerified`.
    /// Never higher than the actor claimed, and never higher than the evidence
    /// supports.
    pub effective_confidence: EffectConfidence,
    /// The actor's own claim, echoed for audit. `None` when the actor recorded
    /// no `effect_confidence`.
    pub claimed_confidence: Option<EffectConfidence>,
    /// Count of bundled witnesses the [`WitnessAuthority`] vouched for.
    pub trusted_witnesses: usize,
    /// Audit notes: downgrades applied, and witnesses that were not trusted.
    pub notes: Vec<String>,
    /// The lifecycle stage the evidence supports. Equal to the actor's claim
    /// except that an unbacked `Finalized` is downgraded to `Indeterminate`:
    /// "the target told me it committed" is the actor's word, and the actor's
    /// word is what this verifier exists to not take. `None` when the receipt
    /// declared no finality at all.
    pub effective_finality: Option<EffectFinality>,
    /// The actor's own finality claim, echoed for audit.
    pub claimed_finality: Option<EffectFinality>,
}

impl EffectVerdict {
    /// True when the effect is independently confirmed at the strongest level.
    pub fn is_verified(&self) -> bool {
        self.effective_confidence == EffectConfidence::Verified
    }
}

/// Reconcile a v2 receipt's effect claim against its evidence. Fails safe: the
/// effective confidence is never higher than what independent, actor-unmintable
/// evidence supports. Independent evidence is a `readback` the actor could not
/// mint, or a witness the [`WitnessAuthority`] vouches for (signed by a trusted
/// key that is not the actor, observing the same post-state).
///
/// Only a `Verified` claim asserts the effect definitely happened, so only it
/// can be inflated and only it is capped. Lesser claims (`Partial`,
/// `Ambiguous`, `Unknown`, `NotVerified`) are already admissions of incomplete
/// confidence and pass through unchanged -- the verifier's job is to block
/// inflation, not to erase an honest actor's own hedging.
///
/// Signature validity is a precondition checked elsewhere; this evaluates
/// operational confidence over bytes assumed authentic.
pub fn verify_effect(stmt: &ActionStatementV2, witnesses: &dyn WitnessAuthority) -> EffectVerdict {
    let effect = match &stmt.effect {
        Some(e) => e,
        None => {
            return EffectVerdict {
                effective_confidence: EffectConfidence::NotVerified,
                claimed_confidence: None,
                trusted_witnesses: 0,
                notes: vec!["receipt carries no effect block; effect is unverified".into()],
                effective_finality: None,
                claimed_finality: None,
            }
        }
    };

    let mut notes: Vec<String> = Vec::new();

    let trusted_witnesses = effect
        .witnesses
        .iter()
        .filter(|w| witnesses.is_trusted(&stmt.actor, effect, w))
        .count();
    let untrusted = effect.witnesses.len() - trusted_witnesses;
    if untrusted > 0 {
        notes.push(format!(
            "{untrusted} of {} bundled witness(es) not independently trusted; they add no evidence",
            effect.witnesses.len()
        ));
    }

    // The verify layer knows more than the pure-data ceiling: a witness the
    // authority vouched for is also actor-unmintable evidence.
    let has_evidence = effect.has_independent_evidence() || trusted_witnesses > 0;

    let claimed = effect.effect_confidence;
    let effective = match claimed {
        None => {
            notes.push("actor recorded no effect_confidence; effect is unverified".into());
            EffectConfidence::NotVerified
        }
        Some(EffectConfidence::Verified) if !has_evidence => {
            notes.push(
                "actor claimed Verified but bundled no independent evidence \
                 (no readback, no trusted witness); downgraded to NotVerified"
                    .into(),
            );
            EffectConfidence::NotVerified
        }
        Some(c) => c,
    };

    // Finality is capped on the same principle as confidence, for the same
    // reason: `Finalized` is the only lifecycle claim that asserts the change
    // definitely landed, so it is the only one an actor can inflate. Lesser
    // stages are admissions and pass through untouched.
    //
    // The downgrade target is `Indeterminate`, not `Initiated`: without
    // evidence we do not know that the target even acknowledged the write, so
    // asserting the weaker stage would be inventing a fact rather than
    // withdrawing one.
    let claimed_finality = effect.finality;
    let effective_finality = match claimed_finality {
        Some(EffectFinality::Finalized) if !has_evidence => {
            notes.push(
                "actor claimed the effect Finalized but bundled no independent evidence \
                 (no readback, no trusted witness); downgraded to Indeterminate"
                    .into(),
            );
            Some(EffectFinality::Indeterminate)
        }
        other => other,
    };

    EffectVerdict {
        effective_confidence: effective,
        claimed_confidence: claimed,
        trusted_witnesses,
        notes,
        effective_finality,
        claimed_finality,
    }
}

// ---------------------------------------------------------------------------
// First-class grant object + attenuation
// ---------------------------------------------------------------------------

/// A signed capability grant. Each delegation edge mints a narrower grant,
/// signed by the grantor, so a verifier can walk grant -> parent-grant -> …
/// -> root offline. Canonical binding mirrors the invitation statement: a
/// pipe-delimited, version-prefixed line with variable-length fields folded
/// into digests, so the canonical stays single-line and unambiguous.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub grant_id: String,
    /// Ed25519 pubkey of the grantor, base64url-no-pad.
    pub grantor: String,
    #[serde(default)]
    pub scope: Vec<String>,
    pub audience: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_request_id: Option<String>,
    #[serde(default)]
    pub delegation_depth: u32,
    pub issued_at: String,
    pub expiry: String,
    #[serde(default)]
    pub max_delegation: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objective_hash: Option<String>,

    /// Grantor's detached signature over this grant's canonical bytes.
    /// Deliberately absent from `canonical_for_signing` -- a signature cannot
    /// cover itself. Required for any grant carried in a mandate chain;
    /// `resolve_grant_chain` refuses unsigned ancestors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_sig: Option<String>,

    /// Content id of the grant this one was delegated from. `None` marks a
    /// root grant. Signed, so lineage cannot be re-parented after issuance --
    /// and because ids are content-derived, this is a hash commitment to the
    /// exact parent, not a reference to a name someone else could also claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_grant_id: Option<String>,

    /// Base64url-no-pad Ed25519 public key of the agent entitled to exercise
    /// this grant. Signed, so a holder cannot rebind it to themselves.
    ///
    /// `None` makes the grant a **bearer credential**: whoever holds the bytes
    /// holds the authority. That was the only mode before this field existed,
    /// and it is why a grant file copied into another workspace let a different
    /// key emit a receipt claiming its authority with nothing to object --
    /// `grantor` says who issued it and `audience` says which system it acts
    /// against, but nothing said who was allowed to spend it.
    ///
    /// Verification treats absence as a disclosed weakness, not a pass: see
    /// [`Grant::binds_holder`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grantee: Option<String>,
}

impl Grant {
    /// Canonical signing bytes. `v1|grant|` prefixed; the variable-length
    /// `scope` is folded into a sorted-key JSON digest so the line stays
    /// single-field-per-position. New fields go through a canonical-version
    /// bump, never a silent extension.
    pub fn canonical_for_signing(&self) -> String {
        let scope_digest = canonical_json_digest(&self.scope);
        // v2 differs from v1 in two ways: `parent_grant_id` is covered, and
        // `grant_id` is NOT. The id is derived from these bytes (see
        // `derive_grant_id`), so including it would be circular -- and it
        // matches how artifact ids work elsewhere: derived from the signed
        // bytes, never stored inside them.
        // v3 adds `grantee`. It has to be inside the signed bytes: a holder who
        // could add or strip it would be choosing who the grant is for, which
        // is the grantor's decision alone. Bumping the version rather than
        // appending silently means a v2 line can never be read as a v3 line
        // with an empty grantee.
        format!(
            "v3|grant|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.grantor,
            scope_digest,
            self.audience,
            self.parent_request_id.as_deref().unwrap_or(""),
            self.parent_grant_id.as_deref().unwrap_or(""),
            self.grantee.as_deref().unwrap_or(""),
            self.delegation_depth,
            self.issued_at,
            self.expiry,
            self.max_delegation,
            self.objective_hash.as_deref().unwrap_or(""),
        )
    }

    /// Whether this grant names the key allowed to exercise it.
    ///
    /// `false` means bearer: authentic, verifiable, and spendable by anyone who
    /// obtains the bytes. Callers must surface that rather than treat a valid
    /// signature as sufficient -- the signature proves who *issued* the grant,
    /// never who is entitled to use it.
    pub fn binds_holder(&self) -> bool {
        self.grantee.as_deref().is_some_and(|g| !g.is_empty())
    }

    /// Whether `holder_pubkey` (base64url-no-pad Ed25519) may exercise this
    /// grant. A bearer grant returns `true` for every key, which is exactly the
    /// property [`Grant::binds_holder`] exists to let callers warn about.
    pub fn exercisable_by(&self, holder_pubkey: &str) -> bool {
        match self.grantee.as_deref() {
            Some(g) if !g.is_empty() => g == holder_pubkey,
            _ => true,
        }
    }

    /// The grant's content id: `grn_` + first 16 hex of sha256 over the
    /// canonical bytes. Mirrors `artifact_id = "art_" + hex(sha256(PAE))[..16]`.
    ///
    /// Ids stop being claims and become facts: two grants collide only under a
    /// hash break, and a `parent_grant_id` therefore commits to one specific
    /// parent rather than to whatever grant happens to assert that name.
    pub fn derive_grant_id(&self) -> String {
        let digest = Sha256::digest(self.canonical_for_signing().as_bytes());
        format!("grn_{}", hex::encode(&digest[..8]))
    }

    /// True when the declared `grant_id` matches the derived one. A mismatch
    /// means the id was chosen rather than computed, so nothing that
    /// references it by id can be trusted to reference *this* grant.
    pub fn id_is_consistent(&self) -> bool {
        self.grant_id == self.derive_grant_id()
    }

    /// Sign the grant's canonical bytes; returns the base64url-no-pad
    /// signature. The `grantor` field must be `signer`'s public key for the
    /// grant to later verify.
    pub fn sign_canonical(&self, signer: &dyn Signer) -> Result<String, SignerError> {
        let sig = signer.sign(self.canonical_for_signing().as_bytes())?;
        Ok(URL_SAFE_NO_PAD.encode(sig))
    }

    /// Verify `signature_b64url` against `self.grantor` over the canonical
    /// bytes. Returns true only when the pubkey decodes AND the signature
    /// math checks out. Does not consult trust roots -- the caller decides
    /// whether `grantor` is a pinned issuer.
    pub fn verify_canonical(&self, signature_b64url: &str) -> bool {
        // A valid signature over content whose id was chosen by hand is still
        // unusable for chain walking: the parent pointer would resolve to a
        // name, not to these bytes. Fail closed before touching the crypto.
        if !self.id_is_consistent() {
            return false;
        }
        let pk_bytes = match URL_SAFE_NO_PAD.decode(self.grantor.as_bytes()) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let sig_bytes = match URL_SAFE_NO_PAD.decode(signature_b64url.as_bytes()) {
            Ok(b) if b.len() == 64 => b,
            _ => return false,
        };
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&sig_bytes);
        let vk = match VerifyingKey::from_bytes(&pk) {
            Ok(k) => k,
            Err(_) => return false,
        };
        vk.verify_strict(
            self.canonical_for_signing().as_bytes(),
            &Signature::from_bytes(&sig),
        )
        .is_ok()
    }
}

/// Why a mandate's grant chain could not be resolved into a trustworthy order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainResolveError {
    /// A grant's declared id does not match its content.
    InconsistentId { grant_id: String },
    /// `mandate.grant_id` names a grant that is not in the carried chain.
    LeafMissing { grant_id: String },
    /// A `parent_grant_id` points at a grant that is not present.
    AncestorMissing { parent_grant_id: String },
    /// Following parent links revisited a grant: the links form a cycle.
    Cycle { grant_id: String },
    /// The carrier supplied grants that the walk never reached. Extra grants
    /// are refused rather than ignored -- silently dropping them would let a
    /// carrier stuff a chain with decoys.
    UnreachableExtras { count: usize },
    /// A grant carried no signature, so its content is unattested.
    Unsigned { grant_id: String },
    /// A grant's signature does not verify against its grantor.
    BadSignature { grant_id: String },
}

impl std::fmt::Display for ChainResolveError {
    /// Operator-facing wording. The CLI prints these verbatim, so each names
    /// the grant it is talking about: "unresolvable" without a subject leaves
    /// a reader nothing to go and look at.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InconsistentId { grant_id } => {
                write!(
                    f,
                    "grant {grant_id} declares an id that does not match its content"
                )
            }
            Self::LeafMissing { grant_id } => {
                write!(
                    f,
                    "the mandate names grant {grant_id}, which is not in the carried chain"
                )
            }
            Self::AncestorMissing { parent_grant_id } => {
                write!(
                    f,
                    "parent grant {parent_grant_id} is missing from the chain"
                )
            }
            Self::Cycle { grant_id } => {
                write!(
                    f,
                    "parent links revisit grant {grant_id}: the chain is a cycle"
                )
            }
            Self::UnreachableExtras { count } => {
                write!(
                    f,
                    "{count} carried grant(s) are not reachable from the mandate"
                )
            }
            Self::Unsigned { grant_id } => {
                write!(f, "grant {grant_id} carries no issuer signature")
            }
            Self::BadSignature { grant_id } => {
                write!(f, "grant {grant_id} has a signature that does not verify")
            }
        }
    }
}

impl std::error::Error for ChainResolveError {}

/// Reconstruct the delegation chain for a mandate, root-first, from the
/// grants it carries.
///
/// The carrier hands over a set; this function derives the *order* from the
/// signed `parent_grant_id` links rather than trusting the sequence it was
/// given. That is the whole point: `verify_grant_chain` checks attenuation
/// between adjacent pairs, so if an attacker picks the pairing, the check
/// establishes nothing. Here, reordering is a no-op, truncation shows up as a
/// missing ancestor, and splicing shows up as an unreachable extra.
///
/// Every grant must be signed by its own grantor and carry a content-consistent
/// id. Fails closed on anything it cannot establish.
pub fn resolve_grant_chain(mandate: &Mandate) -> Result<Vec<Grant>, ChainResolveError> {
    use std::collections::{HashMap, HashSet};

    // Index by content id, checking each grant is self-consistent and attested.
    let mut by_id: HashMap<String, &Grant> = HashMap::new();
    for g in &mandate.chain {
        if !g.id_is_consistent() {
            return Err(ChainResolveError::InconsistentId {
                grant_id: g.grant_id.clone(),
            });
        }
        let sig = match g.issuer_sig.as_deref() {
            Some(s) if !s.is_empty() => s,
            _ => {
                return Err(ChainResolveError::Unsigned {
                    grant_id: g.grant_id.clone(),
                })
            }
        };
        if !g.verify_canonical(sig) {
            return Err(ChainResolveError::BadSignature {
                grant_id: g.grant_id.clone(),
            });
        }
        by_id.insert(g.grant_id.clone(), g);
    }

    // Walk leaf -> root through signed parent links.
    let mut leaf_first: Vec<Grant> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut cursor = Some(mandate.grant_id.clone());

    while let Some(id) = cursor {
        if !seen.insert(id.clone()) {
            return Err(ChainResolveError::Cycle { grant_id: id });
        }
        let g = match by_id.get(&id) {
            Some(g) => *g,
            None => {
                return Err(if leaf_first.is_empty() {
                    ChainResolveError::LeafMissing { grant_id: id }
                } else {
                    ChainResolveError::AncestorMissing {
                        parent_grant_id: id,
                    }
                })
            }
        };
        leaf_first.push(g.clone());
        cursor = g.parent_grant_id.clone();
    }

    // Anything the walk never reached is a decoy, not a spare.
    if seen.len() != by_id.len() {
        return Err(ChainResolveError::UnreachableExtras {
            count: by_id.len() - seen.len(),
        });
    }

    leaf_first.reverse(); // verify_grant_chain wants root-first
    Ok(leaf_first)
}

/// Why a grant chain failed its attenuation invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantChainError {
    /// Chain was empty.
    Empty,
    /// A grant carried an unparseable `issued_at`/`expiry`.
    BadTimestamp { index: usize },
    /// child.scope is not a subset of parent.scope.
    ScopeWidened { parent: usize },
    /// child.expiry is later than parent.expiry.
    ExpiryWidened { parent: usize },
    /// child.delegation_depth is not exactly parent.delegation_depth + 1.
    DepthNotIncremented { parent: usize },
    /// child.delegation_depth exceeds parent.max_delegation.
    DepthExceedsMax { parent: usize },
    /// child.audience differs from parent.audience.
    AudienceChanged { parent: usize },
}

impl std::fmt::Display for GrantChainError {
    /// `parent` is the index of the *parent* in the resolved root-first chain,
    /// so the violation is reported as the hop between it and its child --
    /// which is where an operator has to look to fix it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "the chain is empty"),
            Self::BadTimestamp { index } => {
                write!(
                    f,
                    "grant at hop {index} has an unparseable issued_at/expiry"
                )
            }
            Self::ScopeWidened { parent } => {
                write!(f, "scope widens at hop {}->{}", parent, parent + 1)
            }
            Self::ExpiryWidened { parent } => {
                write!(
                    f,
                    "expiry extends past the parent at hop {}->{}",
                    parent,
                    parent + 1
                )
            }
            Self::DepthNotIncremented { parent } => {
                write!(
                    f,
                    "delegation depth does not increment by one at hop {}->{}",
                    parent,
                    parent + 1
                )
            }
            Self::DepthExceedsMax { parent } => {
                write!(
                    f,
                    "delegation depth exceeds the parent's max_delegation at hop {}->{}",
                    parent,
                    parent + 1
                )
            }
            Self::AudienceChanged { parent } => {
                write!(f, "audience changes at hop {}->{}", parent, parent + 1)
            }
        }
    }
}

impl std::error::Error for GrantChainError {}

/// Verify attenuation across an ordered grant chain (`chain[0]` is the root,
/// `chain[last]` is the leaf the action was minted from). Every adjacent pair
/// must satisfy: scope narrows (child ⊆ parent), expiry does not extend,
/// delegation depth increments by exactly one and stays within the parent's
/// `max_delegation`, and audience is preserved. All checks fail closed.
///
/// This validates the *shape* of the delegation. Signature verification of
/// each grant is a separate concern ([`Grant::verify_canonical`]); a full
/// verifier composes both.
pub fn verify_grant_chain(chain: &[Grant]) -> Result<(), GrantChainError> {
    if chain.is_empty() {
        return Err(GrantChainError::Empty);
    }

    // Every grant's timestamps must parse, or downstream comparisons would be
    // meaningless. Fail closed up front.
    for (i, g) in chain.iter().enumerate() {
        if parse_rfc3339_to_unix(&g.issued_at).is_none()
            || parse_rfc3339_to_unix(&g.expiry).is_none()
        {
            return Err(GrantChainError::BadTimestamp { index: i });
        }
    }

    for (i, pair) in chain.windows(2).enumerate() {
        let parent = &pair[0];
        let child = &pair[1];

        if !scope_subset(&child.scope, &parent.scope) {
            return Err(GrantChainError::ScopeWidened { parent: i });
        }

        // Safe: timestamps validated above.
        let parent_expiry = parse_rfc3339_to_unix(&parent.expiry).unwrap();
        let child_expiry = parse_rfc3339_to_unix(&child.expiry).unwrap();
        if child_expiry > parent_expiry {
            return Err(GrantChainError::ExpiryWidened { parent: i });
        }

        if child.delegation_depth != parent.delegation_depth + 1 {
            return Err(GrantChainError::DepthNotIncremented { parent: i });
        }
        if child.delegation_depth > parent.max_delegation {
            return Err(GrantChainError::DepthExceedsMax { parent: i });
        }

        if child.audience != parent.audience {
            return Err(GrantChainError::AudienceChanged { parent: i });
        }
    }

    Ok(())
}

/// True iff every entry of `child` is covered by some entry of `parent`. An
/// exact label is covered by an equal label or by a parent family glob; a
/// child family glob is covered only by an equal-or-broader parent glob.
fn scope_subset(child: &[String], parent: &[String]) -> bool {
    child
        .iter()
        .all(|c| parent.iter().any(|p| scope_entry_covers(p, c)))
}

fn scope_entry_covers(parent: &str, child: &str) -> bool {
    if parent == child {
        return true;
    }
    if let Some(parent_prefix) = parent.strip_suffix(".*") {
        // A parent glob `foo.*` covers `foo`, anything under `foo.`, and a
        // narrower child glob like `foo.bar.*` (compare on its prefix).
        let child_core = child.strip_suffix(".*").unwrap_or(child);
        child_core == parent_prefix || child_core.starts_with(&format!("{parent_prefix}."))
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{sign, Ed25519Signer, Verifier as EnvVerifier};

    #[test]
    fn effect_confidence_ceiling_gates_on_independent_evidence() {
        // A readback the actor could not mint lets the evidence support Verified.
        let with_evidence = Effect {
            readback: Some("sha256:observed".into()),
            effect_confidence: Some(EffectConfidence::Verified),
            ..Default::default()
        };
        assert!(with_evidence.has_independent_evidence());
        assert_eq!(with_evidence.evidence_ceiling(), EffectConfidence::Verified);

        // No independent evidence: the honest ceiling is NotVerified, so a
        // `Verified` CLAIM here must be treated as inflated (ack != act).
        let claim_only = Effect {
            output_hash: Some("sha256:out".into()),
            effect_confidence: Some(EffectConfidence::Verified),
            ..Default::default()
        };
        assert!(!claim_only.has_independent_evidence());
        assert_eq!(claim_only.evidence_ceiling(), EffectConfidence::NotVerified);

        // An honest actor can downgrade below the ceiling with no evidence.
        let honest_downgrade = Effect {
            effect_confidence: Some(EffectConfidence::Unknown),
            ..Default::default()
        };
        assert_eq!(
            honest_downgrade.evidence_ceiling(),
            EffectConfidence::NotVerified
        );
    }

    #[test]
    fn effect_confidence_serializes_snake_case_and_is_omitted_when_absent() {
        let e = Effect {
            effect_confidence: Some(EffectConfidence::NotVerified),
            ..Default::default()
        };
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains("\"effect_confidence\":\"not_verified\""), "{j}");

        // Absent => omitted entirely (additive, backward-compatible over v1).
        let empty = Effect::default();
        assert!(!serde_json::to_string(&empty)
            .unwrap()
            .contains("effect_confidence"));
    }

    /// A test authority that trusts any signed witness whose observer differs
    /// from the actor and whose observation matches the effect's readback.
    /// Stands in for the real trust-root + signature check.
    struct TrustingWitnessAuthority;
    impl WitnessAuthority for TrustingWitnessAuthority {
        fn is_trusted(&self, actor: &str, effect: &Effect, w: &Witness) -> bool {
            w.is_signed()
                && w.observer != actor
                && effect.readback.as_deref() == Some(w.observation.as_str())
        }
    }

    #[test]
    fn verify_effect_downgrades_unbacked_verified_claim() {
        // Verified claim, no readback, no witness => downgraded to NotVerified.
        let mut s = good_stmt();
        s.actor = "agent://worker".into();
        s.effect = Some(Effect {
            output_hash: Some("sha256:out".into()),
            effect_confidence: Some(EffectConfidence::Verified),
            ..Default::default()
        });
        let v = verify_effect(&s, &NoWitnessAuthority);
        assert_eq!(v.effective_confidence, EffectConfidence::NotVerified);
        assert_eq!(v.claimed_confidence, Some(EffectConfidence::Verified));
        assert!(!v.is_verified());
        assert!(
            v.notes.iter().any(|n| n.contains("downgraded")),
            "{:?}",
            v.notes
        );
    }

    // ---- effect finality (lifecycle) vs confidence (evidence) ----

    #[test]
    fn finality_and_confidence_are_independent_axes() {
        // The composite-claim bug in one assertion: a receipt can be honest
        // about its evidence and still overclaim completion. Weak evidence,
        // strong completion claim -- the verifier must judge them separately.
        let mut s = good_stmt();
        s.effect = Some(Effect {
            output_hash: Some("sha256:out".into()),
            effect_confidence: Some(EffectConfidence::Partial),
            finality: Some(EffectFinality::Finalized),
            ..Default::default()
        });
        let v = verify_effect(&s, &NoWitnessAuthority);
        // Partial is an admission, so it survives untouched...
        assert_eq!(v.effective_confidence, EffectConfidence::Partial);
        // ...while the unbacked Finalized does not.
        assert_eq!(v.effective_finality, Some(EffectFinality::Indeterminate));
        assert_eq!(v.claimed_finality, Some(EffectFinality::Finalized));
    }

    #[test]
    fn unbacked_finalized_is_downgraded_to_indeterminate() {
        // The 56%-of-writes case: accepted, acknowledged, served back on read,
        // never committed. Downgrade must land on Indeterminate, not Initiated
        // -- without evidence we cannot assert the weaker stage either, and
        // inventing it would be a different false claim.
        let mut s = good_stmt();
        s.effect = Some(Effect {
            output_hash: Some("sha256:out".into()),
            finality: Some(EffectFinality::Finalized),
            ..Default::default()
        });
        let v = verify_effect(&s, &NoWitnessAuthority);
        assert_eq!(v.effective_finality, Some(EffectFinality::Indeterminate));
        assert!(
            v.notes.iter().any(|n| n.contains("Finalized")),
            "the downgrade must be stated, not silent: {:?}",
            v.notes
        );
    }

    #[test]
    fn finalized_backed_by_readback_survives() {
        let mut s = good_stmt();
        s.effect = Some(Effect {
            readback: Some("sha256:observed".into()),
            finality: Some(EffectFinality::Finalized),
            ..Default::default()
        });
        let v = verify_effect(&s, &NoWitnessAuthority);
        assert_eq!(v.effective_finality, Some(EffectFinality::Finalized));
    }

    #[test]
    fn lesser_finality_claims_pass_through_unchanged() {
        // Only the strongest claim can be inflated, so only it is capped.
        // Downgrading an actor's own hedge would punish honesty.
        for stage in [
            EffectFinality::NotAttempted,
            EffectFinality::Initiated,
            EffectFinality::Failed,
            EffectFinality::Indeterminate,
        ] {
            let mut s = good_stmt();
            s.effect = Some(Effect {
                finality: Some(stage),
                ..Default::default()
            });
            let v = verify_effect(&s, &NoWitnessAuthority);
            assert_eq!(v.effective_finality, Some(stage), "{stage:?} was altered");
        }
    }

    #[test]
    fn not_attempted_is_the_no_authority_moved_receipt() {
        // A timeout before the call. The input is bound so the negative is
        // about a specific request, and the stage is terminal so nothing is
        // still owed. This is what makes absence expressible instead of silent.
        let e = Effect {
            input_hash: Some("sha256:req".into()),
            finality: Some(EffectFinality::NotAttempted),
            ..Default::default()
        };
        assert!(EffectFinality::NotAttempted.is_resolved());
        assert_eq!(
            check_resolution(&e, 4_000_000_000),
            ResolutionStatus::Resolved
        );
    }

    // ---- resolution deadlines ----

    fn open_effect(resolution: Option<Resolution>) -> Effect {
        Effect {
            finality: Some(EffectFinality::Initiated),
            resolution,
            ..Default::default()
        }
    }

    #[test]
    fn unresolved_without_a_deadline_reports_indefinite() {
        // The 181-day pending row. Silence here is what made it survivable;
        // naming the state is the whole point of the field.
        assert_eq!(
            check_resolution(&open_effect(None), 1_800_000_000),
            ResolutionStatus::Indefinite
        );
    }

    /// Derive the epoch from the same parser the check uses, rather than
    /// hand-computing one. A wrong literal here would make the test assert a
    /// fact about my arithmetic instead of about the function.
    const DEADLINE: &str = "2026-07-20T11:00:00Z";
    fn deadline_unix() -> i64 {
        parse_rfc3339_to_unix(DEADLINE).expect("fixture deadline parses") as i64
    }

    #[test]
    fn unresolved_past_its_deadline_reports_the_declared_event() {
        let e = open_effect(Some(Resolution {
            deadline: DEADLINE.into(),
            on_deadline: DeadlineEvent::Escalate,
        }));
        match check_resolution(&e, deadline_unix() + 90) {
            ResolutionStatus::Breached {
                on_deadline,
                seconds_overdue,
            } => {
                assert_eq!(on_deadline, DeadlineEvent::Escalate);
                assert_eq!(seconds_overdue, 90);
            }
            other => panic!("expected Breached, got {other:?}"),
        }
    }

    #[test]
    fn unresolved_inside_its_window_is_pending() {
        let e = open_effect(Some(Resolution {
            deadline: DEADLINE.into(),
            on_deadline: DeadlineEvent::Timeout,
        }));
        match check_resolution(&e, deadline_unix() - 60) {
            ResolutionStatus::Pending { seconds_remaining } => {
                assert_eq!(seconds_remaining, 60)
            }
            other => panic!("expected Pending, got {other:?}"),
        }
    }

    #[test]
    fn a_resolved_effect_cannot_breach() {
        // Finalized long before "now": the deadline is moot, not breached.
        let e = Effect {
            finality: Some(EffectFinality::Finalized),
            resolution: Some(Resolution {
                deadline: "2026-07-20T11:00:00Z".into(),
                on_deadline: DeadlineEvent::Tombstone,
            }),
            ..Default::default()
        };
        assert_eq!(
            check_resolution(&e, 4_000_000_000),
            ResolutionStatus::Resolved
        );
    }

    #[test]
    fn unparseable_deadline_fails_toward_unknown() {
        // Never toward "in window": a deadline nobody can read must not be
        // treated as one that has not passed yet.
        let e = open_effect(Some(Resolution {
            deadline: "whenever".into(),
            on_deadline: DeadlineEvent::Timeout,
        }));
        assert_eq!(
            check_resolution(&e, 1_800_000_000),
            ResolutionStatus::BadDeadline
        );
    }

    #[test]
    fn missing_finality_is_treated_as_unresolved() {
        // A receipt that never says where its state change got to has not told
        // us it landed. Conservative reading, stated explicitly.
        let e = Effect {
            output_hash: Some("sha256:out".into()),
            ..Default::default()
        };
        assert_eq!(
            check_resolution(&e, 1_800_000_000),
            ResolutionStatus::Indefinite
        );
    }

    #[test]
    fn finality_and_resolution_are_omitted_when_absent() {
        // Existing v2 receipts must keep byte-identical canonical bytes.
        let json = serde_json::to_string(&Effect {
            output_hash: Some("sha256:out".into()),
            ..Default::default()
        })
        .unwrap();
        assert!(!json.contains("finality"), "{json}");
        assert!(!json.contains("resolution"), "{json}");
    }

    #[test]
    fn verify_effect_honors_verified_backed_by_readback() {
        let mut s = good_stmt();
        s.effect = Some(Effect {
            readback: Some("sha256:observed".into()),
            effect_confidence: Some(EffectConfidence::Verified),
            ..Default::default()
        });
        let v = verify_effect(&s, &NoWitnessAuthority);
        assert_eq!(v.effective_confidence, EffectConfidence::Verified);
        assert!(v.is_verified());
    }

    #[test]
    fn verify_effect_trusts_a_vouched_witness_over_no_readback() {
        // No readback, but an independent trusted witness observed the same
        // post-state the effect commits to: Verified stands.
        let mut s = good_stmt();
        s.actor = "agent://worker".into();
        s.effect = Some(Effect {
            readback: Some("sha256:state".into()),
            effect_confidence: Some(EffectConfidence::Verified),
            witnesses: vec![Witness {
                observer: "agent://auditor".into(),
                observation: "sha256:state".into(),
                observed_at: Some("2026-07-20T10:00:00Z".into()),
                signature: Some("ed25519:sig".into()),
            }],
            ..Default::default()
        });
        let v = verify_effect(&s, &TrustingWitnessAuthority);
        assert_eq!(v.trusted_witnesses, 1);
        assert_eq!(v.effective_confidence, EffectConfidence::Verified);

        // A self-witness (observer == actor) is not trusted, even signed.
        let mut self_witness = s.clone();
        if let Some(e) = self_witness.effect.as_mut() {
            e.readback = None; // remove the readback so only the witness could lift it
            e.witnesses[0].observer = "agent://worker".into();
        }
        let v2 = verify_effect(&self_witness, &TrustingWitnessAuthority);
        assert_eq!(v2.trusted_witnesses, 0);
        assert_eq!(v2.effective_confidence, EffectConfidence::NotVerified);
        assert!(v2
            .notes
            .iter()
            .any(|n| n.contains("not independently trusted")));
    }

    #[test]
    fn verify_effect_passes_honest_lesser_claims_through_unchanged() {
        // Partial/Unknown are admissions, not inflations: no downgrade even
        // without independent evidence.
        for c in [
            EffectConfidence::Partial,
            EffectConfidence::Ambiguous,
            EffectConfidence::Unknown,
            EffectConfidence::NotVerified,
        ] {
            let mut s = good_stmt();
            s.effect = Some(Effect {
                effect_confidence: Some(c),
                ..Default::default()
            });
            let v = verify_effect(&s, &NoWitnessAuthority);
            assert_eq!(v.effective_confidence, c, "claim {c:?} should pass through");
        }
    }

    #[test]
    fn verify_effect_reports_unverified_when_no_effect_or_no_claim() {
        // No effect block at all.
        let s = good_stmt();
        assert!(s.effect.is_none());
        let v = verify_effect(&s, &NoWitnessAuthority);
        assert_eq!(v.effective_confidence, EffectConfidence::NotVerified);
        assert_eq!(v.claimed_confidence, None);
        assert!(v.notes.iter().any(|n| n.contains("no effect block")));

        // Effect present but no confidence claim.
        let mut s2 = good_stmt();
        s2.effect = Some(Effect {
            output_hash: Some("sha256:out".into()),
            ..Default::default()
        });
        let v2 = verify_effect(&s2, &NoWitnessAuthority);
        assert_eq!(v2.effective_confidence, EffectConfidence::NotVerified);
        assert!(v2.notes.iter().any(|n| n.contains("no effect_confidence")));
    }

    #[test]
    fn witness_does_not_inflate_evidence_ceiling() {
        // Security invariant: a witness the actor bundled in -- even a signed
        // one -- must NOT lift evidence_ceiling at the data-model layer. Only
        // an actor-unmintable readback does that here; witness trust is
        // verify's job.
        let signed_witness = Witness {
            observer: "agent://auditor".into(),
            observation: "sha256:observed".into(),
            observed_at: Some("2026-07-20T10:00:00Z".into()),
            signature: Some("ed25519:sig".into()),
        };
        let e = Effect {
            witnesses: vec![signed_witness.clone()],
            effect_confidence: Some(EffectConfidence::Verified),
            ..Default::default()
        };
        assert!(!e.has_independent_evidence());
        assert_eq!(e.evidence_ceiling(), EffectConfidence::NotVerified);
        // The signature is visible for verify to check, but that's a
        // precondition, not evidence.
        assert!(signed_witness.is_signed());
        assert_eq!(e.signed_witnesses().count(), 1);

        // An unsigned witness isn't even a candidate.
        let unsigned = Effect {
            witnesses: vec![Witness {
                observer: "agent://auditor".into(),
                observation: "sha256:observed".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(unsigned.signed_witnesses().count(), 0);
    }

    #[test]
    fn witnesses_serialize_and_omit_when_empty() {
        let empty = Effect::default();
        assert!(!serde_json::to_string(&empty).unwrap().contains("witnesses"));

        let e = Effect {
            witnesses: vec![Witness {
                observer: "key_9f2c".into(),
                observation: "sha256:obs".into(),
                observed_at: None,
                signature: Some("ed25519:sig".into()),
            }],
            ..Default::default()
        };
        let j = serde_json::to_string(&e).unwrap();
        assert!(j.contains("\"witnesses\":[{"), "{j}");
        assert!(j.contains("\"observer\":\"key_9f2c\""), "{j}");
        // observed_at absent => omitted, not null.
        assert!(!j.contains("observed_at"), "{j}");
        let back: Effect = serde_json::from_str(&j).unwrap();
        assert_eq!(back.witnesses.len(), 1);
        assert!(back.witnesses[0].is_signed());
    }

    #[test]
    fn runtime_identity_is_unbound_only_when_all_fields_absent() {
        assert!(RuntimeIdentity::default().is_unbound());

        // Any single populated field means the binding attests something.
        let with_model = RuntimeIdentity {
            model: Some("claude-opus-4-8".into()),
            ..Default::default()
        };
        assert!(!with_model.is_unbound());

        let with_prompt = RuntimeIdentity {
            system_prompt_hash: Some("sha256:sys".into()),
            ..Default::default()
        };
        assert!(!with_prompt.is_unbound());
    }

    #[test]
    fn runtime_identity_serializes_snake_case_and_omits_absent_fields() {
        let rt = RuntimeIdentity {
            provider: Some("anthropic".into()),
            model: Some("claude-opus-4-8".into()),
            tool_schema_hash: Some("sha256:tools".into()),
            system_prompt_hash: None,
        };
        let j = serde_json::to_string(&rt).unwrap();
        assert!(j.contains("\"provider\":\"anthropic\""), "{j}");
        assert!(j.contains("\"model\":\"claude-opus-4-8\""), "{j}");
        assert!(j.contains("\"tool_schema_hash\":\"sha256:tools\""), "{j}");
        // Absent field omitted, not null -- keeps the canonical stable.
        assert!(!j.contains("system_prompt_hash"), "{j}");

        // All-absent runtime is an empty object, and roundtrips.
        let empty = serde_json::to_string(&RuntimeIdentity::default()).unwrap();
        assert_eq!(empty, "{}");
        let back: RuntimeIdentity = serde_json::from_str(&empty).unwrap();
        assert!(back.is_unbound());
    }

    #[test]
    fn runtime_is_omitted_from_statement_when_absent() {
        // A v2 statement with no runtime must not emit a `runtime` key, so
        // existing artifact_ids over runtime-less receipts are unaffected.
        let s = good_stmt();
        assert!(s.runtime.is_none());
        let j = serde_json::to_string(&s).unwrap();
        assert!(!j.contains("runtime"), "{j}");

        // When present, it rides in the signed statement and roundtrips.
        let mut with_rt = good_stmt();
        with_rt.runtime = Some(RuntimeIdentity {
            model: Some("claude-opus-4-8".into()),
            ..Default::default()
        });
        let j2 = serde_json::to_string(&with_rt).unwrap();
        assert!(j2.contains("\"runtime\""), "{j2}");
        let back: ActionStatementV2 = serde_json::from_str(&j2).unwrap();
        assert_eq!(
            back.runtime.unwrap().model.as_deref(),
            Some("claude-opus-4-8")
        );
    }

    fn base_mandate() -> Mandate {
        Mandate {
            grant_id: "grant_9c2f".into(),
            grantor: "key_parent".into(),
            // Bound, so tests of the scope / audience / window / revocation
            // layers are not perpetually Unverified on the holder layer. The
            // bearer case has its own test.
            grantee: Some("key_holder".into()),
            issuer_sig: None,
            objective_hash: Some("sha256:abc".into()),
            scope: vec!["payments.charge".into()],
            audience: "acme-payments-api".into(),
            parent_request_id: Some("req_7d3e".into()),
            delegation_depth: 2,
            issued_at: "2026-07-11T19:50:00Z".into(),
            expiry: "2026-07-11T20:50:00Z".into(),
            max_delegation: 3,
            revocation: Revocation {
                path: "hub://acme/revocations".into(),
                revoked_at: None,
            },
            chain: Vec::new(),
        }
    }

    /// A statement whose signed_at sits inside the mandate window, action in
    /// scope, audience matching.
    fn good_stmt() -> ActionStatementV2 {
        let mut s = ActionStatementV2::new("ship://ship_f9ba", "payments.charge", base_mandate());
        s.timestamp = "2026-07-11T19:53:09Z".into();
        s.audience = Some("acme-payments-api".into());
        s
    }

    struct StaticRevocation(RevocationStatus);
    impl RevocationSource for StaticRevocation {
        fn status(&self, _g: &str, _p: &str) -> RevocationStatus {
            self.0.clone()
        }
    }

    // ---- scope ----

    #[test]
    fn scope_exact_and_glob() {
        assert!(action_in_scope(
            "payments.charge",
            &["payments.charge".into()]
        ));
        assert!(action_in_scope("payments.charge", &["payments.*".into()]));
        assert!(action_in_scope("payments", &["payments.*".into()]));
        assert!(!action_in_scope(
            "payments.refund",
            &["payments.charge".into()]
        ));
        assert!(!action_in_scope("email.send", &["payments.*".into()]));
        // A bare "*" is a literal, not a wildcard.
        assert!(!action_in_scope("anything", &["*".into()]));
        assert!(action_in_scope("*", &["*".into()]));
    }

    #[test]
    fn empty_scope_authorizes_nothing() {
        let mut s = good_stmt();
        s.mandate.scope = vec![];
        match verify_mandate(&s, &StaticRevocation(RevocationStatus::NotRevoked)) {
            MandateVerdict::Fail(rs) => assert!(rs.iter().any(|r| r.contains("scope is empty"))),
            v => panic!("empty scope must fail, got {v:?}"),
        }
    }

    #[test]
    fn action_out_of_scope_fails() {
        let mut s = good_stmt();
        s.action = "payments.refund".into();
        assert!(matches!(
            verify_mandate(&s, &StaticRevocation(RevocationStatus::NotRevoked)),
            MandateVerdict::Fail(_)
        ));
    }

    // ---- audience ----

    #[test]
    fn audience_match_passes_layer() {
        let s = good_stmt();
        assert_eq!(
            verify_mandate(&s, &StaticRevocation(RevocationStatus::NotRevoked)),
            MandateVerdict::Pass
        );
    }

    #[test]
    fn audience_mismatch_fails() {
        let mut s = good_stmt();
        s.audience = Some("evil-api".into());
        assert!(matches!(
            verify_mandate(&s, &StaticRevocation(RevocationStatus::NotRevoked)),
            MandateVerdict::Fail(_)
        ));
    }

    #[test]
    fn missing_action_audience_is_unverified_not_pass() {
        let mut s = good_stmt();
        s.audience = None;
        match verify_mandate(&s, &StaticRevocation(RevocationStatus::NotRevoked)) {
            MandateVerdict::Unverified(rs) => {
                assert!(rs.iter().any(|r| r.contains("recorded no audience")))
            }
            v => panic!("missing audience must be Unverified, got {v:?}"),
        }
    }

    #[test]
    fn empty_mandate_audience_fails() {
        let mut s = good_stmt();
        s.mandate.audience = "".into();
        assert!(matches!(
            verify_mandate(&s, &StaticRevocation(RevocationStatus::NotRevoked)),
            MandateVerdict::Fail(_)
        ));
    }

    // ---- TTL (validity at signed_at) ----

    #[test]
    fn signed_before_issued_fails() {
        let mut s = good_stmt();
        s.timestamp = "2026-07-11T19:49:59Z".into(); // one sec before issued
        assert!(matches!(
            verify_mandate(&s, &StaticRevocation(RevocationStatus::NotRevoked)),
            MandateVerdict::Fail(_)
        ));
    }

    #[test]
    fn signed_at_expiry_fails() {
        let mut s = good_stmt();
        s.timestamp = "2026-07-11T20:50:00Z".into(); // exactly expiry (exclusive)
        assert!(matches!(
            verify_mandate(&s, &StaticRevocation(RevocationStatus::NotRevoked)),
            MandateVerdict::Fail(_)
        ));
    }

    #[test]
    fn signed_within_window_passes() {
        let s = good_stmt(); // 19:53:09 within [19:50, 20:50)
        assert_eq!(
            verify_mandate(&s, &StaticRevocation(RevocationStatus::NotRevoked)),
            MandateVerdict::Pass
        );
    }

    #[test]
    fn malformed_timestamp_fails_closed() {
        let mut s = good_stmt();
        s.timestamp = "not-a-timestamp".into();
        assert!(matches!(
            verify_mandate(&s, &StaticRevocation(RevocationStatus::NotRevoked)),
            MandateVerdict::Fail(_)
        ));
    }

    // ---- revocation at signing time ----

    #[test]
    fn revoked_after_signing_still_passes() {
        // Grant revoked at 20:00; receipt signed at 19:53 -> still valid,
        // like a TLS cert whose later revocation is not retroactive.
        let s = good_stmt();
        let src = StaticRevocation(RevocationStatus::RevokedAt("2026-07-11T20:00:00Z".into()));
        assert_eq!(verify_mandate(&s, &src), MandateVerdict::Pass);
    }

    #[test]
    fn revoked_before_signing_fails() {
        let s = good_stmt(); // signed 19:53
        let src = StaticRevocation(RevocationStatus::RevokedAt("2026-07-11T19:52:00Z".into()));
        assert!(matches!(verify_mandate(&s, &src), MandateVerdict::Fail(_)));
    }

    #[test]
    fn revocation_unknown_is_unverified() {
        let s = good_stmt();
        match verify_mandate(&s, &NoRevocationSource) {
            MandateVerdict::Unverified(rs) => {
                assert!(rs
                    .iter()
                    .any(|r| r.contains("revocation could not be checked")))
            }
            v => panic!("no revocation source must be Unverified, got {v:?}"),
        }
    }

    #[test]
    fn fail_takes_precedence_over_unverified() {
        // Out-of-scope action (fail) AND no revocation source (unverified):
        // the verdict must be Fail, never Unverified.
        let mut s = good_stmt();
        s.action = "payments.refund".into();
        assert!(matches!(
            verify_mandate(&s, &NoRevocationSource),
            MandateVerdict::Fail(_)
        ));
    }

    #[test]
    fn wrong_type_fails() {
        let mut s = good_stmt();
        s.type_ = "treeship/action/v1".into();
        assert!(matches!(
            verify_mandate(&s, &StaticRevocation(RevocationStatus::NotRevoked)),
            MandateVerdict::Fail(_)
        ));
    }

    // ---- canonical binding: mandate/effect are in the signed bytes ----

    #[test]
    fn mandate_is_bound_into_signature() {
        let signer = Ed25519Signer::generate("key_test").unwrap();
        let pt = payload_type_v2("action");

        let a = good_stmt();
        let mut b = good_stmt();
        b.mandate.scope = vec!["payments.*".into()]; // differ only in mandate

        let ra = sign(&pt, &a, &signer).unwrap();
        let rb = sign(&pt, &b, &signer).unwrap();
        assert_ne!(
            ra.artifact_id, rb.artifact_id,
            "changing mandate.scope must change the signed artifact id"
        );
    }

    #[test]
    fn v2_sign_verify_roundtrip() {
        let signer = Ed25519Signer::generate("key_test").unwrap();
        let verifier = EnvVerifier::from_signer(&signer);
        let pt = payload_type_v2("action");

        let mut s = good_stmt();
        s.effect = Some(Effect {
            output_hash: Some("sha256:out".into()),
            readback: Some("sha256:observed".into()),
            bytes_moved: Some(1_048_576),
            cost: Some(Cost {
                unit: "usd_micros".into(),
                amount: 4200,
            }),
            side_effects: vec!["db:users.update".into()],
            ..Default::default()
        });

        let signed = sign(&pt, &s, &signer).unwrap();
        verifier.verify(&signed.envelope).unwrap();

        let decoded: ActionStatementV2 = signed.envelope.unmarshal_statement().unwrap();
        assert_eq!(decoded.type_, TYPE_ACTION_V2);
        assert_eq!(decoded.mandate.grant_id, "grant_9c2f");
        assert_eq!(decoded.effect.unwrap().cost.unwrap().amount, 4200);
    }

    #[test]
    fn v2_payload_type_differs_from_v1() {
        assert_eq!(
            payload_type_v2("action"),
            "application/vnd.treeship.action.v2+json"
        );
        assert_ne!(
            payload_type_v2("action"),
            super::super::payload_type("action")
        );
    }

    // ---- holder binding ----

    #[test]
    fn a_bearer_mandate_is_reported_not_passed() {
        // No grantee means anyone holding the grant bytes could have produced
        // this receipt. The signature proves who issued the grant and who
        // signed the receipt; it never proves the two were related.
        let mut s = good_stmt();
        s.mandate.grantee = None;
        match verify_mandate(&s, &StaticRevocation(RevocationStatus::NotRevoked)) {
            MandateVerdict::Unverified(r) => assert!(
                r.iter().any(|x| x.contains("bearer")),
                "the reason must name it: {r:?}"
            ),
            other => panic!("bearer must not pass silently, got {other:?}"),
        }
    }

    #[test]
    fn a_bound_mandate_clears_the_holder_layer() {
        let s = good_stmt();
        assert_eq!(
            verify_mandate(&s, &StaticRevocation(RevocationStatus::NotRevoked)),
            MandateVerdict::Pass
        );
    }

    #[test]
    fn exercisable_by_is_exact_and_bearer_admits_everyone() {
        let mut g = grant("g", "k", &["a"], 0, "2026-07-11T21:00:00Z", 3);
        g.grantee = Some("holder-key".into());
        assert!(g.binds_holder());
        assert!(g.exercisable_by("holder-key"));
        assert!(!g.exercisable_by("someone-else"));

        // Bearer: true for every key, which is exactly what `binds_holder`
        // exists to let a caller warn about.
        g.grantee = None;
        assert!(!g.binds_holder());
        assert!(g.exercisable_by("anyone-at-all"));
    }

    #[test]
    fn grantee_is_covered_by_the_signed_bytes() {
        // A holder who could add or strip the grantee would be choosing who the
        // grant is for -- the grantor's decision alone.
        let mut a = grant("g", "k", &["a"], 0, "2026-07-11T21:00:00Z", 3);
        let mut b = a.clone();
        a.grantee = Some("alice".into());
        b.grantee = Some("bob".into());
        assert_ne!(a.canonical_for_signing(), b.canonical_for_signing());
        assert_ne!(a.derive_grant_id(), b.derive_grant_id());
    }

    // ---- grant object + chain attenuation ----

    fn grant(
        id: &str,
        grantor: &str,
        scope: &[&str],
        depth: u32,
        expiry: &str,
        max_deleg: u32,
    ) -> Grant {
        Grant {
            grant_id: id.into(),
            grantor: grantor.into(),
            grantee: None,
            issuer_sig: None,
            scope: scope.iter().map(|s| (*s).into()).collect(),
            audience: "acme-payments-api".into(),
            parent_request_id: None,
            parent_grant_id: None,
            delegation_depth: depth,
            issued_at: "2026-07-11T19:00:00Z".into(),
            expiry: expiry.into(),
            max_delegation: max_deleg,
            objective_hash: None,
        }
    }

    #[test]
    fn grant_sign_verify_roundtrip_and_tamper() {
        let signer = Ed25519Signer::from_bytes("g", &[9u8; 32]).unwrap();
        let grantor = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());
        let mut g = grant(
            "grant_root",
            &grantor,
            &["payments.*"],
            0,
            "2026-07-11T21:00:00Z",
            3,
        );
        // Ids are content-derived now; verify_canonical refuses a hand-chosen
        // one, so compute it before signing.
        g.grant_id = g.derive_grant_id();

        let sig = g.sign_canonical(&signer).unwrap();
        assert!(g.verify_canonical(&sig));

        // Tamper after signing -> verification fails.
        g.scope.push("email.*".into());
        assert!(!g.verify_canonical(&sig));
    }

    #[test]
    fn grant_verify_rejects_wrong_key() {
        let signer = Ed25519Signer::from_bytes("g", &[9u8; 32]).unwrap();
        let attacker = Ed25519Signer::from_bytes("a", &[3u8; 32]).unwrap();
        let grantor = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());
        let g = grant(
            "grant_root",
            &grantor,
            &["payments.*"],
            0,
            "2026-07-11T21:00:00Z",
            3,
        );
        let sig = g.sign_canonical(&attacker).unwrap();
        assert!(!g.verify_canonical(&sig));
    }

    #[test]
    fn valid_attenuating_chain_ok() {
        let root = grant("g0", "k", &["payments.*"], 0, "2026-07-11T21:00:00Z", 3);
        let child = grant(
            "g1",
            "k",
            &["payments.charge"],
            1,
            "2026-07-11T20:30:00Z",
            3,
        );
        assert_eq!(verify_grant_chain(&[root, child]), Ok(()));
    }

    #[test]
    fn scope_widening_rejected() {
        let root = grant(
            "g0",
            "k",
            &["payments.charge"],
            0,
            "2026-07-11T21:00:00Z",
            3,
        );
        let child = grant("g1", "k", &["payments.*"], 1, "2026-07-11T21:00:00Z", 3);
        assert_eq!(
            verify_grant_chain(&[root, child]),
            Err(GrantChainError::ScopeWidened { parent: 0 })
        );
    }

    #[test]
    fn expiry_widening_rejected() {
        let root = grant("g0", "k", &["payments.*"], 0, "2026-07-11T21:00:00Z", 3);
        let child = grant(
            "g1",
            "k",
            &["payments.charge"],
            1,
            "2026-07-11T22:00:00Z",
            3,
        );
        assert_eq!(
            verify_grant_chain(&[root, child]),
            Err(GrantChainError::ExpiryWidened { parent: 0 })
        );
    }

    #[test]
    fn depth_not_incremented_rejected() {
        let root = grant("g0", "k", &["payments.*"], 0, "2026-07-11T21:00:00Z", 3);
        let child = grant(
            "g1",
            "k",
            &["payments.charge"],
            2,
            "2026-07-11T21:00:00Z",
            3,
        );
        assert_eq!(
            verify_grant_chain(&[root, child]),
            Err(GrantChainError::DepthNotIncremented { parent: 0 })
        );
    }

    #[test]
    fn depth_exceeds_max_rejected() {
        let root = grant("g0", "k", &["payments.*"], 0, "2026-07-11T21:00:00Z", 0);
        let child = grant(
            "g1",
            "k",
            &["payments.charge"],
            1,
            "2026-07-11T21:00:00Z",
            0,
        );
        assert_eq!(
            verify_grant_chain(&[root, child]),
            Err(GrantChainError::DepthExceedsMax { parent: 0 })
        );
    }

    #[test]
    fn audience_change_rejected() {
        let root = grant("g0", "k", &["payments.*"], 0, "2026-07-11T21:00:00Z", 3);
        let mut child = grant(
            "g1",
            "k",
            &["payments.charge"],
            1,
            "2026-07-11T21:00:00Z",
            3,
        );
        child.audience = "other-api".into();
        assert_eq!(
            verify_grant_chain(&[root, child]),
            Err(GrantChainError::AudienceChanged { parent: 0 })
        );
    }

    #[test]
    fn empty_chain_rejected() {
        assert_eq!(verify_grant_chain(&[]), Err(GrantChainError::Empty));
    }

    #[test]
    fn bad_timestamp_in_chain_rejected() {
        let mut root = grant("g0", "k", &["payments.*"], 0, "2026-07-11T21:00:00Z", 3);
        root.expiry = "nope".into();
        assert_eq!(
            verify_grant_chain(&[root]),
            Err(GrantChainError::BadTimestamp { index: 0 })
        );
    }

    #[test]
    fn single_grant_chain_ok() {
        let root = grant("g0", "k", &["payments.*"], 0, "2026-07-11T21:00:00Z", 3);
        assert_eq!(verify_grant_chain(&[root]), Ok(()));
    }

    // ---- grant chain resolution ----

    /// Mint a signed grant with a content-consistent id.
    fn mk_grant(
        signer: &Ed25519Signer,
        grantor_pk: &str,
        scope: Vec<&str>,
        depth: u32,
        parent: Option<&str>,
    ) -> Grant {
        let mut g = Grant {
            grant_id: String::new(),
            grantor: grantor_pk.to_string(),
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
        g.issuer_sig = Some(g.sign_canonical(signer).unwrap());
        g
    }

    fn chain_fixture() -> (Grant, Grant, Ed25519Signer) {
        let signer = Ed25519Signer::generate("issuer").unwrap();
        let pk = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());
        let root = mk_grant(&signer, &pk, vec!["payments.*"], 0, None);
        let leaf = mk_grant(
            &signer,
            &pk,
            vec!["payments.charge"],
            1,
            Some(&root.grant_id),
        );
        (root, leaf, signer)
    }

    fn mandate_with(leaf: &Grant, chain: Vec<Grant>) -> Mandate {
        let mut m = base_mandate();
        m.grant_id = leaf.grant_id.clone();
        m.chain = chain;
        m
    }

    #[test]
    fn grant_id_is_content_derived_and_stable() {
        let (root, _, _) = chain_fixture();
        assert!(root.grant_id.starts_with("grn_"));
        assert_eq!(root.grant_id, root.derive_grant_id());
        // Changing any covered field must move the id.
        let mut altered = root.clone();
        altered.scope = vec!["payments.refund".into()];
        assert_ne!(altered.derive_grant_id(), root.grant_id);
    }

    #[test]
    fn hand_chosen_id_fails_verification() {
        let (mut root, _, _) = chain_fixture();
        let sig = root.issuer_sig.clone().unwrap();
        root.grant_id = "grn_deadbeefdeadbeef".into();
        assert!(
            !root.verify_canonical(&sig),
            "an id that was chosen rather than computed must not verify"
        );
    }

    #[test]
    fn resolves_root_first_regardless_of_carrier_order() {
        let (root, leaf, _) = chain_fixture();
        // Carrier hands them over leaf-first; resolution must not care.
        let m = mandate_with(&leaf, vec![leaf.clone(), root.clone()]);
        let resolved = resolve_grant_chain(&m).expect("resolves");
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].grant_id, root.grant_id, "root must come first");
        assert_eq!(resolved[1].grant_id, leaf.grant_id);
    }

    #[test]
    fn truncated_chain_is_rejected() {
        let (_, leaf, _) = chain_fixture();
        // Drop the root: the leaf still points at it, so the walk must fail
        // rather than treating the leaf as its own root.
        let m = mandate_with(&leaf, vec![leaf.clone()]);
        match resolve_grant_chain(&m) {
            Err(ChainResolveError::AncestorMissing { .. }) => {}
            other => panic!("truncation must be caught, got {other:?}"),
        }
    }

    #[test]
    fn spliced_decoy_grant_is_rejected() {
        let (root, leaf, signer) = chain_fixture();
        let pk = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());
        // A valid, signed, unrelated grant smuggled into the chain. It must
        // differ in content from root -- an identical grant has an identical
        // content id, which is the point of deriving ids from content.
        let decoy = mk_grant(&signer, &pk, vec!["email.send"], 0, None);
        assert_ne!(decoy.grant_id, root.grant_id);
        let m = mandate_with(&leaf, vec![root.clone(), leaf.clone(), decoy]);
        match resolve_grant_chain(&m) {
            Err(ChainResolveError::UnreachableExtras { count }) => assert_eq!(count, 1),
            other => panic!("unreachable extras must be refused, got {other:?}"),
        }
    }

    #[test]
    fn unsigned_ancestor_is_rejected() {
        let (mut root, leaf, _) = chain_fixture();
        root.issuer_sig = None;
        let m = mandate_with(&leaf, vec![root, leaf.clone()]);
        assert!(matches!(
            resolve_grant_chain(&m),
            Err(ChainResolveError::Unsigned { .. })
        ));
    }

    #[test]
    fn resolved_chain_feeds_attenuation_check() {
        // End to end: resolution proves the shape, verify_grant_chain then
        // judges the attenuation. Only together do they mean anything.
        let (root, leaf, _) = chain_fixture();
        let m = mandate_with(&leaf, vec![leaf.clone(), root.clone()]);
        let resolved = resolve_grant_chain(&m).expect("resolves");
        assert!(
            verify_grant_chain(&resolved).is_ok(),
            "narrowing scope at depth+1 must satisfy attenuation"
        );
    }

    #[test]
    fn leaf_not_in_chain_is_rejected() {
        // The mandate names a grant the carrier did not supply. Distinct from
        // AncestorMissing: nothing has been walked yet, so the failure has to
        // point at the leaf rather than at a parent link.
        let (root, leaf, _) = chain_fixture();
        let mut m = mandate_with(&leaf, vec![root.clone()]);
        m.grant_id = leaf.grant_id.clone();
        match resolve_grant_chain(&m) {
            Err(ChainResolveError::LeafMissing { grant_id }) => {
                assert_eq!(grant_id, leaf.grant_id);
            }
            other => panic!("a mandate naming an absent leaf must fail, got {other:?}"),
        }
    }

    #[test]
    fn ancestor_signed_by_a_stranger_is_rejected() {
        // Content-consistent id, well-formed signature -- but produced by a key
        // that is not the declared grantor. The id check cannot catch this
        // because `grantor` is covered by the canonical: only the crypto can.
        let (root, leaf, _) = chain_fixture();
        let stranger = Ed25519Signer::generate("stranger").unwrap();
        let mut forged = root.clone();
        forged.issuer_sig = Some(forged.sign_canonical(&stranger).unwrap());
        assert_eq!(
            forged.grant_id, root.grant_id,
            "signing with another key must not change the content id"
        );

        let m = mandate_with(&leaf, vec![forged, leaf.clone()]);
        match resolve_grant_chain(&m) {
            Err(ChainResolveError::BadSignature { grant_id }) => {
                assert_eq!(grant_id, root.grant_id);
            }
            other => panic!("a grant signed by a non-grantor must fail, got {other:?}"),
        }
    }

    #[test]
    fn inconsistent_id_is_caught_before_signature_check() {
        // A tampered id must be refused as InconsistentId, not surface later as
        // BadSignature -- the reason an operator is given should name the
        // actual defect.
        let (root, leaf, _) = chain_fixture();
        let mut tampered = root.clone();
        tampered.grant_id = "grn_0000000000000000".into();
        let m = mandate_with(&leaf, vec![tampered, leaf.clone()]);
        assert!(matches!(
            resolve_grant_chain(&m),
            Err(ChainResolveError::InconsistentId { .. })
        ));
    }
}
