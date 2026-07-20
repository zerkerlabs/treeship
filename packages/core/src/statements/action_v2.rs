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
}

/// A metered cost attached to an effect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cost {
    pub unit: String,
    pub amount: u64,
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

impl Effect {
    /// True when the effect carries a signal the actor could not have minted
    /// itself (an external read-back). This is what lets a verifier honor a
    /// `Verified` confidence claim; without it, `Verified` is downgraded.
    pub fn has_independent_evidence(&self) -> bool {
        self.readback.is_some()
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

/// `treeship/action/v2` statement. Additive over v1: the v1 core fields are
/// unchanged; `audience`, `mandate`, and `effect` are new. `mandate` is
/// required (a v2 receipt with no mandate would just be a v1 receipt);
/// `effect` is optional.
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

    if !fail.is_empty() {
        MandateVerdict::Fail(fail)
    } else if !unver.is_empty() {
        MandateVerdict::Unverified(unver)
    } else {
        MandateVerdict::Pass
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
}

impl Grant {
    /// Canonical signing bytes. `v1|grant|` prefixed; the variable-length
    /// `scope` is folded into a sorted-key JSON digest so the line stays
    /// single-field-per-position. New fields go through a canonical-version
    /// bump, never a silent extension.
    pub fn canonical_for_signing(&self) -> String {
        let scope_digest = canonical_json_digest(&self.scope);
        format!(
            "v1|grant|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.grant_id,
            self.grantor,
            scope_digest,
            self.audience,
            self.parent_request_id.as_deref().unwrap_or(""),
            self.delegation_depth,
            self.issued_at,
            self.expiry,
            self.max_delegation,
            self.objective_hash.as_deref().unwrap_or(""),
        )
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

    fn base_mandate() -> Mandate {
        Mandate {
            grant_id: "grant_9c2f".into(),
            grantor: "key_parent".into(),
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
            scope: scope.iter().map(|s| (*s).into()).collect(),
            audience: "acme-payments-api".into(),
            parent_request_id: None,
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
}
