//! Approval Authority schemas — the journal-side companions to ApprovalScope.
//!
//! v0.9.6 introduced `ApprovalScope` to say *what* an approval allows
//! (actor / action / subject / max_uses) and `verify` reports the
//! authorization posture honestly: binding, scope, and a "package-local
//! only" replay note. These schemas add the *consumed* side: a per-use
//! record that, with a local Approval Use Journal (PR 2) and the
//! consume-before-action flow (PR 3), turns
//!
//! ```text
//! ⚠ replay check     package-local only -- no global ledger consulted
//! ```
//!
//! into
//!
//! ```text
//! ✓ replay check     local Approval Use Journal passed, use 1/1
//! ```
//!
//! v0.9.9 (this file) ships only the schema. PR 2 wires the journal,
//! PR 3 the consume flow, PR 4 package export, PR 5 report polish, PR 6
//! the optional Hub-checkpoint scaffold.
//!
//! Privacy rule baked into the schema: the journal stores
//! `nonce_digest`, never the raw nonce. Raw nonces stay in the signed
//! grant + package where they need to. The journal is private append-only
//! local memory, not a public ledger -- "no SQLite source of truth, no
//! public approval-use ledger" is a release rule.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Type constants
// ---------------------------------------------------------------------------

pub const TYPE_APPROVAL_USE:        &str = "treeship/approval-use/v1";
pub const TYPE_APPROVAL_REVOCATION: &str = "treeship/approval-revocation/v1";
pub const TYPE_JOURNAL_CHECKPOINT:  &str = "treeship/journal-checkpoint/v1";

// ---------------------------------------------------------------------------
// ApprovalUse
// ---------------------------------------------------------------------------

/// Records that a specific Approval Grant was consumed by a specific
/// Action. One record per use; an approval with `max_actions = 3` produces
/// up to three of these (subject to the journal's max_uses enforcement).
///
/// Designed for the local Approval Use Journal (PR 2). Two fields anchor
/// the journal's hash chain:
///   - `record_digest`        : sha256 of this record's canonical JSON,
///                              minus `record_digest` itself.
///   - `previous_record_digest`: the previous record's `record_digest`,
///                              giving the journal an append-only hash
///                              chain. The genesis record has this empty.
///
/// `signature` is optional in the schema because the journal can be signed
/// either per-record or via signed checkpoints over a range of records;
/// PR 2 picks the strategy. Keeping the field optional keeps the schema
/// stable across that decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalUse {
    #[serde(rename = "type")]
    pub type_: String,

    /// Stable per-record identifier. Independent of the action artifact
    /// id so the journal can write the use *before* the action signs
    /// (consume-before-action, PR 3).
    pub use_id: String,

    /// The grant being consumed (artifact id of the ApprovalStatement).
    pub grant_id: String,

    /// sha256 of the signed grant envelope. Pinning the digest detects
    /// drift if the grant is tampered or rotated; verify can reject any
    /// use that points at a digest different from the live grant.
    pub grant_digest: String,

    /// sha256 of the approval's `nonce` field. The journal indexes by
    /// this so duplicate consumption attempts collapse on lookup; raw
    /// nonces stay in the signed grant and are never written to disk
    /// outside the package they live in.
    pub nonce_digest: String,

    pub actor:   String,
    pub action:  String,
    /// Subject URI / artifact id the action targets. Mirrors
    /// `ApprovalScope.allowed_subjects` so journal records carry the
    /// resolved value used at consume time.
    pub subject: String,

    /// Session this use was recorded under. Optional because uses can
    /// happen outside any active session (e.g. a CLI one-shot).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,

    /// Action artifact this use authorized. Set when the action is
    /// signed; left None during the brief "reserved" window between
    /// journal write and action sign in the consume-before-action flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_artifact_id: Option<String>,

    /// Receipt this use will appear in. None until the receipt is built.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_digest: Option<String>,

    /// Which use of this grant this is. 1-indexed. Reads as "use 1/1"
    /// or "use 2/3" in verify output.
    pub use_number: u32,

    /// Mirror of the grant's `max_actions` at consume time. Stored on
    /// the use record so a later journal verifier doesn't need to
    /// re-resolve the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,

    /// Caller-supplied idempotency key. If present, a retry with the
    /// same `(grant_id, idempotency_key)` collapses to the existing use
    /// rather than allocating a new one. Lets a flaky network produce
    /// at-most-once consumption without burning a use slot per retry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,

    pub created_at: String,

    /// Optional expiry on the use itself, distinct from grant expiry.
    /// The grant's `valid_until` is the outer bound; this is for "this
    /// reserved use must commit by X or be released" semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,

    /// Genesis record carries the empty string. All others carry the
    /// previous record's `record_digest`. Pinning the chain.
    #[serde(default)]
    pub previous_record_digest: String,

    /// sha256 of this record's canonical JSON with `record_digest`
    /// itself omitted. Computed and stamped at write time.
    #[serde(default)]
    pub record_digest: String,

    /// Optional per-record signature. The journal can also sign by
    /// checkpoint over many records; PR 2 picks one. `signature_alg`
    /// names the algorithm so a future migration can introspect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
}

// ---------------------------------------------------------------------------
// ApprovalRevocation
// ---------------------------------------------------------------------------

/// Records that an approver revoked a previously-signed grant. Replayed
/// from the journal, this short-circuits any subsequent consume attempt
/// against the revoked grant -- "wrong actor / action / subject" fails
/// in scope, "grant revoked" fails in journal lookup.
///
/// Schema sibling of ApprovalUse so revocations live in the same
/// append-only chain and inherit the same digest discipline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRevocation {
    #[serde(rename = "type")]
    pub type_: String,
    pub revocation_id: String,
    pub grant_id: String,
    pub grant_digest: String,
    pub revoker: String,
    pub reason: Option<String>,
    pub created_at: String,
    #[serde(default)]
    pub previous_record_digest: String,
    #[serde(default)]
    pub record_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
}

// ---------------------------------------------------------------------------
// JournalCheckpoint
// ---------------------------------------------------------------------------

/// What a `JournalCheckpoint` is committing to. The discriminator lets a
/// verifier physically distinguish a local-journal record from a
/// Hub/org checkpoint, so a checkpoint can never accidentally promote
/// `replay-hub-org` just because the on-disk shape happens to match.
///
/// PR 6 v0.9.9 release rule: a verifier emits `replay-hub-org` PASS
/// ONLY when:
///   1. checkpoint_kind == HubOrg AND
///   2. hub_id is set AND
///   3. hub_public_key is set AND
///   4. hub_signature is set AND verifies AND
///   5. covered_use_ids includes every use under verification
///
/// Default value is LocalJournal so checkpoints written before PR 6
/// (which serialized without this field) deserialize as local-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CheckpointKind {
    /// Internal local-journal commitment. Cannot promote replay
    /// posture beyond `included-checkpoint`.
    #[default]
    LocalJournal,
    /// Signed by a Hub / org. May promote `replay-hub-org` if the
    /// signature verifies and coverage is asserted.
    HubOrg,
}

impl CheckpointKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::LocalJournal => "local-journal",
            Self::HubOrg       => "hub-org",
        }
    }
}

/// A signed Merkle commitment to a contiguous range of journal records.
/// Lets a verifier check journal continuity (and, with a Hub-signed
/// variant, replay across machines) without reading every record.
///
/// Two kinds with the same shape:
///
/// - `LocalJournal` (default): committed by the local journal as a
///   compaction primitive. Verify only emits `replay-included-checkpoint`.
///
/// - `HubOrg`: signed by a Hub/org. Carries `hub_id`, `hub_public_key`,
///   `hub_signature`, `signed_at`, and `covered_use_ids` listing every
///   use the checkpoint asserts coverage over. Verify emits
///   `replay-hub-org` PASS only when every Hub-signature check passes
///   and every embedded use is in `covered_use_ids`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalCheckpoint {
    #[serde(rename = "type")]
    pub type_: String,
    pub checkpoint_id: String,

    /// Discriminator. Defaults to LocalJournal for back-compat with
    /// pre-PR-6 records that didn't serialize this field.
    #[serde(default)]
    pub checkpoint_kind: CheckpointKind,

    /// Inclusive range of `use_number`s (or revocation_ids) covered by
    /// this checkpoint, in journal order.
    pub from_record_index: u64,
    pub to_record_index:   u64,

    /// Merkle root over the canonical JSON of every record in
    /// `[from_record_index, to_record_index]`.
    pub merkle_root: String,
    pub leaf_count:  u64,

    pub journal_id: String,
    pub created_at: String,

    /// Hub identity (e.g. "hub://org-foo"). Required when
    /// `checkpoint_kind == HubOrg`. Empty/absent for local-journal.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hub_id: String,

    /// Hub's signing public key. base64-url no-pad. Required for HubOrg.
    /// Embedded so a verifier can check the signature without a
    /// separate trust root lookup; PR 7+ adds a trusted issuer
    /// registry that pins acceptable hub_public_keys.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hub_public_key: String,

    /// base64-url-no-pad Ed25519 signature over the canonical
    /// signing payload (`canonical_hub_signing_bytes`). Required for
    /// HubOrg.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hub_signature: String,

    /// RFC 3339 timestamp when the Hub signed this checkpoint.
    /// Distinct from `created_at` (which is the local journal's
    /// recorded creation time).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signed_at: String,

    /// Use IDs the Hub asserts this checkpoint covers. The verifier
    /// MUST confirm every package use_id is in this list before
    /// emitting `replay-hub-org` PASS.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_use_ids: Vec<String>,

    /// Grant IDs covered. Informational; the per-use check is what
    /// gates the row.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_grant_ids: Vec<String>,

    #[serde(default)]
    pub previous_record_digest: String,
    #[serde(default)]
    pub record_digest: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
}

impl JournalCheckpoint {
    /// True only when EVERY Hub field is populated -- the precondition
    /// for `replay-hub-org` PASS to be considered. Signature
    /// verification is a separate step.
    pub fn is_hub_signed(&self) -> bool {
        self.checkpoint_kind == CheckpointKind::HubOrg
            && !self.hub_id.is_empty()
            && !self.hub_public_key.is_empty()
            && !self.hub_signature.is_empty()
            && !self.signed_at.is_empty()
    }

    /// Canonical bytes the Hub signs. Stable JSON of every field
    /// except `hub_signature` and `record_digest` (those depend on
    /// the signature itself). Sibling helper to `record_digest`'s
    /// approach in this same module.
    pub fn canonical_hub_signing_bytes(&self) -> Vec<u8> {
        // Build a serializable view that omits hub_signature and
        // record_digest. The previous_record_digest is part of the
        // chain link and SHOULD be signed -- changing it changes the
        // checkpoint's identity in the journal.
        #[derive(Serialize)]
        struct Signing<'a> {
            #[serde(rename = "type")]                    type_: &'a str,
            checkpoint_id:           &'a str,
            checkpoint_kind:         CheckpointKind,
            from_record_index:       u64,
            to_record_index:         u64,
            merkle_root:             &'a str,
            leaf_count:              u64,
            journal_id:              &'a str,
            created_at:              &'a str,
            hub_id:                  &'a str,
            hub_public_key:          &'a str,
            signed_at:               &'a str,
            covered_use_ids:         &'a [String],
            covered_grant_ids:       &'a [String],
            previous_record_digest:  &'a str,
        }
        let v = Signing {
            type_:                   &self.type_,
            checkpoint_id:           &self.checkpoint_id,
            checkpoint_kind:         self.checkpoint_kind,
            from_record_index:       self.from_record_index,
            to_record_index:         self.to_record_index,
            merkle_root:             &self.merkle_root,
            leaf_count:              self.leaf_count,
            journal_id:              &self.journal_id,
            created_at:              &self.created_at,
            hub_id:                  &self.hub_id,
            hub_public_key:          &self.hub_public_key,
            signed_at:               &self.signed_at,
            covered_use_ids:         &self.covered_use_ids,
            covered_grant_ids:       &self.covered_grant_ids,
            previous_record_digest:  &self.previous_record_digest,
        };
        serde_json::to_vec(&v).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Replay-check metadata for verify output
// ---------------------------------------------------------------------------

/// Replay-check level surfaced by `verify`. Lets the printer say exactly
/// what was checked, instead of overclaiming or underclaiming.
///
/// The progression is monotonic in trust strength: each level subsumes
/// the previous. A verifier should report the *strongest* level it
/// successfully checked, never falling back silently to a weaker one
/// just because the stronger one was unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReplayCheckLevel {
    /// No replay check ran (e.g. no approvals in the package).
    NotPerformed,
    /// The package itself was scanned for duplicate uses of the same
    /// nonce. v0.9.6's behavior. No external state consulted.
    PackageLocal,
    /// A local Approval Use Journal was consulted. PR 2's outcome.
    LocalJournal,
    /// A signed Hub / org checkpoint was consulted on top of local. PR 6.
    HubOrg,
}

impl ReplayCheckLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::NotPerformed => "not performed",
            Self::PackageLocal => "package-local",
            Self::LocalJournal => "local-journal",
            Self::HubOrg       => "hub-org",
        }
    }
}

/// Result of the replay check that verify ran. Carries the level that
/// was achieved plus enough context for printers / reports to render
/// "use 1/1" without re-resolving state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayCheck {
    pub level: ReplayCheckLevel,

    /// Which use of the grant was observed. Some when a journal
    /// returned the count; None when no journal was consulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_number: Option<u32>,

    /// Mirror of the grant's `max_actions` at the time of check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,

    /// True when the check passed. False or absent means a violation
    /// (duplicate use, journal tampered, etc.). The `details` string
    /// carries the human-readable reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passed: Option<bool>,

    /// One-line summary shown in verify output and the report.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl ReplayCheck {
    pub fn not_performed() -> Self {
        Self { level: ReplayCheckLevel::NotPerformed, use_number: None, max_uses: None, passed: None, details: None }
    }

    pub fn package_local(passed: bool, details: impl Into<String>) -> Self {
        Self {
            level:      ReplayCheckLevel::PackageLocal,
            use_number: None,
            max_uses:   None,
            passed:     Some(passed),
            details:    Some(details.into()),
        }
    }
}

// ---------------------------------------------------------------------------
// Canonical-form helpers
// ---------------------------------------------------------------------------

/// Compute `record_digest` for an ApprovalUse. The record's own
/// `record_digest` field is excluded from the hash so the value is
/// idempotent: digest_of(record_with_digest_cleared) == record.record_digest.
///
/// Canonical form is JSON with sorted keys (serde_json's default ordering
/// is field-declaration order, which is stable for the typed structs in
/// this module). Both the journal writer and any external auditor must
/// use this exact function to get matching digests.
pub fn approval_use_record_digest(rec: &ApprovalUse) -> String {
    use sha2::{Digest, Sha256};
    let mut canon = rec.clone();
    canon.record_digest = String::new();
    let bytes = serde_json::to_vec(&canon).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64 + 7);
    hex.push_str("sha256:");
    for b in digest.as_slice() {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

pub fn approval_revocation_record_digest(rec: &ApprovalRevocation) -> String {
    use sha2::{Digest, Sha256};
    let mut canon = rec.clone();
    canon.record_digest = String::new();
    let bytes = serde_json::to_vec(&canon).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64 + 7);
    hex.push_str("sha256:");
    for b in digest.as_slice() {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

pub fn journal_checkpoint_record_digest(rec: &JournalCheckpoint) -> String {
    use sha2::{Digest, Sha256};
    let mut canon = rec.clone();
    canon.record_digest = String::new();
    let bytes = serde_json::to_vec(&canon).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64 + 7);
    hex.push_str("sha256:");
    for b in digest.as_slice() {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

/// Outcome of `verify_hub_checkpoint_signature`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HubCheckpointVerification {
    /// Signature verified. The checkpoint was genuinely signed by
    /// `hub_public_key`. Coverage is the caller's job to assert.
    Valid,
    /// Checkpoint claims `kind=HubOrg` but is missing one of
    /// `hub_id`, `hub_public_key`, `hub_signature`, or `signed_at`.
    /// Verifiers MUST treat this the same as Tampered for the
    /// purpose of emitting `replay-hub-org`.
    MissingFields(&'static str),
    /// Signature did not verify against the embedded public key.
    /// Tampered or wrong key.
    Tampered,
    /// Checkpoint kind is `LocalJournal` -- nothing to verify here.
    /// Caller should not have called this; surface as a programming
    /// error.
    NotHubKind,
}

/// Verify the embedded Hub signature on a `JournalCheckpoint`. Does NOT
/// check coverage (`covered_use_ids`) -- that's the caller's job, since
/// it depends on which uses the package contains.
///
/// Verification rule: the public key in the checkpoint must successfully
/// validate the signature against `canonical_hub_signing_bytes()`. If
/// any required field is empty or the signature decodes wrong, the
/// result is `Tampered` (or `MissingFields` for upfront validation
/// failures). Never returns `Valid` on a borderline -- the
/// release rule "no global single-use claim without verified Hub
/// checkpoint" is enforced here.
pub fn verify_hub_checkpoint_signature(
    cp: &JournalCheckpoint,
) -> HubCheckpointVerification {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if cp.checkpoint_kind != CheckpointKind::HubOrg {
        return HubCheckpointVerification::NotHubKind;
    }
    if cp.hub_id.is_empty()         { return HubCheckpointVerification::MissingFields("hub_id"); }
    if cp.hub_public_key.is_empty() { return HubCheckpointVerification::MissingFields("hub_public_key"); }
    if cp.hub_signature.is_empty()  { return HubCheckpointVerification::MissingFields("hub_signature"); }
    if cp.signed_at.is_empty()      { return HubCheckpointVerification::MissingFields("signed_at"); }

    let pk_bytes = match URL_SAFE_NO_PAD.decode(cp.hub_public_key.as_bytes()) {
        Ok(b) if b.len() == 32 => b,
        _ => return HubCheckpointVerification::Tampered,
    };
    let sig_bytes = match URL_SAFE_NO_PAD.decode(cp.hub_signature.as_bytes()) {
        Ok(b) if b.len() == 64 => b,
        _ => return HubCheckpointVerification::Tampered,
    };
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_bytes);
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    let vk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(k)  => k,
        Err(_) => return HubCheckpointVerification::Tampered,
    };
    let sig = Signature::from_bytes(&sig_arr);
    let payload = cp.canonical_hub_signing_bytes();
    match vk.verify(&payload, &sig) {
        Ok(())  => HubCheckpointVerification::Valid,
        Err(_)  => HubCheckpointVerification::Tampered,
    }
}

/// sha256 over a raw approval nonce, prefixed `sha256:`. Used everywhere
/// the journal needs to reference a grant's nonce without storing it.
pub fn nonce_digest(raw_nonce: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(raw_nonce.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(64 + 7);
    hex.push_str("sha256:");
    for b in digest.as_slice() {
        use std::fmt::Write;
        let _ = write!(hex, "{b:02x}");
    }
    hex
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_use() -> ApprovalUse {
        ApprovalUse {
            type_:                  TYPE_APPROVAL_USE.into(),
            use_id:                 "use_abc".into(),
            grant_id:               "art_grant_1".into(),
            grant_digest:           "sha256:00".into(),
            nonce_digest:           "sha256:11".into(),
            actor:                  "agent://deployer".into(),
            action:                 "deploy.production".into(),
            subject:                "env://production".into(),
            session_id:             Some("ssn_xyz".into()),
            action_artifact_id:     None,
            receipt_digest:         None,
            use_number:             1,
            max_uses:               Some(1),
            idempotency_key:        None,
            created_at:             "2026-04-30T06:00:00Z".into(),
            expires_at:             None,
            previous_record_digest: String::new(),
            record_digest:          String::new(),
            signature:              None,
            signature_alg:          None,
            signing_key_id:         None,
        }
    }

    #[test]
    fn approval_use_serialization_round_trips() {
        let u = sample_use();
        let bytes = serde_json::to_vec(&u).unwrap();
        let back: ApprovalUse = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.use_id, u.use_id);
        assert_eq!(back.grant_id, u.grant_id);
        assert_eq!(back.use_number, 1);
    }

    #[test]
    fn record_digest_is_stable_and_excludes_itself() {
        // The digest of a record must be the same whether `record_digest`
        // was empty or already populated -- the function clears it
        // internally before hashing.
        let u1 = sample_use();
        let mut u2 = u1.clone();
        u2.record_digest = "sha256:cafe".into();
        assert_eq!(approval_use_record_digest(&u1), approval_use_record_digest(&u2));
    }

    #[test]
    fn previous_record_digest_chains() {
        // Two sample records produce a chain: record N's
        // previous_record_digest equals record N-1's record_digest.
        // This pins the property the journal writer must uphold.
        let mut a = sample_use();
        a.use_number = 1;
        a.record_digest = approval_use_record_digest(&a);

        let mut b = sample_use();
        b.use_number = 2;
        b.use_id = "use_def".into();
        b.previous_record_digest = a.record_digest.clone();
        b.record_digest = approval_use_record_digest(&b);

        assert_eq!(b.previous_record_digest, a.record_digest);
        // A different parent breaks the chain check (different digest).
        let mut c = sample_use();
        c.use_id = "use_ghi".into();
        c.use_number = 2;
        c.previous_record_digest = "sha256:wrong".into();
        c.record_digest = approval_use_record_digest(&c);
        assert_ne!(b.record_digest, c.record_digest);
    }

    #[test]
    fn nonce_digest_does_not_leak_raw_nonce() {
        // The journal stores nonce_digest, never the raw nonce. The
        // schema enforces this by design (no `nonce` field on
        // ApprovalUse) -- this test just pins the helper.
        let raw = "n_abcdef0123";
        let d = nonce_digest(raw);
        assert!(d.starts_with("sha256:"));
        assert!(!d.contains(raw), "digest must not contain the raw nonce");
    }

    #[test]
    fn replay_check_level_labels() {
        assert_eq!(ReplayCheckLevel::NotPerformed.label(), "not performed");
        assert_eq!(ReplayCheckLevel::PackageLocal.label(), "package-local");
        assert_eq!(ReplayCheckLevel::LocalJournal.label(), "local-journal");
        assert_eq!(ReplayCheckLevel::HubOrg.label(),       "hub-org");
    }

    #[test]
    fn replay_check_serialization_uses_kebab_case() {
        let r = ReplayCheck {
            level:      ReplayCheckLevel::LocalJournal,
            use_number: Some(1),
            max_uses:   Some(1),
            passed:     Some(true),
            details:    Some("local Approval Use Journal passed".into()),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["level"], "local-journal");
        assert_eq!(v["use_number"], 1);
        assert_eq!(v["max_uses"], 1);
        assert_eq!(v["passed"], true);
    }

    #[test]
    fn revocation_record_digest_stable() {
        let rev = ApprovalRevocation {
            type_:                  TYPE_APPROVAL_REVOCATION.into(),
            revocation_id:          "rev_1".into(),
            grant_id:               "art_grant_1".into(),
            grant_digest:           "sha256:00".into(),
            revoker:                "human://alice".into(),
            reason:                 Some("rotated key".into()),
            created_at:             "2026-04-30T06:01:00Z".into(),
            previous_record_digest: "sha256:00".into(),
            record_digest:          String::new(),
            signature:              None,
            signature_alg:          None,
            signing_key_id:         None,
        };
        let d1 = approval_revocation_record_digest(&rev);
        let d2 = approval_revocation_record_digest(&rev);
        assert_eq!(d1, d2);
    }

    fn sample_checkpoint(kind: CheckpointKind) -> JournalCheckpoint {
        JournalCheckpoint {
            type_:                  TYPE_JOURNAL_CHECKPOINT.into(),
            checkpoint_id:          "cp_1".into(),
            checkpoint_kind:        kind,
            from_record_index:      1,
            to_record_index:        10,
            merkle_root:            "sha256:abcd".into(),
            leaf_count:             10,
            journal_id:             "journal_1".into(),
            created_at:             "2026-04-30T06:02:00Z".into(),
            hub_id:                 String::new(),
            hub_public_key:         String::new(),
            hub_signature:          String::new(),
            signed_at:              String::new(),
            covered_use_ids:        Vec::new(),
            covered_grant_ids:      Vec::new(),
            previous_record_digest: "sha256:00".into(),
            record_digest:          String::new(),
            signature:              None,
            signature_alg:          None,
            signing_key_id:         None,
        }
    }

    #[test]
    fn checkpoint_record_digest_stable() {
        let cp = sample_checkpoint(CheckpointKind::LocalJournal);
        let d1 = journal_checkpoint_record_digest(&cp);
        let d2 = journal_checkpoint_record_digest(&cp);
        assert_eq!(d1, d2);
    }

    #[test]
    fn checkpoint_kind_defaults_to_local_journal() {
        // Pre-PR-6 records serialized without the field; deserialize
        // must default to LocalJournal so existing PR 4 packages
        // verify identically.
        let json = r#"{"type":"treeship/journal-checkpoint/v1","checkpoint_id":"cp_legacy",
            "from_record_index":1,"to_record_index":10,"merkle_root":"sha256:00",
            "leaf_count":10,"journal_id":"j","created_at":"2026-04-30T00:00:00Z"}"#;
        let cp: JournalCheckpoint = serde_json::from_str(json).unwrap();
        assert_eq!(cp.checkpoint_kind, CheckpointKind::LocalJournal);
        assert!(!cp.is_hub_signed());
    }

    #[test]
    fn checkpoint_kind_serializes_kebab_case() {
        let cp = sample_checkpoint(CheckpointKind::HubOrg);
        let v = serde_json::to_value(&cp).unwrap();
        assert_eq!(v["checkpoint_kind"], "hub-org");
    }

    #[test]
    fn local_journal_checkpoint_is_not_hub_signed() {
        let cp = sample_checkpoint(CheckpointKind::LocalJournal);
        assert!(!cp.is_hub_signed());
        assert_eq!(
            verify_hub_checkpoint_signature(&cp),
            HubCheckpointVerification::NotHubKind,
        );
    }

    #[test]
    fn hub_kind_without_fields_is_missing() {
        let cp = sample_checkpoint(CheckpointKind::HubOrg);
        assert!(!cp.is_hub_signed());
        assert!(matches!(
            verify_hub_checkpoint_signature(&cp),
            HubCheckpointVerification::MissingFields(_),
        ));
    }

    /// End-to-end: sign a Hub checkpoint with a real Ed25519 key,
    /// embed the signature, verify it round-trips. The release rule
    /// pins on this path: replay-hub-org cannot pass without a real
    /// signature here.
    #[test]
    fn hub_checkpoint_signature_round_trip() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use ed25519_dalek::{Signer, SigningKey};

        let mut sk_bytes = [0u8; 32];
        for (i, b) in sk_bytes.iter_mut().enumerate() {
            *b = i as u8 + 7;
        }
        let sk = SigningKey::from_bytes(&sk_bytes);
        let pk = sk.verifying_key();
        let pk_b64 = URL_SAFE_NO_PAD.encode(pk.to_bytes());

        let mut cp = sample_checkpoint(CheckpointKind::HubOrg);
        cp.hub_id          = "hub://zerker-org".into();
        cp.hub_public_key  = pk_b64.clone();
        cp.signed_at       = "2026-04-30T07:00:00Z".into();
        cp.covered_use_ids = vec!["use_alpha".into(), "use_beta".into()];

        let payload = cp.canonical_hub_signing_bytes();
        let sig     = sk.sign(&payload);
        cp.hub_signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());

        assert!(cp.is_hub_signed());
        assert_eq!(
            verify_hub_checkpoint_signature(&cp),
            HubCheckpointVerification::Valid,
        );
    }

    #[test]
    fn tampered_hub_checkpoint_fails_verification() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use ed25519_dalek::{Signer, SigningKey};

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let pk = sk.verifying_key();

        let mut cp = sample_checkpoint(CheckpointKind::HubOrg);
        cp.hub_id          = "hub://x".into();
        cp.hub_public_key  = URL_SAFE_NO_PAD.encode(pk.to_bytes());
        cp.signed_at       = "2026-04-30T07:00:00Z".into();
        cp.covered_use_ids = vec!["use_alpha".into()];

        let sig = sk.sign(&cp.canonical_hub_signing_bytes());
        cp.hub_signature = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        // Sanity: signature is good before tamper.
        assert_eq!(verify_hub_checkpoint_signature(&cp), HubCheckpointVerification::Valid);

        // Tamper with covered_use_ids -- now the canonical bytes
        // change, signature no longer applies.
        cp.covered_use_ids.push("use_smuggled".into());
        assert_eq!(
            verify_hub_checkpoint_signature(&cp),
            HubCheckpointVerification::Tampered,
        );
    }

    #[test]
    fn wrong_key_fails_verification() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use ed25519_dalek::{Signer, SigningKey};

        let sk_real = SigningKey::from_bytes(&[2u8; 32]);
        let sk_imp  = SigningKey::from_bytes(&[3u8; 32]); // different key
        let pk_imp  = sk_imp.verifying_key();

        let mut cp = sample_checkpoint(CheckpointKind::HubOrg);
        cp.hub_id          = "hub://x".into();
        // Signature made by sk_real, but public key claims sk_imp.
        cp.hub_public_key  = URL_SAFE_NO_PAD.encode(pk_imp.to_bytes());
        cp.signed_at       = "2026-04-30T07:00:00Z".into();
        let sig = sk_real.sign(&cp.canonical_hub_signing_bytes());
        cp.hub_signature   = URL_SAFE_NO_PAD.encode(sig.to_bytes());
        assert_eq!(
            verify_hub_checkpoint_signature(&cp),
            HubCheckpointVerification::Tampered,
        );
    }

    #[test]
    fn malformed_pubkey_or_signature_fails() {
        let mut cp = sample_checkpoint(CheckpointKind::HubOrg);
        cp.hub_id          = "hub://x".into();
        cp.hub_public_key  = "not-base64!!".into();
        cp.hub_signature   = "also-not-base64".into();
        cp.signed_at       = "2026-04-30T07:00:00Z".into();
        assert_eq!(
            verify_hub_checkpoint_signature(&cp),
            HubCheckpointVerification::Tampered,
        );
    }
}
