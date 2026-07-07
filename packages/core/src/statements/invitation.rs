//! Agent invitation statement -- Phase 1 of the agent-invitations spec.
//!
//! See `docs/specs/agent-invitations-rooms.md`.
//!
//! An invitation is structurally an Approval Grant for `action_type =
//! "session.join"`. The host (the session's owning signing key) mints a
//! single-use, expiring, restriction-bound grant; the joining agent
//! redeems it by emitting a participant event (see
//! `session_participant.rs`). Replay protection comes from the existing
//! Approval Use Journal -- the invitation's nonce is hashed into a
//! `nonce_digest` and the journal rejects double-consumption.
//!
//! Phase 1 scope (decisions locked in by the maintainer):
//!
//! * `invitee_restriction` default is `Cert` for production. `Pubkey` is
//!   the tighter option; `Open` is opt-in only.
//! * `expires_at` default is 1 hour; the protocol-level maximum is 7
//!   days, enforced at mint time via `validate_for_mint`.
//! * `max_uses` is always 1 in Phase 1 -- the schema carries it for
//!   forward-compat but mint rejects any other value.
//! * Authority is HostOnly: the issuer pubkey is the session's owning
//!   signing key. Delegation is Phase 2.
//!
//! The canonical signing string follows the v0.10.4 pattern: a
//! pipe-delimited line that binds every field that participates in
//! verification dispatch. New fields added in future versions go through
//! a `canonical_version` bump, not a silent extension.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attestation::{Signer, SignerError};

// ---------------------------------------------------------------------------
// Type constants
// ---------------------------------------------------------------------------

pub const TYPE_INVITATION: &str = "treeship/invitation/v1";

/// Maximum allowed lifetime of a freshly minted invitation, in seconds.
/// 7 days. Enforced at mint time. Verifiers do NOT re-check this bound
/// (an invitation that was minted under a different binary with a
/// looser bound would still verify cryptographically; the protocol-level
/// guarantee is "the host promised to bound their own mints").
pub const MAX_INVITATION_LIFETIME_SECS: u64 = 7 * 24 * 60 * 60;

/// Default invitation lifetime when the operator does not specify one.
/// 1 hour. Matches the recommendation in the spec.
pub const DEFAULT_INVITATION_LIFETIME_SECS: u64 = 60 * 60;

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// Who may redeem an invitation. Three shapes; the default for new
/// invitations is `Cert`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InviteeRestriction {
    /// Tightest: only the agent whose pubkey hashes to `fingerprint` may
    /// join. Fingerprint is `sha256(canonical_pubkey)`'s first 16 hex
    /// chars, matching `pubkey_fingerprint` in the trust CLI.
    Pubkey { fingerprint: String },
    /// Production sweet spot: any agent holding a certificate issued by
    /// `issuer_pubkey` whose subject is in `allowed_subjects`.
    Cert {
        issuer_pubkey: String,
        allowed_subjects: Vec<String>,
    },
    /// Anyone holding the blob may redeem. Opt-in only; the CLI refuses
    /// to mint an Open invitation without an explicit `--open` flag.
    Open,
}

/// Capabilities granted to the joining agent. Phase 1 carries only
/// `action_types`; `workflow_node_ids` comes in Phase 3 once PR #107
/// (workflow declarations) lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantedCapabilities {
    /// Dot-namespaced action labels the joining agent is authorized to
    /// emit (e.g. `["tool.call", "agent.handoff"]`). Empty means no
    /// capabilities (degenerate; the CLI warns).
    #[serde(default)]
    pub action_types: Vec<String>,
}

/// One signed invitation. Wrap in a DSSE envelope via
/// `crate::attestation::sign` with `payload_type("invitation")` to seal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationStatement {
    #[serde(rename = "type")]
    pub type_: String,

    /// `session_id` (e.g. `ssn_<hex>`) that this invitation joins.
    pub session_ref: String,

    /// Issuer's Ed25519 public key as base64url-no-pad. Verifiers MUST
    /// confirm this key is present in the trust root store under kind
    /// `SessionHost` before honoring the invitation.
    pub issuer: String,

    pub invitee_restriction: InviteeRestriction,

    pub granted_capabilities: GrantedCapabilities,

    /// RFC 3339 expiry timestamp.
    pub expires_at: String,

    /// Always 1 in Phase 1. The schema carries the field so multi-use
    /// invitations (roadmap) don't need a canonical-format bump.
    pub max_uses: u32,

    /// Random hex-encoded nonce. The Approval Use Journal indexes its
    /// SHA-256 digest, so the journal never sees the raw nonce.
    pub nonce: String,
}

impl InvitationStatement {
    /// Construct an invitation with the current canonical type tag.
    pub fn new(
        session_ref: impl Into<String>,
        issuer: impl Into<String>,
        invitee_restriction: InviteeRestriction,
        granted_capabilities: GrantedCapabilities,
        expires_at: impl Into<String>,
        nonce: impl Into<String>,
    ) -> Self {
        Self {
            type_:                TYPE_INVITATION.into(),
            session_ref:          session_ref.into(),
            issuer:               issuer.into(),
            invitee_restriction,
            granted_capabilities,
            expires_at:           expires_at.into(),
            max_uses:             1,
            nonce:                nonce.into(),
        }
    }

    /// Canonical signing bytes. Pipe-delimited, version-prefixed,
    /// following the v0.10.4 `Checkpoint::canonical_for_signing` shape.
    ///
    /// Format:
    /// `"v1|invitation|{session_ref}|{issuer}|{restriction_canonical}|{capabilities_canonical}|{expires_at}|{max_uses}|{nonce_digest}"`
    ///
    /// `restriction_canonical` and `capabilities_canonical` are
    /// `sha256:<hex>` digests over the sorted-key canonical JSON
    /// serialization of the field. Hashing them keeps the canonical
    /// string a single line regardless of field cardinality (cert
    /// `allowed_subjects` is a Vec; embedding it directly would require
    /// a sub-delimiter and reopen the parser-mismatch attack surface
    /// that pipe-delimited canonicals are designed to avoid).
    ///
    /// `nonce_digest` (not the raw nonce) is bound for the same reason
    /// the Approval Use Journal stores the digest: the raw nonce is
    /// already in the signed envelope's payload bytes, so binding the
    /// digest into the canonical adds redundancy without exposing the
    /// nonce in a second place.
    pub fn canonical_for_signing(&self) -> String {
        let restriction_digest  = canonical_json_digest(&self.invitee_restriction);
        let capabilities_digest = canonical_json_digest(&self.granted_capabilities);
        let nonce_d             = nonce_digest_hex(&self.nonce);
        format!(
            "v1|invitation|{}|{}|{}|{}|{}|{}|{}",
            self.session_ref,
            self.issuer,
            restriction_digest,
            capabilities_digest,
            self.expires_at,
            self.max_uses,
            nonce_d,
        )
    }

    /// Sign the invitation under the host's keypair. The signature is
    /// over the canonical bytes (see `canonical_for_signing`), encoded
    /// as base64url-no-pad. The signed envelope (DSSE) is produced by
    /// callers via `crate::attestation::sign`; this helper produces
    /// just the raw signature so callers can compose either way.
    pub fn sign_canonical(&self, signer: &dyn Signer) -> Result<String, SignerError> {
        let canonical = self.canonical_for_signing();
        let sig = signer.sign(canonical.as_bytes())?;
        Ok(URL_SAFE_NO_PAD.encode(sig))
    }

    /// Verify the supplied `signature_b64url` against `self.issuer`'s
    /// pubkey over the canonical bytes. Returns `true` only when both
    /// the pubkey decodes cleanly AND the signature math checks out.
    /// Does NOT consult trust roots -- the caller is responsible for
    /// checking that `self.issuer` is pinned under kind `SessionHost`.
    pub fn verify_canonical(&self, signature_b64url: &str) -> bool {
        let pk_bytes = match URL_SAFE_NO_PAD.decode(self.issuer.as_bytes()) {
            Ok(b) if b.len() == 32 => b,
            _ => return false,
        };
        let sig_bytes = match URL_SAFE_NO_PAD.decode(signature_b64url.as_bytes()) {
            Ok(b) if b.len() == 64 => b,
            _ => return false,
        };
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);
        let vk = match VerifyingKey::from_bytes(&pk_arr) {
            Ok(k)  => k,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify_strict(self.canonical_for_signing().as_bytes(), &sig).is_ok()
    }

    /// Mint-time validation: rejects invitations that violate
    /// protocol-level invariants the verifier alone cannot enforce.
    ///
    /// * `expires_at` parses as RFC 3339 and is in the future.
    /// * `expires_at - now_unix_secs` does not exceed
    ///   `MAX_INVITATION_LIFETIME_SECS` (7 days).
    /// * `max_uses == 1` (Phase 1).
    /// * `session_ref` and `nonce` are non-empty.
    /// * `issuer` decodes as a 32-byte Ed25519 pubkey.
    pub fn validate_for_mint(&self, now_unix_secs: u64) -> Result<(), InvitationError> {
        if self.session_ref.trim().is_empty() {
            return Err(InvitationError::EmptyField("session_ref"));
        }
        if self.nonce.trim().is_empty() {
            return Err(InvitationError::EmptyField("nonce"));
        }
        if self.max_uses != 1 {
            return Err(InvitationError::MaxUsesUnsupported { max_uses: self.max_uses });
        }
        // issuer parse check
        let pk_bytes = URL_SAFE_NO_PAD
            .decode(self.issuer.as_bytes())
            .map_err(|_| InvitationError::IssuerNotEd25519)?;
        if pk_bytes.len() != 32 {
            return Err(InvitationError::IssuerNotEd25519);
        }
        let expires_secs = parse_rfc3339_to_unix(&self.expires_at)
            .ok_or(InvitationError::ExpiresAtNotRfc3339)?;
        if expires_secs <= now_unix_secs {
            return Err(InvitationError::ExpiresInPast);
        }
        let lifetime = expires_secs - now_unix_secs;
        if lifetime > MAX_INVITATION_LIFETIME_SECS {
            return Err(InvitationError::LifetimeTooLong {
                requested_secs: lifetime,
                max_secs:       MAX_INVITATION_LIFETIME_SECS,
            });
        }
        Ok(())
    }

    /// True when `now_unix_secs >= expires_at`. Verifiers call this at
    /// redeem time. Returns true on a malformed `expires_at` so that a
    /// tampered field fails closed.
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        match parse_rfc3339_to_unix(&self.expires_at) {
            Some(secs) => now_unix_secs >= secs,
            None       => true,
        }
    }

    /// Returns `sha256(<raw nonce>)` in `sha256:<hex>` form. Same digest
    /// the Approval Use Journal indexes by; callers route invitation
    /// consumption through the journal using this value.
    pub fn nonce_digest(&self) -> String {
        nonce_digest_hex(&self.nonce)
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvitationError {
    EmptyField(&'static str),
    IssuerNotEd25519,
    ExpiresAtNotRfc3339,
    ExpiresInPast,
    LifetimeTooLong { requested_secs: u64, max_secs: u64 },
    MaxUsesUnsupported { max_uses: u32 },
}

impl std::fmt::Display for InvitationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyField(name) => write!(f, "invitation field {name} must not be empty"),
            Self::IssuerNotEd25519 => write!(
                f,
                "invitation issuer must decode to a 32-byte Ed25519 public key (base64url-no-pad)",
            ),
            Self::ExpiresAtNotRfc3339 => write!(
                f,
                "invitation expires_at must be RFC 3339 (e.g. 2026-05-18T12:00:00Z)",
            ),
            Self::ExpiresInPast => write!(f, "invitation expires_at must be in the future at mint time"),
            Self::LifetimeTooLong { requested_secs, max_secs } => write!(
                f,
                "invitation lifetime {requested_secs}s exceeds protocol max {max_secs}s ({} days)",
                max_secs / (24 * 60 * 60),
            ),
            Self::MaxUsesUnsupported { max_uses } => write!(
                f,
                "invitation max_uses must be 1 in Phase 1 (got {max_uses}); \
                 multi-use invitations are a future-version feature",
            ),
        }
    }
}

impl std::error::Error for InvitationError {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Helper used by both invitation + participant canonicals: a deterministic
/// digest over the sorted-key canonical JSON of a serializable value.
/// Folds variable-length fields into a fixed-length string so the
/// pipe-delimited canonical stays single-line and unambiguous.
///
/// Panics if the value cannot serialize -- caller types are all in-crate
/// concrete structs/enums with primitive fields, so failure here would
/// signal a programming bug (same audit lane C rationale as the
/// approval_use record-digest helpers).
pub(crate) fn canonical_json_digest<T: Serialize>(value: &T) -> String {
    let json_value = serde_json::to_value(value)
        .expect("canonical_json_digest: serialize must not fail for in-crate types");
    let canonical = canonical_json_string(&json_value);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

/// Sorted-key canonical JSON. Mirrors `merkle::checkpoint::canonical_json_string`
/// (intentionally a copy rather than a cross-module pub use; the merkle
/// version is private and this module needs the same behavior without
/// reaching into a sibling's internals).
fn canonical_json_string(value: &serde_json::Value) -> String {
    use std::collections::BTreeMap;
    match value {
        serde_json::Value::Object(map) => {
            let sorted: BTreeMap<&String, String> = map
                .iter()
                .map(|(k, v)| (k, canonical_json_string(v)))
                .collect();
            let mut out = String::from("{");
            let mut first = true;
            for (k, v) in sorted {
                if !first { out.push(','); }
                first = false;
                let key_json = serde_json::to_string(k)
                    .expect("string serializes to JSON");
                out.push_str(&key_json);
                out.push(':');
                out.push_str(&v);
            }
            out.push('}');
            out
        }
        serde_json::Value::Array(items) => {
            let mut out = String::from("[");
            let mut first = true;
            for v in items {
                if !first { out.push(','); }
                first = false;
                out.push_str(&canonical_json_string(v));
            }
            out.push(']');
            out
        }
        other => serde_json::to_string(other)
            .expect("scalar JSON value serializes"),
    }
}

/// `sha256(<raw_nonce>)` as `sha256:<hex>`. Shared with the journal
/// (`statements::approval_use::nonce_digest`); kept here so the
/// invitation module does not depend on the journal-side type.
fn nonce_digest_hex(raw_nonce: &str) -> String {
    let digest = Sha256::digest(raw_nonce.as_bytes());
    format!("sha256:{}", hex::encode(digest))
}

/// Parse RFC 3339 / ISO 8601 timestamps in the subset Treeship emits
/// (`YYYY-MM-DDTHH:MM:SSZ`). Returns Unix epoch seconds. Returns
/// `None` on any parse failure -- callers that need a hard error
/// translate this into the appropriate `InvitationError`.
///
/// We deliberately do not pull in `chrono` here -- the statements module
/// is dep-light by design and already implements `unix_to_rfc3339`. This
/// is the inverse.
pub fn parse_rfc3339_to_unix(s: &str) -> Option<u64> {
    // Strict shape: 20 bytes, "YYYY-MM-DDTHH:MM:SSZ".
    let b = s.as_bytes();
    if b.len() != 20 || b[10] != b'T' || b[19] != b'Z'
        || b[4] != b'-' || b[7] != b'-'
        || b[13] != b':' || b[16] != b':'
    {
        return None;
    }
    let year:  i64 = std::str::from_utf8(&b[0..4]).ok()?.parse().ok()?;
    let month: u32 = std::str::from_utf8(&b[5..7]).ok()?.parse().ok()?;
    let day:   u32 = std::str::from_utf8(&b[8..10]).ok()?.parse().ok()?;
    let hour:  u32 = std::str::from_utf8(&b[11..13]).ok()?.parse().ok()?;
    let min:   u32 = std::str::from_utf8(&b[14..16]).ok()?.parse().ok()?;
    let sec:   u32 = std::str::from_utf8(&b[17..19]).ok()?.parse().ok()?;
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23 || min > 59 || sec > 60
    {
        return None;
    }
    // Days since 1970-01-01 to start of (year, month, day).
    let mut days: i64 = 0;
    for y in 1970..year {
        days += if is_leap(y as u64) { 366 } else { 365 };
    }
    let months = if is_leap(year as u64) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    for m in 1..month {
        days += months[(m - 1) as usize];
    }
    days += (day - 1) as i64;
    let total = days * 86_400 + (hour as i64) * 3600 + (min as i64) * 60 + (sec as i64);
    if total < 0 { return None; }
    Some(total as u64)
}

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

/// Generate a random hex-encoded nonce suitable for an invitation.
/// 16 bytes -> 32 hex chars; matches the entropy of an Ed25519 keyid.
pub fn generate_nonce() -> String {
    use rand::{rngs::OsRng, RngCore};
    let mut buf = [0u8; 16];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// `sha256(<canonical_pk>)` truncated to first 16 hex chars. Mirrors
/// `pubkey_fingerprint` in the trust CLI so a `Pubkey` restriction can
/// be checked against either input format. Operators paste either form
/// into `--invitee-pubkey`.
pub fn pubkey_fingerprint_short(canonical_pk: &str) -> String {
    let bytes = Sha256::digest(canonical_pk.as_bytes());
    hex::encode(bytes)[..16].to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::Ed25519Signer;

    fn sample_caps() -> GrantedCapabilities {
        GrantedCapabilities {
            action_types: vec!["tool.call".into(), "agent.handoff".into()],
        }
    }

    fn host_signer() -> Ed25519Signer {
        Ed25519Signer::from_bytes("host_key", &[7u8; 32]).unwrap()
    }

    fn fixed_now() -> u64 {
        // 2026-05-18T00:00:00Z
        1_779_580_800
    }

    fn one_hour_after(now: u64) -> String {
        crate::statements::unix_to_rfc3339(now + 3600)
    }

    fn sample(restriction: InviteeRestriction) -> InvitationStatement {
        let signer = host_signer();
        let issuer = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());
        InvitationStatement::new(
            "ssn_room_abc",
            issuer,
            restriction,
            sample_caps(),
            one_hour_after(fixed_now()),
            "nonce_deadbeef",
        )
    }

    #[test]
    fn invitation_round_trips_serde() {
        let inv = sample(InviteeRestriction::Open);
        let bytes = serde_json::to_vec(&inv).unwrap();
        let back: InvitationStatement = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.session_ref, inv.session_ref);
        assert_eq!(back.type_, TYPE_INVITATION);
        assert_eq!(back.max_uses, 1);
    }

    /// The canonical signing bytes MUST include every field. Mutating
    /// any one of them must change the canonical (and thus break the
    /// signature). This pins the audit-lane-D property: no
    /// wire-controllable field is unbound.
    #[test]
    fn invitation_canonical_includes_all_fields() {
        let base = sample(InviteeRestriction::Cert {
            issuer_pubkey:    "ed25519:AAA".into(),
            allowed_subjects: vec!["org-x".into()],
        });
        let base_canonical = base.canonical_for_signing();

        let mut m1 = base.clone(); m1.session_ref = "ssn_other".into();
        assert_ne!(m1.canonical_for_signing(), base_canonical, "session_ref must bind");

        let mut m2 = base.clone(); m2.issuer = URL_SAFE_NO_PAD.encode([9u8; 32]);
        assert_ne!(m2.canonical_for_signing(), base_canonical, "issuer must bind");

        let mut m3 = base.clone();
        m3.invitee_restriction = InviteeRestriction::Open;
        assert_ne!(m3.canonical_for_signing(), base_canonical, "restriction must bind");

        let mut m4 = base.clone();
        m4.granted_capabilities.action_types.push("extra.cap".into());
        assert_ne!(m4.canonical_for_signing(), base_canonical, "capabilities must bind");

        let mut m5 = base.clone(); m5.expires_at = one_hour_after(fixed_now() + 1);
        assert_ne!(m5.canonical_for_signing(), base_canonical, "expires_at must bind");

        // max_uses is locked at 1 in Phase 1, but the schema field is
        // bound into the canonical so a future relax doesn't silently
        // verify older invitations under the wrong value.
        let mut m6 = base.clone(); m6.max_uses = 2;
        assert_ne!(m6.canonical_for_signing(), base_canonical, "max_uses must bind");

        let mut m7 = base.clone(); m7.nonce = "nonce_other".into();
        assert_ne!(m7.canonical_for_signing(), base_canonical, "nonce must bind");
    }

    #[test]
    fn invitation_sign_and_verify_roundtrip() {
        let inv = sample(InviteeRestriction::Open);
        let signer = host_signer();
        let sig = inv.sign_canonical(&signer).unwrap();
        assert!(inv.verify_canonical(&sig));
    }

    #[test]
    fn invitation_verify_rejects_wrong_signature() {
        let inv = sample(InviteeRestriction::Open);
        // Sign with a different key than `inv.issuer`.
        let attacker = Ed25519Signer::from_bytes("att", &[3u8; 32]).unwrap();
        let sig = inv.sign_canonical(&attacker).unwrap();
        assert!(!inv.verify_canonical(&sig));
    }

    #[test]
    fn invitation_verify_rejects_tampered_canonical() {
        let mut inv = sample(InviteeRestriction::Open);
        let signer = host_signer();
        let sig = inv.sign_canonical(&signer).unwrap();
        // Mutate after signing -- verification must fail.
        inv.session_ref = "ssn_tampered".into();
        assert!(!inv.verify_canonical(&sig));
    }

    /// Q2 default: invitations MUST NOT mint with > 7d expiry.
    #[test]
    fn invitation_expiry_max_7d_enforced() {
        let now = fixed_now();
        let signer = host_signer();
        let issuer = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());

        // 7 days + 1 second -> rejected.
        let too_long = crate::statements::unix_to_rfc3339(now + MAX_INVITATION_LIFETIME_SECS + 1);
        let inv = InvitationStatement::new(
            "ssn_a", issuer.clone(),
            InviteeRestriction::Open, sample_caps(),
            too_long, "n1",
        );
        match inv.validate_for_mint(now) {
            Err(InvitationError::LifetimeTooLong { .. }) => {}
            other => panic!("expected LifetimeTooLong, got {other:?}"),
        }

        // Exactly 7 days -> accepted.
        let exact = crate::statements::unix_to_rfc3339(now + MAX_INVITATION_LIFETIME_SECS);
        let inv_ok = InvitationStatement::new(
            "ssn_a", issuer,
            InviteeRestriction::Open, sample_caps(),
            exact, "n2",
        );
        assert!(inv_ok.validate_for_mint(now).is_ok());
    }

    #[test]
    fn invitation_validate_rejects_past_expiry() {
        let now = fixed_now();
        let signer = host_signer();
        let issuer = URL_SAFE_NO_PAD.encode(signer.public_key_bytes());
        let past = crate::statements::unix_to_rfc3339(now - 60);
        let inv = InvitationStatement::new(
            "ssn_a", issuer, InviteeRestriction::Open, sample_caps(), past, "n",
        );
        assert_eq!(inv.validate_for_mint(now), Err(InvitationError::ExpiresInPast));
    }

    #[test]
    fn invitation_validate_rejects_max_uses_not_one() {
        let now = fixed_now();
        let mut inv = sample(InviteeRestriction::Open);
        inv.max_uses = 2;
        match inv.validate_for_mint(now) {
            Err(InvitationError::MaxUsesUnsupported { max_uses }) => assert_eq!(max_uses, 2),
            other => panic!("expected MaxUsesUnsupported, got {other:?}"),
        }
    }

    /// Q1: Pubkey restriction rejects join with a wrong pubkey.
    #[test]
    fn invitation_pubkey_restriction_enforced() {
        // Mint a Pubkey-restricted invitation against signer_a's fp.
        let signer_a   = Ed25519Signer::from_bytes("a", &[1u8; 32]).unwrap();
        let signer_b   = Ed25519Signer::from_bytes("b", &[2u8; 32]).unwrap();
        let fp_a = pubkey_fingerprint_short(&format!(
            "ed25519:{}",
            URL_SAFE_NO_PAD.encode(signer_a.public_key_bytes()),
        ));
        let fp_b = pubkey_fingerprint_short(&format!(
            "ed25519:{}",
            URL_SAFE_NO_PAD.encode(signer_b.public_key_bytes()),
        ));
        assert_ne!(fp_a, fp_b);

        let restriction = InviteeRestriction::Pubkey { fingerprint: fp_a.clone() };

        // Join-time check (mirrors what the CLI does on `session join`):
        // accept iff the joining agent's pubkey-fp equals the restriction's fp.
        let accept_for = |fp: &str| matches!(
            &restriction,
            InviteeRestriction::Pubkey { fingerprint } if fingerprint == fp,
        );
        assert!(accept_for(&fp_a),  "matching pubkey must be accepted");
        assert!(!accept_for(&fp_b), "non-matching pubkey must be rejected");
    }

    /// Q1: Cert restriction rejects join without a matching cert.
    #[test]
    fn invitation_cert_restriction_enforced() {
        let restriction = InviteeRestriction::Cert {
            issuer_pubkey:    "ed25519:ISSUER_X".into(),
            allowed_subjects: vec!["org-x".into(), "org-y".into()],
        };
        // Helper: would this (issuer, subject) be accepted?
        let accept = |iss: &str, subj: &str| matches!(
            &restriction,
            InviteeRestriction::Cert { issuer_pubkey, allowed_subjects }
                if issuer_pubkey == iss && allowed_subjects.iter().any(|s| s == subj),
        );

        assert!(accept("ed25519:ISSUER_X",     "org-x"), "matching issuer+subject accepted");
        assert!(!accept("ed25519:ISSUER_OTHER", "org-x"), "wrong issuer rejected");
        assert!(!accept("ed25519:ISSUER_X",     "org-z"), "wrong subject rejected");
    }

    /// Q1: Open restriction accepts any joining agent.
    #[test]
    fn invitation_open_restriction_works() {
        let restriction = InviteeRestriction::Open;
        // Open is unconditionally accepted at restriction-check time.
        // Defense in depth still comes from the journal (single-use)
        // and the expiry.
        let is_open = matches!(restriction, InviteeRestriction::Open);
        assert!(is_open);
    }

    #[test]
    fn invitation_is_expired_returns_true_past_expiry() {
        let now = fixed_now();
        let inv = InvitationStatement::new(
            "ssn_a", URL_SAFE_NO_PAD.encode([5u8; 32]),
            InviteeRestriction::Open, sample_caps(),
            crate::statements::unix_to_rfc3339(now - 1),
            "n",
        );
        assert!(inv.is_expired(now));
    }

    /// The nonce_digest helper matches the journal's nonce digest helper.
    /// Pins that invitations and the Approval Use Journal will agree on
    /// the index key when the CLI routes invitation consumption through
    /// the journal.
    #[test]
    fn invitation_nonce_digest_matches_journal_helper() {
        let inv = sample(InviteeRestriction::Open);
        assert_eq!(
            inv.nonce_digest(),
            crate::statements::nonce_digest(&inv.nonce),
        );
    }

    #[test]
    fn parse_rfc3339_round_trips() {
        let now = fixed_now();
        let s = crate::statements::unix_to_rfc3339(now);
        assert_eq!(parse_rfc3339_to_unix(&s), Some(now));

        // Bad shapes must return None, not panic.
        assert_eq!(parse_rfc3339_to_unix("not a timestamp"), None);
        assert_eq!(parse_rfc3339_to_unix("2026-05-18T00:00:00"), None); // no Z
        assert_eq!(parse_rfc3339_to_unix("2026-13-18T00:00:00Z"), None); // bad month
    }
}
