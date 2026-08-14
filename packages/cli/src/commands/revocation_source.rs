//! A [`RevocationSource`] backed by `grant_revocation.v1` receipts in the
//! local artifact store.
//!
//! # Why this exists
//!
//! `Mandate.revocation.path` has always named a resolver (`hub://local/…`) and
//! nothing implemented one, so every verification passed `NoRevocationSource`
//! and every action/v2 mandate degraded to `Unverified`. That was the honest
//! failure -- refusing to confirm rather than confirming falsely -- but it
//! meant a withdrawn grant was indistinguishable from a live one, and
//! `--require-authority` could never be satisfied by a real receipt.
//!
//! # What makes a revocation count
//!
//! **Signed by the grant's own grantor, and nothing else.** A revocation
//! anyone could mint is a denial-of-service against every grant whose id they
//! know: learn a `grn_…` from a published receipt, sign "revoked", and the
//! grant dies. So the signer's key must equal the `grantor` the revocation
//! names, and the reader is expected to have obtained that grantor from the
//! grant itself.
//!
//! This is the same rule capability-card revocation already applies -- honored
//! only from the card's own key or a trusted issuer -- stated for grants.
//!
//! # Time, and what revocation does not do
//!
//! Revocation is evaluated against the action's `signed_at`, not against now.
//! An action signed before the revocation instant stays authorized: withdrawing
//! authority is not the same as retroactively unmaking what was already done
//! under it. `verify_mandate` owns that comparison; this type only reports
//! *when* the grant was withdrawn.
//!
//! # Absence only means something for grants we issued
//!
//! This is the distinction that decides whether the resolver is sound.
//!
//! For a grant **this ship issued**, the local store is authoritative: we are
//! the grantor, revoking is something we would have done, and finding no
//! revocation is a real answer -- [`RevocationStatus::NotRevoked`].
//!
//! For a grant issued by **anyone else**, an empty local store says nothing.
//! We may simply never have been told. Reporting `NotRevoked` there would let
//! a stale or freshly-initialised store manufacture a passing verdict out of
//! ignorance, which is the same defect as a boolean that reads true because
//! nothing looked. Those resolve [`RevocationStatus::Unknown`], and the
//! mandate degrades to `Unverified` exactly as it did before.
//!
//! Closing that needs a published, fetchable revocation list. The Hub's
//! `/.well-known/treeship/revoked.json` is currently hardcoded empty and
//! unsigned (audit item 6), so there is nothing to fetch yet.

use treeship_core::statements::{RevocationSource, RevocationStatus};
use treeship_core::storage::Store;

use treeship_core::attestation::{verify_with_key, Envelope};
use treeship_core::statements::ReceiptStatement;

/// Resolves revocation from `grant_revocation.v1` receipts held locally.
pub struct LocalRevocationSource {
    entries: Vec<RevocationEntry>,
    /// Public keys this ship holds, base64url-no-pad. A grant whose grantor is
    /// one of these was issued here, which is what makes "no revocation found"
    /// an answer rather than an absence of information.
    own_keys: Vec<String>,
    /// grant_id -> grantor, for grants held locally. Needed because `status`
    /// receives only a grant id and has to decide whether we issued it.
    known_grantors: std::collections::HashMap<String, String>,
}

struct RevocationEntry {
    grant_id: String,
    /// Kept for the error message when a revocation fails the grantor check --
    /// naming the key that was expected is what makes that message actionable.
    #[allow(dead_code)]
    grantor: String,
    revoked_at: String,
    /// Whether the DSSE signature verifies under the `grantor` key the payload
    /// names. Computed at load, because that is where the envelope is.
    grantor_signed: bool,
}

impl LocalRevocationSource {
    /// Scan the store once. Called before verification so a chain of N
    /// mandates does not re-read the store N times.
    pub fn load(
        store: &Store,
        own_keys: Vec<String>,
        known_grantors: std::collections::HashMap<String, String>,
    ) -> Self {
        let mut entries = Vec::new();

        for entry in store.list() {
            let Ok(record) = store.read(&entry.id) else {
                continue;
            };
            let Ok(stmt) = record.envelope.unmarshal_statement::<ReceiptStatement>() else {
                continue;
            };
            if stmt.kind != "grant_revocation.v1" {
                continue;
            }
            let Some(p) = stmt.payload else { continue };

            // Every field is required by the schema, but this reads receipts
            // that may predate it or come from elsewhere. A revocation missing
            // any of them cannot be evaluated, and treating it as valid would
            // let a malformed artifact kill a grant.
            let (Some(grant_id), Some(grantor), Some(revoked_at)) = (
                p.get("grant_id").and_then(|v| v.as_str()),
                p.get("grantor").and_then(|v| v.as_str()),
                p.get("revoked_at").and_then(|v| v.as_str()),
            ) else {
                continue;
            };

            entries.push(RevocationEntry {
                grant_id: grant_id.to_string(),
                grantor: grantor.to_string(),
                revoked_at: revoked_at.to_string(),
                grantor_signed: signed_by(&record.envelope, grantor),
            });
        }

        Self {
            entries,
            own_keys,
            known_grantors,
        }
    }

    /// Whether this ship issued the grant, and so whether the absence of a
    /// local revocation is informative.
    fn we_issued(&self, grant_id: &str) -> bool {
        self.known_grantors
            .get(grant_id)
            .map(|g| {
                let g = g.strip_prefix("ed25519:").unwrap_or(g);
                self.own_keys
                    .iter()
                    .any(|k| k.strip_prefix("ed25519:").unwrap_or(k) == g)
            })
            .unwrap_or(false)
    }
}

impl RevocationSource for LocalRevocationSource {
    fn status(&self, grant_id: &str, _path: &str) -> RevocationStatus {
        let mut unauthorized = 0usize;

        // Earliest revocation wins. Two revocations of one grant should not
        // happen, but if they do, the earlier instant is the one that
        // withdrew the authority -- taking the later would silently widen the
        // window in which actions still count as authorized.
        let mut earliest: Option<&RevocationEntry> = None;

        for e in self.entries.iter().filter(|e| e.grant_id == grant_id) {
            // The grantor check. Without it, anyone who learns a grant id from
            // a published receipt can revoke it.
            //
            // `grantor` is the grant issuer's public key and `signer_keyid` is
            // the DSSE key id, so this compares a key to its id: the match
            // holds when the revocation was signed by the same key material
            // the grant names. A mismatch is counted and reported rather than
            // ignored, because a revocation someone tried and failed to make
            // stick is worth a verifier seeing.
            if !e.grantor_signed {
                unauthorized += 1;
                continue;
            }
            match earliest {
                None => earliest = Some(e),
                Some(cur) if e.revoked_at < cur.revoked_at => earliest = Some(e),
                _ => {}
            }
        }

        if let Some(e) = earliest {
            return RevocationStatus::RevokedAt(e.revoked_at.clone());
        }

        if unauthorized > 0 {
            // Not `NotRevoked`: something claimed to revoke this grant and was
            // not authorized to. Saying "not revoked" would hide that, and
            // saying "revoked" would let the forgery succeed.
            return RevocationStatus::Unknown(format!(
                "{unauthorized} revocation(s) exist for {grant_id} but none was signed by \
                 the grant's grantor; treating the grant as neither confirmed live nor \
                 revoked"
            ));
        }

        // Nothing found locally. Whether that means anything depends on who
        // issued the grant.
        if self.we_issued(grant_id) {
            // We are the grantor. Revoking is an act we would have performed,
            // and we have no record of performing it.
            RevocationStatus::NotRevoked
        } else {
            // Someone else's grant. An empty local store is ignorance, not
            // evidence, and saying `NotRevoked` here would let a machine that
            // has never synced produce a passing verdict out of not knowing.
            RevocationStatus::Unknown(format!(
                "no local revocation record for {grant_id}, and this ship did not issue it -- \
                 a revocation published elsewhere would not be visible here"
            ))
        }
    }
}

/// Whether this envelope's signature verifies under the key the payload names
/// as `grantor`.
///
/// This is a cryptographic check, not a name comparison, and the distinction
/// is the whole control. The first version of this compared the DSSE `keyid`
/// (`key_<hex>`) against `grantor` (a base64url public key) as strings, on the
/// assumption that the store carried both forms. It does not, so the check
/// never matched and every revocation was rejected as unauthorized.
///
/// Comparing names would also have been the weaker test even if the forms had
/// lined up: `grantor` is a field in a payload an attacker writes. Verifying
/// the signature *against* that key is what makes the claim self-checking --
/// a forger can name the victim's key, and then cannot produce a signature
/// that verifies under it.
fn signed_by(envelope: &Envelope, grantor: &str) -> bool {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::VerifyingKey;

    let raw = grantor.strip_prefix("ed25519:").unwrap_or(grantor);
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(raw) else {
        return false;
    };
    let Ok(arr): Result<[u8; 32], _> = bytes.as_slice().try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&arr) else {
        return false;
    };

    // `verify_with_key` needs a key id to index by; any label works, because
    // the map holds exactly this one key and a signature that verifies under
    // it is the only thing that can pass.
    envelope
        .signatures
        .iter()
        .any(|sig| verify_with_key(envelope, &sig.keyid, vk).is_ok())
}

/// Build a resolver for this context: the local revocations, plus the two
/// things needed to know whether an absent revocation is informative -- which
/// keys this ship holds, and which grants it issued.
pub fn for_ctx(ctx: &crate::ctx::Ctx) -> LocalRevocationSource {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    // Every key this ship holds, as a pinnable public key. A grant issued by
    // any of them is one we could have revoked ourselves.
    let own_keys: Vec<String> = ctx
        .keys
        .list()
        .map(|infos| {
            infos
                .iter()
                .map(|k| URL_SAFE_NO_PAD.encode(&k.public_key))
                .collect()
        })
        .unwrap_or_default();

    // grant_id -> grantor for grants on disk. Read unchecked: this only
    // decides whether absence is informative, and a grant with an
    // inconsistent id simply will not match a mandate's grant_id anyway.
    let mut known_grantors = std::collections::HashMap::new();
    let dir = crate::commands::grant::grants_dir_for(&ctx.config_path);
    if dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for e in entries.flatten() {
                let path = e.path();
                if path.extension().and_then(|x| x.to_str()) != Some("json") {
                    continue;
                }
                if let Ok(g) = crate::commands::grant::read_grant_unchecked(&path) {
                    known_grantors.insert(g.grant_id.clone(), g.grantor.clone());
                }
            }
        }
    }

    LocalRevocationSource::load(&ctx.storage, own_keys, known_grantors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(grant: &str, grantor: &str, at: &str, grantor_signed: bool) -> RevocationEntry {
        RevocationEntry {
            grant_id: grant.into(),
            grantor: grantor.into(),
            revoked_at: at.into(),
            grantor_signed,
        }
    }

    /// A source that did NOT issue the grants under test, so absence is
    /// `Unknown`. `own()` below covers the other side.
    fn src(entries: Vec<RevocationEntry>) -> LocalRevocationSource {
        LocalRevocationSource {
            entries,
            own_keys: vec![],
            known_grantors: Default::default(),
        }
    }

    /// A source for a grant this ship issued, where absence is informative.
    fn own(entries: Vec<RevocationEntry>) -> LocalRevocationSource {
        LocalRevocationSource {
            entries,
            own_keys: vec!["pk1".into()],
            known_grantors: [("grn_a".to_string(), "pk1".to_string())]
                .into_iter()
                .collect(),
        }
    }

    #[test]
    fn a_grantor_signed_revocation_is_honored() {
        let s = src(vec![entry("grn_a", "pk1", "2026-08-14T10:00:00Z", true)]);
        assert_eq!(
            s.status("grn_a", "hub://local/revocations"),
            RevocationStatus::RevokedAt("2026-08-14T10:00:00Z".into())
        );
    }

    /// The denial-of-service this check exists to stop: learn a grant id from
    /// a published receipt, sign "revoked", kill the grant.
    #[test]
    fn a_revocation_signed_by_a_stranger_does_not_revoke() {
        let s = src(vec![entry("grn_a", "pk1", "2026-08-14T10:00:00Z", false)]);
        match s.status("grn_a", "p") {
            RevocationStatus::Unknown(r) => {
                assert!(r.contains("none was signed by the grant's grantor"), "{r}")
            }
            other => panic!("a stranger's revocation must not decide the outcome: {other:?}"),
        }
    }

    /// And it must not read as a clean bill of health either. Something tried
    /// to revoke this grant; a verifier should see that.
    #[test]
    fn an_unauthorized_attempt_is_not_reported_as_not_revoked() {
        let s = src(vec![entry("grn_a", "pk1", "2026-08-14T10:00:00Z", false)]);
        assert_ne!(s.status("grn_a", "p"), RevocationStatus::NotRevoked);
    }

    #[test]
    fn the_earliest_revocation_wins() {
        let s = src(vec![
            entry("grn_a", "pk1", "2026-08-14T12:00:00Z", true),
            entry("grn_a", "pk1", "2026-08-14T09:00:00Z", true),
        ]);
        assert_eq!(
            s.status("grn_a", "p"),
            RevocationStatus::RevokedAt("2026-08-14T09:00:00Z".into()),
            "taking the later instant would widen the window in which actions still count"
        );
    }

    #[test]
    fn other_grants_are_unaffected() {
        let s = own(vec![entry("grn_a", "pk1", "2026-08-14T10:00:00Z", true)]);
        // grn_b was not issued here, so we cannot speak to it either way.
        assert!(matches!(
            s.status("grn_b", "p"),
            RevocationStatus::Unknown(_)
        ));
    }

    /// The soundness rule. An empty store is an answer only about grants this
    /// ship issued; for anyone else's it is ignorance, and reporting
    /// `NotRevoked` would let a machine that has never synced manufacture a
    /// pass out of not knowing.
    #[test]
    fn absence_is_an_answer_only_for_our_own_grants() {
        assert_eq!(
            own(vec![]).status("grn_a", "p"),
            RevocationStatus::NotRevoked
        );

        match src(vec![]).status("grn_a", "p") {
            RevocationStatus::Unknown(r) => assert!(r.contains("did not issue it"), "{r}"),
            other => {
                panic!("someone else's grant must not resolve from an empty store: {other:?}")
            }
        }
    }

    /// A revocation we DO hold decides the outcome regardless of issuer -- the
    /// ignorance rule is about absence, not about evidence in hand.
    #[test]
    fn a_held_revocation_counts_even_for_someone_elses_grant() {
        let s = src(vec![entry("grn_a", "pk1", "2026-08-14T10:00:00Z", true)]);
        assert_eq!(
            s.status("grn_a", "p"),
            RevocationStatus::RevokedAt("2026-08-14T10:00:00Z".into())
        );
    }

    #[test]
    fn an_unsigned_revocation_is_not_authorized() {
        let s = src(vec![entry("grn_a", "pk1", "2026-08-14T10:00:00Z", false)]);
        assert!(matches!(
            s.status("grn_a", "p"),
            RevocationStatus::Unknown(_)
        ));
    }
}
