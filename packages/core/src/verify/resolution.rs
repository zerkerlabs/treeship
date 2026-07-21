//! Card resolution verification: the certificate-chain walk that backs
//! `resolve --hub` and `verify-presentation`.
//!
//! Lifted verbatim from the CLI (`packages/cli/src/commands/resolve.rs`) so the
//! same code path runs in the CLI, the WASM verifier, and every SDK. Pure and
//! time-injected: the caller supplies `now` and the trust roots. No I/O, no
//! system clock.

use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;

use crate::attestation::{Envelope, Verifier};
use crate::capability::is_key_bound;
use crate::statements::ReceiptStatement;
use crate::trust::{decode_ed25519_pubkey, TrustRootKind, TrustRootStore};

/// Build an offline Verifier from the client's pinned trust roots. An agent
/// whose key the client has not pinned simply will not verify, which is the
/// honest answer, not an error.
pub fn verifier_from_trust(trust: &TrustRootStore) -> Verifier {
    let mut map: HashMap<String, VerifyingKey> = HashMap::new();
    for r in trust.roots() {
        if let Ok(vk) = decode_ed25519_pubkey(&r.public_key) {
            map.insert(r.key_id.clone(), vk);
        }
    }
    Verifier::new(map)
}

/// A card verified through the certificate chain rather than a direct leaf
/// pin: which cert artifact vouched, and the subject key it certified.
pub struct ChainVerdict {
    pub cert_id: String,
    pub subject_key: VerifyingKey,
}

/// Walk the certificate chain for a card whose signer key is NOT directly
/// pinned: find a served `agent_cert.v1` that (in this order, fail-closed at
/// every step):
///
///   1. is signed by a key pinned under `CertIssuer` in MY trust roots — the
///      cert envelope signature is verified with the PINNED pubkey, never the
///      wire's, before any payload field is believed;
///   2. binds THIS agent URI to THIS card signer (`agent` + `subject_key_id`
///      match, and the card's own `keyid` claim equals its envelope signer,
///      mirroring `is_key_bound`);
///   3. is within its validity window at `now` (expired certs reject);
///   4. certifies a subject key that actually verifies the card envelope.
///
/// This is the TLS chain: pin the ship (the CA), verify its agents' leaves
/// through the cert, no per-leaf pinning. See registry-topology spec slice 1.
pub fn chain_verify_card(
    card_env: &Envelope,
    card_keyid: &str,
    agent: &str,
    certs: &[(String, Envelope)],
    trust: &TrustRootStore,
    now: &str,
) -> Option<ChainVerdict> {
    // The card must claim the key that signed it (same rule as is_key_bound):
    // a chain-verified signer vouches only for cards that bind themselves to
    // that exact key.
    let card_signer = card_env.signatures.first().map(|s| s.keyid.as_str())?;
    if card_keyid.is_empty() || card_keyid != card_signer {
        return None;
    }

    for (cert_id, cert_env) in certs {
        // 1. Cert envelope must verify against a PINNED CertIssuer root. The
        //    pubkey comes from my trust store, never from the wire.
        let cert_signer = match cert_env.signatures.first() {
            Some(s) => s.keyid.as_str(),
            None => continue,
        };
        let Some(ship_root) = trust
            .roots()
            .iter()
            .find(|r| r.key_id == cert_signer && r.kind == TrustRootKind::CertIssuer)
        else {
            continue;
        };
        let Ok(ship_vk) = decode_ed25519_pubkey(&ship_root.public_key) else {
            continue;
        };
        let mut cert_verifier = Verifier::new(HashMap::new());
        cert_verifier.add_key(cert_signer.to_string(), ship_vk);
        if cert_verifier.verify_any(cert_env).is_err() {
            continue;
        }

        // Only now are the payload fields issuer-attested and believable.
        let Ok(stmt) = cert_env.unmarshal_statement::<ReceiptStatement>() else {
            continue;
        };
        if stmt.kind != "agent_cert.v1" {
            continue;
        }
        let Some(p) = stmt.payload else { continue };

        // 2. Binds this agent to this signer.
        if p.get("agent").and_then(|v| v.as_str()) != Some(agent)
            || p.get("subject_key_id").and_then(|v| v.as_str()) != Some(card_signer)
        {
            continue;
        }

        // 3. Validity window. Both bounds required — a cert missing either
        //    field fails closed. RFC 3339 UTC strings from the same generator
        //    compare lexicographically.
        let (Some(issued), Some(until)) = (
            p.get("issued_at").and_then(|v| v.as_str()),
            p.get("valid_until").and_then(|v| v.as_str()),
        ) else {
            continue;
        };
        if now < issued || now > until {
            continue;
        }

        // 4. The certified subject key must verify the card envelope itself.
        let Some(subject_b64) = p.get("subject_public_key").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(subject_vk) = decode_ed25519_pubkey(&format!("ed25519:{subject_b64}")) else {
            continue;
        };
        let mut card_verifier = Verifier::new(HashMap::new());
        card_verifier.add_key(card_signer.to_string(), subject_vk);
        if card_verifier.verify_any(card_env).is_err() {
            continue;
        }

        return Some(ChainVerdict {
            cert_id: cert_id.clone(),
            subject_key: subject_vk,
        });
    }
    None
}

/// A resolution bundle: exactly the signed bytes a verifier needs to decide
/// whether an agent's current card is trustworthy. No I/O — the caller (the
/// CLI over the network, the WASM verifier / SDKs in a browser) assembles it
/// and supplies `now`.
pub struct ResolutionBundle {
    pub agent: String,
    /// The agent's current `agent_card.v1` envelope.
    pub card: Envelope,
    /// `(artifact_id, agent_cert.v1 envelope)` served for the certificate chain.
    pub certs: Vec<(String, Envelope)>,
    /// Any `agent_card_revocation.v1` envelopes the bundle carries.
    pub revocations: Vec<Envelope>,
}

/// The trust verdict for a resolution bundle: is the card authentic (directly
/// pinned or chain-certified), and is it revoked? Capability grading and
/// provenance are the caller's concern; this is only the trust decision.
#[derive(serde::Serialize)]
pub struct ResolutionVerdict {
    /// The card envelope signature verified against the caller's roots
    /// (directly, or via a chain-certified subject key).
    pub sig_ok: bool,
    /// The card is key-bound: its signer is pinned under `AgentCert`, or a
    /// pinned `CertIssuer` chain-certified it.
    pub key_bound: bool,
    /// If verified through the certificate chain, the cert artifact that vouched.
    pub chain_cert_id: Option<String>,
    /// An authorized, verifying revocation was found.
    pub revoked: bool,
    /// The revocation reason, when revoked.
    pub revocation_reason: Option<String>,
}

/// Decide whether a resolution bundle's card is trustworthy against the
/// caller's pinned trust roots at `now`. Mirrors the CLI `resolve --hub`
/// decision exactly: verify the card signature (direct leaf pin), else walk
/// the certificate chain; then honor an authorized, verifying revocation
/// (self-revocation by the card key, or an issuer pinned under `Revoker`).
pub fn verify_resolution(
    bundle: &ResolutionBundle,
    trust: &TrustRootStore,
    now: &str,
) -> Result<ResolutionVerdict, String> {
    let verifier = verifier_from_trust(trust);
    let mut sig_ok = verifier.verify_any(&bundle.card).is_ok();

    let stmt: ReceiptStatement = bundle
        .card
        .unmarshal_statement()
        .map_err(|e| format!("unparseable card: {e}"))?;
    if stmt.kind != "agent_card.v1" {
        return Err(format!(
            "bundle card is a `{}`, not an agent_card.v1",
            stmt.kind
        ));
    }
    let card = stmt.payload.unwrap_or(serde_json::Value::Null);
    let card_keyid = card.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
    let signer = bundle
        .card
        .signatures
        .first()
        .map(|s| s.keyid.as_str())
        .unwrap_or("");
    let mut key_bound = sig_ok && is_key_bound(card_keyid, signer, trust);

    // Chain walk when the leaf key is not directly pinned. The revocation
    // verifier gains the chain-certified subject key so a self-revocation
    // signed by the agent's own key still counts.
    let mut chain_cert_id: Option<String> = None;
    let mut rev_verifier = verifier;
    if !key_bound {
        if let Some(verdict) = chain_verify_card(
            &bundle.card,
            card_keyid,
            &bundle.agent,
            &bundle.certs,
            trust,
            now,
        ) {
            sig_ok = true;
            key_bound = true;
            rev_verifier.add_key(signer.to_string(), verdict.subject_key);
            chain_cert_id = Some(verdict.cert_id);
        }
    }
    let verifier = rev_verifier;

    // Honor an authorized, verifying revocation.
    let mut revocation_reason: Option<String> = None;
    for rev_env in &bundle.revocations {
        if verifier.verify_any(rev_env).is_err() {
            continue; // unverified revocation -> ignored
        }
        let Ok(rev_stmt) = rev_env.unmarshal_statement::<ReceiptStatement>() else {
            continue;
        };
        if rev_stmt.kind != "agent_card_revocation.v1" {
            continue;
        }
        let rev_signer = rev_env
            .signatures
            .first()
            .map(|s| s.keyid.as_str())
            .unwrap_or("");
        let self_revoke = !card_keyid.is_empty() && rev_signer == card_keyid;
        // Issuer revocation is scoped to the `Revoker` kind.
        let issuer = trust
            .roots()
            .iter()
            .any(|r| r.key_id == rev_signer && r.kind == TrustRootKind::Revoker);
        if self_revoke || issuer {
            revocation_reason = Some(
                rev_stmt
                    .payload
                    .as_ref()
                    .and_then(|p| p.get("reason"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("(no reason given)")
                    .to_string(),
            );
            break;
        }
    }

    Ok(ResolutionVerdict {
        sig_ok,
        key_bound,
        chain_cert_id,
        revoked: revocation_reason.is_some(),
        revocation_reason,
    })
}

#[cfg(test)]
mod chain_tests {
    use super::*;
    use crate::attestation::{sign, Ed25519Signer, Signer};
    use crate::statements::payload_type;
    use crate::trust::TrustRoot;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    const NOW: &str = "2026-07-06T12:00:00Z";

    fn cert_payload(agent: &str, subject: &Ed25519Signer) -> serde_json::Value {
        serde_json::json!({
            "agent": agent,
            "subject_key_id": subject.key_id(),
            "subject_public_key": URL_SAFE_NO_PAD.encode(subject.public_key_bytes()),
            "issuer": "ship://ship_test",
            "issued_at": "2026-01-01T00:00:00Z",
            "valid_until": "2027-01-01T00:00:00Z",
        })
    }

    fn signed_receipt(kind: &str, payload: serde_json::Value, signer: &Ed25519Signer) -> Envelope {
        let mut stmt = ReceiptStatement::new("ship://ship_test", kind);
        stmt.payload = Some(payload);
        sign(&payload_type("receipt"), &stmt, signer)
            .unwrap()
            .envelope
    }

    fn signed_card(agent: &str, keyid_claim: &str, signer: &Ed25519Signer) -> Envelope {
        let mut stmt = ReceiptStatement::new("ship://ship_test", "agent_card.v1");
        stmt.payload = Some(serde_json::json!({ "agent": agent, "keyid": keyid_claim }));
        sign(&payload_type("receipt"), &stmt, signer)
            .unwrap()
            .envelope
    }

    fn ship_pinned(ship: &Ed25519Signer, kind: TrustRootKind) -> TrustRootStore {
        TrustRootStore::with_roots(vec![TrustRoot {
            key_id: ship.key_id().to_string(),
            public_key: format!(
                "ed25519:{}",
                URL_SAFE_NO_PAD.encode(ship.public_key_bytes())
            ),
            kind,
            label: "test ship".into(),
            added_at: String::new(),
        }])
    }

    #[test]
    fn chain_verifies_card_through_pinned_ship_root() {
        let ship = Ed25519Signer::generate("key_ship").unwrap();
        let agent_key = Ed25519Signer::generate("key_agent").unwrap();
        let cert = signed_receipt(
            "agent_cert.v1",
            cert_payload("agent://a", &agent_key),
            &ship,
        );
        let card = signed_card("agent://a", "key_agent", &agent_key);
        let trust = ship_pinned(&ship, TrustRootKind::CertIssuer);

        let verdict = chain_verify_card(
            &card,
            "key_agent",
            "agent://a",
            &[("art_cert".into(), cert)],
            &trust,
            NOW,
        );
        assert!(verdict.is_some(), "valid chain must verify");
        assert_eq!(verdict.unwrap().cert_id, "art_cert");
    }

    #[test]
    fn chain_rejects_unpinned_ship() {
        let ship = Ed25519Signer::generate("key_ship").unwrap();
        let agent_key = Ed25519Signer::generate("key_agent").unwrap();
        let cert = signed_receipt(
            "agent_cert.v1",
            cert_payload("agent://a", &agent_key),
            &ship,
        );
        let card = signed_card("agent://a", "key_agent", &agent_key);

        // Empty roots: a self-signed forgery chain must not verify.
        let empty = TrustRootStore::with_roots(vec![]);
        assert!(chain_verify_card(
            &card,
            "key_agent",
            "agent://a",
            &[("art_cert".into(), cert.clone())],
            &empty,
            NOW
        )
        .is_none());

        // Pinned under the WRONG kind (agent_cert, not ship) also rejects:
        // certifying agents is the Ship role, not a leaf role.
        let wrong_kind = ship_pinned(&ship, TrustRootKind::AgentCert);
        assert!(chain_verify_card(
            &card,
            "key_agent",
            "agent://a",
            &[("art_cert".into(), cert)],
            &wrong_kind,
            NOW
        )
        .is_none());
    }

    #[test]
    fn chain_rejects_expired_and_not_yet_valid_certs() {
        let ship = Ed25519Signer::generate("key_ship").unwrap();
        let agent_key = Ed25519Signer::generate("key_agent").unwrap();
        let card = signed_card("agent://a", "key_agent", &agent_key);
        let trust = ship_pinned(&ship, TrustRootKind::CertIssuer);

        let mut expired = cert_payload("agent://a", &agent_key);
        expired["valid_until"] = serde_json::json!("2026-01-02T00:00:00Z");
        let cert = signed_receipt("agent_cert.v1", expired, &ship);
        assert!(
            chain_verify_card(
                &card,
                "key_agent",
                "agent://a",
                &[("c".into(), cert)],
                &trust,
                NOW
            )
            .is_none(),
            "expired cert must reject"
        );

        let mut future = cert_payload("agent://a", &agent_key);
        future["issued_at"] = serde_json::json!("2026-12-01T00:00:00Z");
        let cert = signed_receipt("agent_cert.v1", future, &ship);
        assert!(
            chain_verify_card(
                &card,
                "key_agent",
                "agent://a",
                &[("c".into(), cert)],
                &trust,
                NOW
            )
            .is_none(),
            "not-yet-valid cert must reject"
        );

        let mut missing = cert_payload("agent://a", &agent_key);
        missing.as_object_mut().unwrap().remove("valid_until");
        let cert = signed_receipt("agent_cert.v1", missing, &ship);
        assert!(
            chain_verify_card(
                &card,
                "key_agent",
                "agent://a",
                &[("c".into(), cert)],
                &trust,
                NOW
            )
            .is_none(),
            "missing window must fail closed"
        );
    }

    #[test]
    fn chain_rejects_subject_and_agent_mismatches() {
        let ship = Ed25519Signer::generate("key_ship").unwrap();
        let agent_key = Ed25519Signer::generate("key_agent").unwrap();
        let other_key = Ed25519Signer::generate("key_other").unwrap();
        let trust = ship_pinned(&ship, TrustRootKind::CertIssuer);

        // Cert certifies a DIFFERENT key than the card's signer.
        let cert = signed_receipt(
            "agent_cert.v1",
            cert_payload("agent://a", &other_key),
            &ship,
        );
        let card = signed_card("agent://a", "key_agent", &agent_key);
        assert!(
            chain_verify_card(
                &card,
                "key_agent",
                "agent://a",
                &[("c".into(), cert)],
                &trust,
                NOW
            )
            .is_none(),
            "subject mismatch must reject"
        );

        // Cert for a DIFFERENT agent URI: key_agent certified for agent://b
        // must not vouch for a card claiming agent://a.
        let cert = signed_receipt(
            "agent_cert.v1",
            cert_payload("agent://b", &agent_key),
            &ship,
        );
        let card = signed_card("agent://a", "key_agent", &agent_key);
        assert!(
            chain_verify_card(
                &card,
                "key_agent",
                "agent://a",
                &[("c".into(), cert)],
                &trust,
                NOW
            )
            .is_none(),
            "agent URI mismatch must reject"
        );

        // Card signed by a key that is NOT the certified subject (stolen
        // cert, attacker's card): the subject-key check must catch it.
        let cert = signed_receipt(
            "agent_cert.v1",
            cert_payload("agent://a", &agent_key),
            &ship,
        );
        let card = signed_card("agent://a", "key_agent", &other_key);
        assert!(
            chain_verify_card(
                &card,
                "key_agent",
                "agent://a",
                &[("c".into(), cert)],
                &trust,
                NOW
            )
            .is_none(),
            "wrong card signer must reject"
        );

        // Card whose keyid claim differs from its envelope signer.
        let cert = signed_receipt(
            "agent_cert.v1",
            cert_payload("agent://a", &agent_key),
            &ship,
        );
        let card = signed_card("agent://a", "key_someone_else", &agent_key);
        assert!(
            chain_verify_card(
                &card,
                "key_someone_else",
                "agent://a",
                &[("c".into(), cert)],
                &trust,
                NOW
            )
            .is_none(),
            "keyid/signer mismatch must reject"
        );
    }

    #[test]
    fn verify_resolution_chains_and_honors_revocation() {
        let ship = Ed25519Signer::generate("key_ship").unwrap();
        let agent_key = Ed25519Signer::generate("key_agent").unwrap();
        let cert = signed_receipt(
            "agent_cert.v1",
            cert_payload("agent://a", &agent_key),
            &ship,
        );
        let card = signed_card("agent://a", "key_agent", &agent_key);
        let trust = ship_pinned(&ship, TrustRootKind::CertIssuer);

        // Chain-verified, not revoked.
        let bundle = ResolutionBundle {
            agent: "agent://a".into(),
            card: card.clone(),
            certs: vec![("art_cert".into(), cert.clone())],
            revocations: vec![],
        };
        let v = verify_resolution(&bundle, &trust, NOW).unwrap();
        assert!(v.key_bound && v.sig_ok, "valid chain must be key-bound");
        assert_eq!(v.chain_cert_id.as_deref(), Some("art_cert"));
        assert!(!v.revoked);

        // A self-revocation signed by the agent's own (chain-certified) key is
        // honored even though that key is not directly pinned.
        let mut rev_stmt = ReceiptStatement::new("ship://ship_test", "agent_card_revocation.v1");
        rev_stmt.payload =
            Some(serde_json::json!({ "card_ref": "card_x", "reason": "key-rotation" }));
        let rev = sign(&payload_type("receipt"), &rev_stmt, &agent_key)
            .unwrap()
            .envelope;
        let bundle = ResolutionBundle {
            agent: "agent://a".into(),
            card,
            certs: vec![("art_cert".into(), cert)],
            revocations: vec![rev],
        };
        let v = verify_resolution(&bundle, &trust, NOW).unwrap();
        assert!(v.revoked, "self-revocation must be honored");
        assert_eq!(v.revocation_reason.as_deref(), Some("key-rotation"));
    }
}
