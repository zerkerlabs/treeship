use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use treeship_core::{
    attestation::{Envelope, Verifier},
    statements::{payload_type, ReceiptStatement},
    storage::Store,
    trust::{decode_ed25519_pubkey, TrustRootStore},
    verify::resolution::certified_subject,
};

/// Build the verifier used for local, imported, and pulled artifacts.
///
/// Local public keys cover artifacts created on this machine. Trust roots
/// cover explicitly trusted counterparties. Keeping this in one place prevents
/// bundle import and `treeship verify` from silently using different trust
/// universes.
pub fn from_local_and_trust(
    keys: &treeship_core::keys::Store,
    trust: &TrustRootStore,
) -> Result<Option<Verifier>, Box<dyn std::error::Error>> {
    let mut map: HashMap<String, VerifyingKey> = HashMap::new();
    for info in keys.list()? {
        if info.algorithm == "ed25519" && info.public_key.len() == 32 {
            let bytes: [u8; 32] = info.public_key.try_into().unwrap();
            if let Ok(vk) = VerifyingKey::from_bytes(&bytes) {
                map.insert(info.id, vk);
            }
        }
    }
    for root in trust.roots() {
        if let Ok(vk) = decode_ed25519_pubkey(&root.public_key) {
            map.insert(root.key_id.clone(), vk);
        }
    }
    if map.is_empty() {
        return Ok(None);
    }
    Ok(Some(Verifier::new(map)))
}

/// [`from_local_and_trust`] plus every agent key certified, at `now`, by an
/// `agent_cert.v1` among `certs` that a key pinned here as `cert_issuer`
/// signed and that is inside its validity window.
///
/// This is the certificate chain for artifacts: pin a counterparty's ship
/// key once and verify what its agents sign through the certs it issued,
/// without pinning each agent key. The cert check is
/// `treeship_core::verify::resolution::certified_subject`, the same walk
/// `resolve --hub` and `verify-presentation` use.
///
/// A certified key never replaces a key this machine already holds or has
/// pinned under the same id, and a key id that two certs bind to different
/// public keys is dropped rather than guessed.
pub fn from_local_trust_and_certs<'a>(
    keys: &treeship_core::keys::Store,
    trust: &TrustRootStore,
    certs: impl IntoIterator<Item = &'a Envelope>,
    now: &str,
) -> Result<Option<Verifier>, Box<dyn std::error::Error>> {
    let base = from_local_and_trust(keys, trust)?;

    let mut certified: HashMap<String, Option<VerifyingKey>> = HashMap::new();
    for cert in certs {
        let Some(subject) = certified_subject(cert, trust, now) else {
            continue;
        };
        certified
            .entry(subject.subject_key_id)
            .and_modify(|slot| {
                if slot.as_ref() != Some(&subject.subject_key) {
                    *slot = None; // conflicting bindings: trust neither
                }
            })
            .or_insert(Some(subject.subject_key));
    }

    let mut verifier = match base {
        Some(v) => v,
        None if certified.values().any(Option::is_some) => Verifier::new(HashMap::new()),
        None => return Ok(None),
    };
    for (key_id, vk) in certified {
        let Some(vk) = vk else { continue };
        if verifier.public_key(&key_id).is_none() {
            verifier.add_key(key_id, vk);
        }
    }
    Ok(Some(verifier))
}

/// The `agent_cert.v1` envelopes in local storage (imported or minted here),
/// for [`from_local_trust_and_certs`]. Unreadable records are skipped; the
/// chain check itself is the gate.
pub fn local_agent_certs(storage: &Store) -> Vec<Envelope> {
    storage
        .list_by_type(&payload_type("receipt"))
        .into_iter()
        .filter_map(|entry| storage.read(&entry.id).ok())
        .filter(|rec| {
            rec.envelope
                .unmarshal_statement::<ReceiptStatement>()
                .map(|s| s.kind == "agent_cert.v1")
                .unwrap_or(false)
        })
        .map(|rec| rec.envelope)
        .collect()
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use tempfile::tempdir;
    use treeship_core::{
        statements::ActionStatement,
        trust::{TrustRoot, TrustRootKind},
    };

    use super::*;

    #[test]
    fn pinned_counterparty_key_verifies_without_local_private_key() {
        let signer_dir = tempdir().unwrap();
        let signer_keys = treeship_core::keys::Store::open(signer_dir.path()).unwrap();
        let signer_info = signer_keys.generate(true).unwrap();
        let signer = signer_keys.signer(&signer_info.id).unwrap();

        let mut trust = TrustRootStore::empty();
        trust.add(TrustRoot {
            key_id: signer_info.id.clone(),
            public_key: format!(
                "ed25519:{}",
                URL_SAFE_NO_PAD.encode(&signer_info.public_key)
            ),
            kind: TrustRootKind::AgentCert,
            agent: None,
            label: "counterparty".into(),
            added_at: "2026-01-01T00:00:00Z".into(),
        });

        let importer_dir = tempdir().unwrap();
        let importer_keys = treeship_core::keys::Store::open(importer_dir.path()).unwrap();
        let verifier = from_local_and_trust(&importer_keys, &trust)
            .unwrap()
            .expect("trust root should produce a verifier");

        let statement = ActionStatement::new("agent://counterparty", "tool.call");
        let signed = treeship_core::attestation::sign(
            &treeship_core::statements::payload_type("action"),
            &statement,
            signer.as_ref(),
        )
        .unwrap();
        assert!(verifier.verify_any(&signed.envelope).is_ok());
    }
}
