use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use treeship_core::{
    attestation::Verifier,
    trust::{decode_ed25519_pubkey, TrustRootStore},
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
