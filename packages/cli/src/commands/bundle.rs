use std::collections::HashMap;
use std::path::PathBuf;

use treeship_core::attestation::Verifier;
use treeship_core::bundle;
use ed25519_dalek::VerifyingKey;

use crate::{ctx, printer::Printer};

pub struct CreateArgs {
    pub artifacts:   Vec<String>,
    pub tag:         Option<String>,
    pub description: Option<String>,
    pub config:      Option<String>,
}

pub fn create(args: CreateArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;
    let signer = ctx.keys.default_signer()?;

    let id_refs: Vec<&str> = args.artifacts.iter().map(|s| s.as_str()).collect();

    let result = bundle::create(
        &id_refs,
        args.tag.as_deref(),
        args.description.as_deref(),
        &ctx.storage,
        signer.as_ref(),
    ).map_err(|e| format!("{e}"))?;

    let mut fields: Vec<(&str, String)> = vec![
        ("id",        result.artifact_id.clone()),
        ("artifacts", format!("{}", result.statement.artifacts.len())),
        ("signed",    result.statement.timestamp.clone()),
    ];
    if let Some(t) = &result.statement.tag {
        fields.push(("tag", t.clone()));
    }

    let field_refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    printer.success("bundle created", &field_refs);
    printer.hint(&format!("treeship bundle export {} --out bundle.treeship", result.artifact_id));
    printer.blank();
    Ok(())
}

pub struct ExportArgs {
    pub bundle_id: String,
    pub out:       String,
    pub config:    Option<String>,
}

pub fn export(args: ExportArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;
    let out_path = PathBuf::from(&args.out);

    bundle::export(&args.bundle_id, &out_path, &ctx.storage)
        .map_err(|e| format!("{e}"))?;

    printer.success("bundle exported", &[
        ("id",   &args.bundle_id),
        ("file", &args.out),
    ]);
    printer.hint(&format!("share {} or run: treeship bundle import {}", args.out, args.out));
    printer.blank();
    Ok(())
}

pub struct ImportArgs {
    pub file:   String,
    pub config: Option<String>,
}

pub fn import(args: ImportArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;
    let path = PathBuf::from(&args.file);

    // Build the trust root from the local keystore. Every public key the
    // user has generated or added becomes a trusted signer for imports.
    // To accept a bundle from a third party, the user must add that
    // party's public key via `treeship keys add` first — which is the
    // intended explicit-trust step, not a silent surprise.
    let verifier = build_local_verifier(&ctx.keys)
        .map_err(|e| format!("build verifier: {e}"))?;

    let bundle_id = bundle::import(&path, &ctx.storage, &verifier)
        .map_err(|e| format!("{e}"))?;

    printer.success("bundle imported", &[
        ("id",   &bundle_id),
        ("from", &args.file),
    ]);
    printer.hint(&format!("treeship verify {}", bundle_id));
    printer.blank();
    Ok(())
}

/// Construct a `Verifier` from every Ed25519 key in the local keystore.
///
/// Returns `bundle::BundleError::NoTrustRoot` if the keystore is empty so the
/// caller can surface a useful "run `treeship init` first" message instead of
/// a silent accept-everything.
///
/// Forward-compat: future keystore entries may carry non-Ed25519 algorithms
/// (e.g. hybrid ML-DSA). We filter by `algorithm == "ed25519"` and skip
/// malformed entries rather than hard-failing the entire import, mirroring the
/// pattern in `verify::build_verifier`. A single bad or unsupported entry
/// must not lock the user out of importing bundles signed by their working
/// keys.
fn build_local_verifier(
    keys: &treeship_core::keys::Store,
) -> Result<Verifier, Box<dyn std::error::Error>> {
    let infos = keys.list()?;
    if infos.is_empty() {
        return Err(Box::new(bundle::BundleError::NoTrustRoot));
    }

    let mut map: HashMap<String, VerifyingKey> = HashMap::new();
    for info in infos {
        if info.algorithm == "ed25519" && info.public_key.len() == 32 {
            let bytes: [u8; 32] = info.public_key.try_into().unwrap();
            if let Ok(vk) = VerifyingKey::from_bytes(&bytes) {
                map.insert(info.id, vk);
            }
        }
    }
    Ok(Verifier::new(map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;
    use treeship_core::bundle as core_bundle;
    use treeship_core::keys::Store as KeyStore;
    use treeship_core::statements::ActionStatement;
    use treeship_core::storage::Store as StorageStore;

    /// build_local_verifier must tolerate a non-ed25519 keystore entry without
    /// failing the entire import. Before the forward-compat fix, an entry
    /// whose `public_key` was not exactly 32 bytes (e.g. a future ML-DSA-65
    /// key) caused `try_into::<[u8; 32]>` to fail and the entire keystore was
    /// rejected — locking the user out of importing bundles signed by their
    /// working ed25519 key. The Verifier built here must still successfully
    /// verify a bundle signed by the working ed25519 key.
    #[test]
    fn build_local_verifier_skips_non_ed25519_entries() {
        // Set up a fresh keystore with one real ed25519 key.
        let keys_dir = tempdir().unwrap();
        let keys = KeyStore::open(keys_dir.path()).unwrap();
        let ed_info = keys.generate(true).unwrap();

        // Drop a fake non-ed25519 keystore entry into the directory. We
        // synthesize a JSON blob matching `EncryptedEntry`'s on-disk schema
        // (the fields the keystore deserializer requires). The `public_key`
        // is intentionally longer than 32 bytes to mimic a future hybrid
        // ML-DSA-65 key — the exact thing that used to break import.
        let fake_id = "key_mldsa_future";
        let fake_entry = serde_json::json!({
            "id":           fake_id,
            "algorithm":    "ml-dsa-65",
            "created_at":   "2026-01-01T00:00:00Z",
            "public_key":   vec![0u8; 1952], // ML-DSA-65 pubkey size, not 32
            "enc_priv_key": vec![0u8; 64],
            "nonce":        vec![0u8; 12],
        });
        fs::write(
            keys_dir.path().join(format!("{fake_id}.json")),
            serde_json::to_vec_pretty(&fake_entry).unwrap(),
        ).unwrap();

        // Splice the fake entry's id into the keystore manifest so list()
        // returns it. Read the existing manifest produced by `generate`, push
        // the new id, write back.
        let manifest_path = keys_dir.path().join("manifest.json");
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["key_ids"].as_array_mut().unwrap()
            .push(serde_json::Value::String(fake_id.into()));
        fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();

        // Sanity: the keystore now lists both keys.
        let listed = keys.list().unwrap();
        assert_eq!(listed.len(), 2, "keystore must list both keys");
        assert!(listed.iter().any(|k| k.algorithm == "ml-dsa-65"));
        assert!(listed.iter().any(|k| k.algorithm == "ed25519"));

        // build_local_verifier must succeed and yield a Verifier with the
        // ed25519 key trusted. Before the fix, the non-32-byte ML-DSA pubkey
        // tripped a hard error here.
        let verifier = build_local_verifier(&keys)
            .expect("build_local_verifier must skip non-ed25519 entries");

        // Build a bundle in a separate storage store, signed by the ed25519
        // key, then export and import it through the constructed verifier.
        let storage_dir = tempdir().unwrap();
        let storage = StorageStore::open(storage_dir.path()).unwrap();
        let signer = keys.signer(&ed_info.id).unwrap();

        // Create a tiny action artifact to bundle.
        let pt_action = treeship_core::statements::payload_type("action");
        let action = ActionStatement::new("agent://test", "tool.call");
        let signed = treeship_core::attestation::sign(&pt_action, &action, signer.as_ref())
            .unwrap();
        storage.write(&treeship_core::storage::Record {
            artifact_id:  signed.artifact_id.clone(),
            digest:       signed.digest.clone(),
            payload_type: pt_action.clone(),
            key_id:       signer.key_id().to_string(),
            signed_at:    "2026-01-01T00:00:00Z".into(),
            parent_id:    None,
            envelope:     signed.envelope,
            hub_url:      None,
        }).unwrap();

        let bundle_res = core_bundle::create(
            &[signed.artifact_id.as_str()],
            Some("forward-compat-test"),
            None,
            &storage,
            signer.as_ref(),
        ).unwrap();

        let export_path = storage_dir.path().join("fwd.treeship");
        core_bundle::export(&bundle_res.artifact_id, &export_path, &storage).unwrap();

        // Import into a fresh storage using our Verifier. This is the
        // regression assertion: the import must succeed even though the
        // keystore contained a non-ed25519 entry.
        let dest_dir = tempdir().unwrap();
        let dest_storage = StorageStore::open(dest_dir.path()).unwrap();
        let imported_id = core_bundle::import(&export_path, &dest_storage, &verifier)
            .expect("import must succeed when only non-ed25519 keys are unsupported");
        assert_eq!(imported_id, bundle_res.artifact_id);
    }
}
