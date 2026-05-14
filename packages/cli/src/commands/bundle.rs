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

/// Construct a `Verifier` from every key in the local keystore. Returns
/// `bundle::BundleError::NoTrustRoot` if the keystore is empty so the caller
/// can surface a useful "run `treeship init` first" message instead of a
/// silent accept-everything.
fn build_local_verifier(
    keys: &treeship_core::keys::Store,
) -> Result<Verifier, Box<dyn std::error::Error>> {
    let infos = keys.list()?;
    if infos.is_empty() {
        return Err(Box::new(bundle::BundleError::NoTrustRoot));
    }

    let mut map: HashMap<String, VerifyingKey> = HashMap::new();
    for info in infos {
        let pk_arr: [u8; 32] = info.public_key.as_slice().try_into()
            .map_err(|_| format!(
                "key {} has malformed public key (expected 32 bytes, got {})",
                info.id,
                info.public_key.len(),
            ))?;
        let vk = VerifyingKey::from_bytes(&pk_arr)
            .map_err(|e| format!("key {}: {e}", info.id))?;
        map.insert(info.id, vk);
    }
    Ok(Verifier::new(map))
}
