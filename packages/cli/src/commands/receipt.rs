//! `treeship receipt export` — emit the exact offline-verifiable triple.
//!
//! A Treeship signature is over the DSSE PAE (`DSSEv1 <len> <payloadType>
//! <len> <payload>`), not the payload JSON, and no command previously exported
//! those exact bytes. So a counterparty trying to verify a receipt with a
//! third-party Ed25519 library had to guess the PAE construction and always
//! failed — the signature is valid, but nothing outside Treeship knew what
//! message it covers. This command emits `{message (the PAE), signature,
//! public_key}` in copy-safe base64 so any Ed25519 verifier confirms the
//! receipt with no Treeship code in the loop. That is the whole "portable,
//! offline, don't-trust-us" promise, made runnable in one command.

use crate::{ctx, printer::Printer};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use treeship_core::attestation::pae;

type CmdResult = Result<(), Box<dyn std::error::Error>>;

pub fn export(id: &str, config: Option<&str>, printer: &Printer) -> CmdResult {
    let ctx = ctx::open(config)?;
    let rec = ctx
        .storage
        .read(id)
        .map_err(|e| format!("no artifact {id} in the local store: {e}"))?;
    let env = &rec.envelope;
    let sig = env.signatures.first().ok_or(
        "artifact has no signature — nothing to export (an unsigned envelope should never have been stored)",
    )?;

    // The message is the PAE: the exact bytes that were signed. Reconstruct it
    // from the same payload_type + payload the verifier sees, so what we export
    // is provably what the signature covers.
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(&env.payload)
        .map_err(|e| format!("envelope payload is not valid base64url: {e}"))?;
    let pae_bytes = pae(&env.payload_type, &payload_bytes);

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(&sig.sig)
        .map_err(|e| format!("signature is not valid base64url: {e}"))?;
    // The public key comes from THIS machine's keystore (the signer's own key).
    // Export is for handing a counterparty a receipt you produced; a receipt
    // you received from elsewhere is verified with `treeship verify`.
    let pub_bytes = ctx.keys.public_key(&sig.keyid).map_err(|e| {
        format!(
            "no public key for signer {} in this keystore: {e}\n  receipt export works on receipts THIS machine signed",
            sig.keyid
        )
    })?;

    let message_b64 = STANDARD.encode(&pae_bytes);
    let signature_b64 = STANDARD.encode(&sig_bytes);
    let public_key_b64 = STANDARD.encode(&pub_bytes);

    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "artifact_id": id,
            "algorithm": "ed25519",
            "encoding": "base64",
            "message_b64": message_b64,
            "signature_b64": signature_b64,
            "public_key_b64": public_key_b64,
            "key_id": sig.keyid,
        }));
        return Ok(());
    }

    printer.success(
        "verifiable triple",
        &[
            ("artifact", id),
            ("algorithm", "ed25519 over the DSSE PAE"),
            ("key_id", sig.keyid.as_str()),
        ],
    );
    printer.blank();
    printer.info(&format!("  message     (base64)  {message_b64}"));
    printer.info(&format!("  signature   (base64)  {signature_b64}"));
    printer.info(&format!("  public_key  (base64)  {public_key_b64}"));
    printer.blank();
    printer.hint(
        "any Ed25519 library confirms this offline, no Treeship code needed: base64-decode all three, then verify(public_key, message, signature). Use --format json to pipe the triple to a partner.",
    );
    printer.blank();
    Ok(())
}
