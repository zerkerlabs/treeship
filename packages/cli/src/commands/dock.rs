use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
use rand::RngCore;

use crate::{config, ctx, printer::Printer};

// ---------------------------------------------------------------------------
// Subcommand dispatch
// ---------------------------------------------------------------------------

pub fn login(
    endpoint: Option<String>,
    config:   Option<&str>,
    printer:  &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx      = ctx::open(config)?;
    let endpoint = endpoint.unwrap_or_else(|| "https://api.treeship.dev".into());

    // 1. GET challenge
    let challenge_url = format!("{}/v1/dock/challenge", endpoint);
    let resp: serde_json::Value = ureq::get(&challenge_url).call()?.into_json()?;

    let device_code = resp["device_code"]
        .as_str()
        .ok_or("missing device_code in challenge response")?
        .to_string();
    let _nonce = resp["nonce"]
        .as_str()
        .ok_or("missing nonce in challenge response")?
        .to_string();

    // 2. Generate fresh Ed25519 dock keypair (separate from ship signing key)
    let mut csprng = rand::thread_rng();
    let dock_signing_key = SigningKey::generate(&mut csprng);
    let dock_verifying_key: VerifyingKey = (&dock_signing_key).into();

    let dock_public_hex  = hex::encode(dock_verifying_key.as_bytes());
    let dock_secret_hex  = hex::encode(dock_signing_key.to_bytes());

    // 3. Print activation instructions
    let formatted_code = format_device_code(&device_code);
    printer.blank();
    // Activation page lives on the website, not the API
    let site_url = if endpoint.contains("localhost") || endpoint.contains("127.0.0.1") {
        endpoint.clone()
    } else {
        "https://www.treeship.dev".to_string()
    };
    printer.info(&format!("visit {}/dock/activate", site_url));
    printer.info(&format!("code: {}", printer.bold(&formatted_code)));
    printer.dim_info("waiting...");
    printer.blank();

    // 4. Poll for authorization -- timeout after 5 minutes
    let poll_url = format!("{}/v1/dock/authorized?device_code={}", endpoint, device_code);
    let start = SystemTime::now();
    let timeout_secs = 300;

    loop {
        let elapsed = start.elapsed().unwrap_or_default().as_secs();
        if elapsed > timeout_secs {
            return Err("dock login timed out after 5 minutes".into());
        }

        std::thread::sleep(std::time::Duration::from_secs(2));

        let poll_resp = ureq::get(&poll_url).call();
        match poll_resp {
            Ok(r) => {
                let status_code = r.status();
                let body: serde_json::Value = r.into_json()?;
                if status_code == 200 {
                    // 200 means approved (by browser or CLI).
                    // Either has dock_id (CLI already called authorize) or just "approved".
                    // In both cases, break and proceed to POST authorize with our keys.
                    break;
                }
                // 202 = pending, keep polling
            }
            Err(ureq::Error::Status(404, _)) => {
                return Err("device code expired or not found".into());
            }
            Err(e) => {
                return Err(format!("polling error: {e}").into());
            }
        }
    };

    // 5. POST authorize with keys
    let ship_public_key = ctx.keys.public_key(&ctx.config.default_key_id)?;
    let ship_public_hex = hex::encode(&ship_public_key);

    let authorize_url = format!("{}/v1/dock/authorize", endpoint);
    let auth_body = serde_json::json!({
        "ship_public_key": ship_public_hex,
        "dock_public_key": dock_public_hex,
        "device_code":     device_code,
    });

    let auth_resp: serde_json::Value = ureq::post(&authorize_url)
        .send_json(&auth_body)?
        .into_json()?;

    let final_dock_id = auth_resp["dock_id"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    // 6. Save to config
    let mut cfg = ctx.config.clone();
    cfg.hub.status          = "docked".into();
    cfg.hub.endpoint        = Some(endpoint.clone());
    cfg.hub.dock_id         = Some(final_dock_id.clone());
    cfg.hub.dock_public_key = Some(dock_public_hex);
    cfg.hub.dock_secret_key = Some(dock_secret_hex);
    config::save(&cfg, &ctx.config_path)?;

    // 7. Print success
    printer.success("docked", &[
        ("dock id",  &final_dock_id),
        ("endpoint", &endpoint),
    ]);
    printer.hint("treeship dock push <artifact-id>");
    printer.blank();

    Ok(())
}

pub fn push(
    id:      &str,
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let hub = &ctx.config.hub;

    if hub.status != "docked" {
        return Err("not docked\n  run: treeship dock login".into());
    }

    let endpoint = hub.endpoint.as_deref().unwrap_or("https://api.treeship.dev");
    let dock_id  = hub.dock_id.as_deref().ok_or("no dock_id in config")?;

    let dock_secret_hex = hub.dock_secret_key.as_deref()
        .ok_or("no dock_secret_key in config -- run: treeship dock login")?;

    // 1. Load artifact from local storage
    let record = ctx.storage.read(id)?;

    // 2. Build DPoP proof JWT
    let artifacts_url = format!("{}/v1/artifacts", endpoint);
    let dpop_jwt = build_dpop_jwt(dock_secret_hex, "POST", &artifacts_url)?;

    // 3. POST to Hub
    let envelope_json = serde_json::to_string(&record.envelope)?;
    let body = serde_json::json!({
        "artifact_id":  record.artifact_id,
        "payload_type": record.payload_type,
        "envelope_json": envelope_json,
        "digest":       record.digest,
        "signed_at":    record.signed_at,
        "parent_id":    record.parent_id,
    });

    let resp: serde_json::Value = ureq::post(&artifacts_url)
        .set("Authorization", &format!("DPoP {}", dock_id))
        .set("DPoP", &dpop_jwt)
        .send_json(&body)?
        .into_json()?;

    let hub_url     = resp["hub_url"].as_str().unwrap_or("");
    let rekor_index = resp["rekor_index"].as_u64();

    // 4. Update local record with hub_url
    if !hub_url.is_empty() {
        ctx.storage.set_hub_url(id, hub_url)?;
    }

    // 5. Print
    let rekor_str = match rekor_index {
        Some(idx) => format!("rekor.sigstore.dev #{}", idx),
        None      => "pending".into(),
    };

    printer.success("pushed", &[
        ("url",   hub_url),
        ("rekor", &rekor_str),
    ]);
    if !hub_url.is_empty() {
        printer.hint(&format!("treeship open {}", hub_url));
    }
    printer.blank();

    Ok(())
}

pub fn pull(
    id:       &str,
    endpoint: Option<&str>,
    config:   Option<&str>,
    printer:  &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    let endpoint = endpoint
        .map(|s| s.to_string())
        .or_else(|| ctx.config.hub.endpoint.clone())
        .unwrap_or_else(|| "https://api.treeship.dev".into());

    // GET artifact (no auth -- public)
    let url = format!("{}/v1/artifacts/{}", endpoint, id);
    let resp: serde_json::Value = ureq::get(&url).call()?.into_json()?;

    // Parse into a Record and store locally
    let envelope_json_str = resp["envelope_json"]
        .as_str()
        .ok_or("missing envelope_json in response")?;

    let envelope: treeship_core::attestation::Envelope =
        serde_json::from_str(envelope_json_str)?;

    let record = treeship_core::storage::Record {
        artifact_id:  resp["artifact_id"].as_str().unwrap_or(id).to_string(),
        digest:       resp["digest"].as_str().unwrap_or("").to_string(),
        payload_type: resp["payload_type"].as_str().unwrap_or("").to_string(),
        key_id:       envelope.signatures.first()
            .map(|s| s.keyid.clone())
            .unwrap_or_default(),
        signed_at:    resp["signed_at"].as_str().unwrap_or("").to_string(),
        parent_id:    resp["parent_id"].as_str().map(|s| s.to_string()),
        envelope,
        hub_url:      resp["hub_url"].as_str().map(|s| s.to_string()),
    };

    ctx.storage.write(&record)?;

    printer.success("pulled", &[
        ("id", id),
    ]);
    printer.hint(&format!("treeship verify {}", id));
    printer.blank();

    Ok(())
}

pub fn status(
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let hub = &ctx.config.hub;

    printer.blank();
    if hub.status == "docked" {
        let endpoint = hub.endpoint.as_deref().unwrap_or("unknown");
        let dock_id  = hub.dock_id.as_deref().unwrap_or("unknown");
        printer.info(&printer.green("● docked"));
        printer.info(&format!("  endpoint:  {}", endpoint));
        printer.info(&format!("  dock id:   {}", dock_id));
    } else {
        printer.info(&printer.dim("○ undocked"));
        printer.hint("treeship dock login");
    }
    printer.blank();

    Ok(())
}

pub fn undock(
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    let mut cfg = ctx.config.clone();
    cfg.hub.status          = "undocked".into();
    cfg.hub.endpoint        = None;
    cfg.hub.dock_id         = None;
    cfg.hub.dock_public_key = None;
    cfg.hub.dock_secret_key = None;
    config::save(&cfg, &ctx.config_path)?;

    printer.success("undocked", &[]);
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// DPoP JWT builder
// ---------------------------------------------------------------------------

fn build_dpop_jwt(
    dock_secret_hex: &str,
    method:          &str,
    url:             &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Decode the dock secret key from hex
    let secret_bytes = hex::decode(dock_secret_hex)?;
    let secret_arr: [u8; 32] = secret_bytes.try_into()
        .map_err(|_| "dock secret key must be 32 bytes")?;
    let signing_key = SigningKey::from_bytes(&secret_arr);

    // Header
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "dpop+jwt",
    });
    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&header)?
    );

    // Payload
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs();

    let mut jti_bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut jti_bytes);
    let jti = hex::encode(jti_bytes);

    let payload = serde_json::json!({
        "iat": now,
        "jti": jti,
        "htm": method,
        "htu": url,
    });
    let payload_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&payload)?
    );

    // Sign: message is "header.payload"
    let message = format!("{}.{}", header_b64, payload_b64);
    let signature = signing_key.sign(message.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{}.{}.{}", header_b64, payload_b64, sig_b64))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format a device code as XXXX-XXXX for display.
fn format_device_code(code: &str) -> String {
    if code.len() >= 8 {
        format!("{}-{}", &code[..4], &code[4..8])
    } else {
        code.to_string()
    }
}
