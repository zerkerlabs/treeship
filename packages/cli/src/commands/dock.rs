use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
use rand::RngCore;

use crate::{config::{self, DockEntry}, ctx, printer::Printer};

// ---------------------------------------------------------------------------
// Result type for push
// ---------------------------------------------------------------------------

/// Result of a successful push to Hub.
pub struct PushResult {
    pub hub_url:     String,
    pub rekor_index: Option<u64>,
}

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------

pub fn login(
    name:     Option<&str>,
    endpoint: Option<&str>,
    config:   Option<&str>,
    printer:  &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx      = ctx::open(config)?;
    let dock_name = name.unwrap_or("default");
    let endpoint  = endpoint.unwrap_or("https://api.treeship.dev").to_string();

    // If dock name already exists with keys, reconnect
    if let Some(existing) = ctx.config.docks.get(dock_name) {
        if existing.dock_secret_key.is_some() {
            let mut cfg = ctx.config.clone();
            cfg.active_dock = Some(dock_name.to_string());
            config::save(&cfg, &ctx.config_path)?;

            printer.success("reconnected", &[
                ("dock", dock_name),
                ("dock id", &existing.dock_id),
            ]);
            printer.hint(&format!(
                "workspace: https://treeship.dev/workspace/{}",
                existing.dock_id
            ));
            printer.blank();
            return Ok(());
        }
    }

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

    // 2. Generate fresh Ed25519 dock keypair
    let mut csprng = rand::thread_rng();
    let dock_signing_key = SigningKey::generate(&mut csprng);
    let dock_verifying_key: VerifyingKey = (&dock_signing_key).into();

    let dock_public_hex = hex::encode(dock_verifying_key.as_bytes());
    let dock_secret_hex = hex::encode(dock_signing_key.to_bytes());

    // 3. Print activation instructions
    let formatted_code = format_device_code(&device_code);
    printer.blank();
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
    let poll_url = format!(
        "{}/v1/dock/authorized?device_code={}",
        endpoint, device_code
    );
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
                let _body: serde_json::Value = r.into_json()?;
                if status_code == 200 {
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
    }

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

    // 6. Build timestamp
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let created_at = format!("{}Z", now);

    // 7. Save to config
    let mut cfg = ctx.config.clone();
    cfg.docks.insert(
        dock_name.to_string(),
        DockEntry {
            dock_id:         final_dock_id.clone(),
            key_id:          ctx.config.default_key_id.clone(),
            endpoint:        endpoint.clone(),
            created_at,
            last_push:       None,
            dock_public_key: Some(dock_public_hex),
            dock_secret_key: Some(dock_secret_hex),
        },
    );
    cfg.active_dock = Some(dock_name.to_string());
    config::save(&cfg, &ctx.config_path)?;

    // 8. Print success
    printer.success("docked", &[
        ("name",     dock_name),
        ("dock id",  &final_dock_id),
        ("endpoint", &endpoint),
    ]);
    printer.hint(&format!(
        "workspace: https://treeship.dev/workspace/{}",
        final_dock_id
    ));
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// logout
// ---------------------------------------------------------------------------

pub fn logout(
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    let dock_name = ctx.config.active_dock.as_deref()
        .unwrap_or("(none)")
        .to_string();

    let mut cfg = ctx.config.clone();
    cfg.active_dock = None;
    config::save(&cfg, &ctx.config_path)?;

    printer.success("logged out", &[("dock", dock_name.as_str())]);
    printer.info("keys preserved");
    printer.hint(&format!("reconnect: treeship dock use {}", dock_name));
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// ls
// ---------------------------------------------------------------------------

pub fn ls(
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    printer.blank();

    if ctx.config.docks.is_empty() {
        printer.info("no docks configured");
        printer.hint("treeship dock login");
        printer.blank();
        return Ok(());
    }

    // Header
    printer.info(&format!(
        "{:<16} {:<24} {:<32} {}",
        "NAME", "DOCK ID", "ENDPOINT", "STATUS"
    ));
    printer.info(&format!("{}", "-".repeat(80)));

    let active = ctx.config.active_dock.as_deref();

    // Sort by name for stable output
    let mut names: Vec<&String> = ctx.config.docks.keys().collect();
    names.sort();

    for name in names {
        let entry = &ctx.config.docks[name];
        let status = if active == Some(name.as_str()) {
            "active"
        } else {
            "inactive"
        };
        let short_id = if entry.dock_id.len() > 20 {
            &entry.dock_id[..20]
        } else {
            &entry.dock_id
        };
        printer.info(&format!(
            "{:<16} {:<24} {:<32} {}",
            name, short_id, entry.endpoint, status
        ));
    }

    printer.blank();
    Ok(())
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

pub fn status(
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    printer.blank();

    if let Some((name, entry)) = ctx.config.active_dock_entry() {
        printer.info(&printer.green("● docked"));
        printer.info(&format!("  name:      {}", name));
        printer.info(&format!("  dock id:   {}", entry.dock_id));
        printer.info(&format!("  key:       {}", entry.key_id));
        printer.info(&format!("  endpoint:  {}", entry.endpoint));
        printer.info(&format!(
            "  workspace: https://treeship.dev/workspace/{}",
            entry.dock_id
        ));
    } else {
        printer.info(&printer.dim("○ not docked"));
        printer.hint("treeship dock login");
    }

    printer.blank();
    Ok(())
}

// ---------------------------------------------------------------------------
// use_dock
// ---------------------------------------------------------------------------

pub fn use_dock(
    name_or_id: &str,
    config:     Option<&str>,
    printer:    &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    // Resolve by name first, then by dock_id
    let resolved_name = if ctx.config.docks.contains_key(name_or_id) {
        name_or_id.to_string()
    } else {
        ctx.config
            .docks
            .iter()
            .find(|(_, v)| v.dock_id == name_or_id)
            .map(|(k, _)| k.clone())
            .ok_or_else(|| format!("dock {:?} not found\n  Run: treeship dock ls", name_or_id))?
    };

    let mut cfg = ctx.config.clone();
    cfg.active_dock = Some(resolved_name.clone());
    config::save(&cfg, &ctx.config_path)?;

    let entry = &ctx.config.docks[&resolved_name];
    printer.success("switched", &[
        ("dock", resolved_name.as_str()),
        ("dock id", &entry.dock_id),
    ]);
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// push
// ---------------------------------------------------------------------------

pub fn push(
    id:      &str,
    dock:    Option<&str>,
    all:     bool,
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    // Resolve "last" to the most recent artifact id
    let resolved_id = resolve_artifact_id(&ctx, id)?;

    if all {
        // Push to every dock in config
        if ctx.config.docks.is_empty() {
            return Err("no docks configured -- run: treeship dock login".into());
        }
        let names: Vec<String> = ctx.config.docks.keys().cloned().collect();
        for name in &names {
            let entry = &ctx.config.docks[name];
            printer.info(&format!("pushing to dock {:?}...", name));
            let result = push_artifact_to_dock(&ctx, &resolved_id, entry)?;
            print_push_result(printer, name, &result);
        }
    } else {
        let (name, entry) = ctx.config.resolve_dock(dock)
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        let result = push_artifact_to_dock(&ctx, &resolved_id, entry)?;
        print_push_result(printer, name, &result);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// pull
// ---------------------------------------------------------------------------

pub fn pull(
    id:      &str,
    dock:    Option<&str>,
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    let (_name, entry) = ctx.config.resolve_dock(dock)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let endpoint = &entry.endpoint;

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

    printer.success("pulled", &[("id", id)]);
    printer.hint(&format!("treeship verify {}", id));
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// workspace
// ---------------------------------------------------------------------------

pub fn workspace(
    dock:    Option<&str>,
    no_open: bool,
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    let (_name, entry) = ctx.config.resolve_dock(dock)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let url = format!("https://treeship.dev/workspace/{}", entry.dock_id);

    printer.blank();
    printer.info(&url);
    printer.blank();

    if !no_open {
        #[cfg(target_os = "macos")]
        { let _ = std::process::Command::new("open").arg(&url).spawn(); }
        #[cfg(target_os = "linux")]
        { let _ = std::process::Command::new("xdg-open").arg(&url).spawn(); }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// rm
// ---------------------------------------------------------------------------

pub fn rm(
    name:    &str,
    force:   bool,
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    if !ctx.config.docks.contains_key(name) {
        return Err(format!("dock {:?} not found\n  Run: treeship dock ls", name).into());
    }

    if !force {
        // Prompt for confirmation
        printer.info(&format!("remove dock {:?}? this deletes the local keys.", name));
        printer.info("pass --force to skip this prompt");

        eprint!("confirm [y/N]: ");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            printer.info("cancelled");
            return Ok(());
        }
    }

    let mut cfg = ctx.config.clone();

    // If removing the active dock, clear active_dock
    if cfg.active_dock.as_deref() == Some(name) {
        cfg.active_dock = None;
    }

    cfg.docks.remove(name);
    config::save(&cfg, &ctx.config_path)?;

    printer.success("removed", &[("dock", name)]);
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// push_artifact  (backward-compatible for wrap --push)
// ---------------------------------------------------------------------------

/// Shared push logic used by `wrap --push`. Uses the active dock from config.
pub fn push_artifact(
    ctx: &crate::ctx::Ctx,
    id:  &str,
) -> Result<PushResult, Box<dyn std::error::Error>> {
    let (_name, entry) = ctx.config.resolve_dock(None)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    push_artifact_to_dock(ctx, id, entry)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Push a single artifact to a specific dock.
fn push_artifact_to_dock(
    ctx:   &crate::ctx::Ctx,
    id:    &str,
    entry: &DockEntry,
) -> Result<PushResult, Box<dyn std::error::Error>> {
    let dock_secret_hex = entry
        .dock_secret_key
        .as_deref()
        .ok_or("no dock_secret_key -- run: treeship dock login")?;

    // 1. Load artifact from local storage
    let record = ctx.storage.read(id)?;

    // 2. Build DPoP proof JWT
    let artifacts_url = format!("{}/v1/artifacts", entry.endpoint);
    let dpop_jwt = build_dpop_jwt(dock_secret_hex, "POST", &artifacts_url)?;

    // 3. POST to Hub
    let envelope_json = serde_json::to_string(&record.envelope)?;
    let body = serde_json::json!({
        "artifact_id":   record.artifact_id,
        "payload_type":  record.payload_type,
        "envelope_json": envelope_json,
        "digest":        record.digest,
        "signed_at":     record.signed_at,
        "parent_id":     record.parent_id,
    });

    let resp: serde_json::Value = ureq::post(&artifacts_url)
        .set("Authorization", &format!("DPoP {}", entry.dock_id))
        .set("DPoP", &dpop_jwt)
        .send_json(&body)?
        .into_json()?;

    let hub_url     = resp["hub_url"].as_str().unwrap_or("").to_string();
    let rekor_index = resp["rekor_index"].as_u64();

    // 4. Update local record with hub_url
    if !hub_url.is_empty() {
        ctx.storage.set_hub_url(id, &hub_url)?;
    }

    Ok(PushResult { hub_url, rekor_index })
}

/// Print push result for a given dock.
fn print_push_result(printer: &Printer, dock_name: &str, result: &PushResult) {
    let rekor_str = match result.rekor_index {
        Some(idx) => format!("rekor.sigstore.dev #{}", idx),
        None      => "pending".into(),
    };

    printer.success("pushed", &[
        ("dock",  dock_name),
        ("url",   &result.hub_url),
        ("rekor", &rekor_str),
    ]);
    if !result.hub_url.is_empty() {
        printer.hint(&format!("treeship open {}", result.hub_url));
    }
    printer.blank();
}

/// Resolve "last" to the actual artifact id from the .last file.
fn resolve_artifact_id(
    ctx: &crate::ctx::Ctx,
    id:  &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if id == "last" {
        let last_path = std::path::Path::new(&ctx.config.storage_dir).join(".last");
        let content = std::fs::read_to_string(&last_path)
            .map_err(|_| "no .last artifact found -- attest or wrap something first")?;
        let resolved = content.trim().to_string();
        if resolved.is_empty() {
            return Err("empty .last file".into());
        }
        Ok(resolved)
    } else {
        Ok(id.to_string())
    }
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
