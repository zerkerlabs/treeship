use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{SigningKey, Signer, VerifyingKey};
use rand::RngCore;

use crate::{config::{self, HubConnection}, ctx, printer::Printer};

// ---------------------------------------------------------------------------
// Result type for push
// ---------------------------------------------------------------------------

/// Result of a successful push to Hub.
pub struct PushResult {
    pub hub_url:     String,
    pub rekor_index: Option<u64>,
}

// ---------------------------------------------------------------------------
// attach
// ---------------------------------------------------------------------------

pub fn attach(
    name:     Option<&str>,
    endpoint: Option<&str>,
    config:   Option<&str>,
    printer:  &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx      = ctx::open(config)?;
    let hub_name = name.unwrap_or("default");
    let endpoint  = endpoint.unwrap_or("https://api.treeship.dev").to_string();

    // If a connection with stored keys exists, PROBE the hub before claiming
    // "reconnected". Cached keys can outlive the server's dock registration
    // (e.g. the hub's database was reset): the old shape trusted them
    // blindly, reported success, and the user's next push 401'd — after the
    // CLI had already told them they were connected. One authenticated,
    // read-only request against the same DPoP path every push uses is the
    // difference between reporting a fact and reporting a hope. On probe
    // failure we fall through to the full device flow rather than lying.
    if let Some(existing) = ctx.config.hub_connections.get(hub_name) {
        if let Some(secret_hex) = existing
            .hub_secret_key
            .as_deref()
            .and_then(|stored| resolve_hub_secret_hex(&ctx.keys, &existing.hub_id, stored).ok())
        {
            let probe_endpoint = existing.endpoint.trim_end_matches('/');
            let probe_url = format!("{probe_endpoint}/v1/ship/agents");
            let probe_ok = build_dpop_jwt(&secret_hex, "GET", &probe_url)
                .ok()
                .and_then(|jwt| {
                    ureq::get(&probe_url)
                        .set("Authorization", &format!("DPoP {}", existing.hub_id))
                        .set("DPoP", &jwt)
                        .call()
                        .ok()
                })
                .is_some();

            if probe_ok {
                let mut cfg = ctx.config.clone();
                cfg.active_hub = Some(hub_name.to_string());
                config::save(&cfg, &ctx.config_path)?;

                printer.success("reconnected", &[
                    ("hub", hub_name),
                    ("hub id", &existing.hub_id),
                    ("probe", "authenticated OK"),
                ]);
                printer.hint("view your workspace: treeship hub open");
                printer.blank();
                return Ok(());
            }
            printer.warn(
                "stored hub keys no longer authenticate (the hub may have been reset) — starting a fresh device flow",
                &[("hub", hub_name), ("hub id", &existing.hub_id)],
            );
            // Fall through to the device flow below; on success it
            // overwrites this connection with freshly-registered keys.
        }
    }

    // 1. GET challenge
    let challenge_url = format!("{}/v1/dock/challenge", endpoint);
    let resp: serde_json::Value = ureq::get(&challenge_url).call()?.into_json()?;

    let device_code = resp["device_code"]
        .as_str()
        .ok_or("missing device_code in challenge response")?
        .to_string();
    let nonce = resp["nonce"]
        .as_str()
        .ok_or("missing nonce in challenge response")?
        .to_string();

    // 2. Generate fresh Ed25519 hub keypair
    let mut csprng = rand::thread_rng();
    let hub_signing_key = SigningKey::generate(&mut csprng);
    let hub_verifying_key: VerifyingKey = (&hub_signing_key).into();

    let hub_public_hex = hex::encode(hub_verifying_key.as_bytes());

    // 3. Print activation instructions
    let formatted_code = format_device_code(&device_code);
    printer.blank();
    let site_url = if endpoint.contains("localhost") || endpoint.contains("127.0.0.1") {
        endpoint.clone()
    } else {
        "https://www.treeship.dev".to_string()
    };
    printer.info(&format!("visit {}/hub/activate", site_url));
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
            return Err("hub attach timed out after 5 minutes\n\n  Fix: try again with treeship hub attach".into());
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
            Err(ureq::Error::Status(code, _)) => {
                // The Hub reports distinct terminal states so we can tell the
                // user exactly what happened instead of a catch-all message.
                //   404 unknown code   410 expired   409 already used
                let reason = match code {
                    404 => "device code not found",
                    410 => "device code expired",
                    409 => "device code already used",
                    _   => "hub activation failed",
                };
                return Err(format!(
                    "{reason}\n\n  Fix: run treeship hub attach again to get a new code"
                ).into());
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
        "dock_public_key": hub_public_hex,
        "device_code":     device_code,
        "nonce":           nonce,
    });

    let auth_resp: serde_json::Value = ureq::post(&authorize_url)
        .send_json(&auth_body)?
        .into_json()?;

    let final_hub_id = auth_resp["dock_id"]
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
    cfg.hub_connections.insert(
        hub_name.to_string(),
        HubConnection {
            hub_id:         final_hub_id.clone(),
            key_id:          ctx.config.default_key_id.clone(),
            endpoint:        endpoint.clone(),
            created_at,
            last_push:       None,
            hub_public_key: Some(hub_public_hex),
            // AUD-02: seal the DPoP private key under the machine key (same
            // protection as ship keys), bound to this hub id. Never write the
            // raw key to config.json — a passive read of that file must not
            // yield a working signing key.
            hub_secret_key: Some(
                ctx.keys
                    .seal_secret(&final_hub_id, &hub_signing_key.to_bytes())
                    .map_err(|e| format!("failed to seal hub key: {e}"))?,
            ),
        },
    );
    cfg.active_hub = Some(hub_name.to_string());
    config::save(&cfg, &ctx.config_path)?;

    // 8. Print success
    printer.success("attached", &[
        ("name",     hub_name),
        ("hub id",   &final_hub_id),
        ("endpoint", &endpoint),
    ]);
    printer.blank();
    print_attach_next_steps(printer);
    printer.hint("view your workspace: treeship hub open");
    printer.blank();

    Ok(())
}

/// Print concrete next steps after a successful attach.
///
/// The commands are provider-neutral templates: signing an external system
/// receipt, pushing it, and verifying it anywhere. The example uses
/// `system://zmem` with a `memory.proof` kind purely to illustrate one
/// customer's memory-proof workflow -- ZMem is an example, not built-in
/// behavior, and `--system`/`--kind` accept any value.
fn print_attach_next_steps(printer: &Printer) {
    printer.info("next steps:");
    printer.info("  treeship status                                check ship + hub state");
    printer.info("  treeship attest receipt --system system://<your-system> \\");
    printer.info("    --kind <kind> --payload-file <file>          sign an external receipt");
    printer.info("  treeship hub push <artifact-id>                share a signed artifact");
    printer.info("  treeship verify <artifact-id>                  verify it anywhere");
    printer.blank();
    printer.dim_info("  example (memory proof):");
    printer.dim_info("    treeship attest receipt --system system://zmem --kind memory.proof \\");
    printer.dim_info("      --payload-file proof.json");
    printer.blank();
}

// ---------------------------------------------------------------------------
// detach
// ---------------------------------------------------------------------------

pub fn detach(
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    let hub_name = ctx.config.active_hub.as_deref()
        .unwrap_or("(none)")
        .to_string();

    let mut cfg = ctx.config.clone();
    cfg.active_hub = None;
    config::save(&cfg, &ctx.config_path)?;

    printer.success("detached", &[("hub", hub_name.as_str())]);
    printer.info("keys preserved");
    printer.hint(&format!("reconnect: treeship hub use {}", hub_name));
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

    // JSON mode: emit a structured list. The pretty path uses
    // `printer.info(...)` which is a no-op in JSON mode (see
    // printer.rs), so without this branch `treeship hub ls --format
    // json` emits zero bytes -- breaking the SDK and any automation
    // that wants to enumerate configured hubs.
    //
    // Shape:
    //   {
    //     "items": [
    //       {"name": "...", "hub_id": "...", "endpoint": "...",
    //        "key_id": "...", "active": true|false},
    //       ...
    //     ],
    //     "active": "<name>" | null,
    //     "count":  <items.len()>
    //   }
    //
    // Each entry includes both `active` (per-row boolean for filtering)
    // and `key_id` so callers don't need to round-trip through `hub
    // status` to know which connection is selected or what key it uses.
    if printer.format == crate::printer::Format::Json {
        let active = ctx.config.active_hub.as_deref();
        let mut names: Vec<&String> = ctx.config.hub_connections.keys().collect();
        names.sort();
        let items: Vec<serde_json::Value> = names
            .iter()
            .map(|name| {
                let entry = &ctx.config.hub_connections[name.as_str()];
                serde_json::json!({
                    "name":     name,
                    "hub_id":   entry.hub_id,
                    "key_id":   entry.key_id,
                    "endpoint": entry.endpoint,
                    "active":   active == Some(name.as_str()),
                })
            })
            .collect();
        let body = serde_json::json!({
            "items":  items,
            "active": active,
            "count":  items.len(),
        });
        printer.json(&body);
        return Ok(());
    }

    printer.blank();

    if ctx.config.hub_connections.is_empty() {
        printer.info("no hub connections configured");
        printer.hint("treeship hub attach");
        printer.blank();
        return Ok(());
    }

    // Header
    printer.info(&format!(
        "{:<16} {:<24} {:<32} {}",
        "NAME", "HUB ID", "ENDPOINT", "STATUS"
    ));
    printer.info(&format!("{}", "-".repeat(80)));

    let active = ctx.config.active_hub.as_deref();

    // Sort by name for stable output
    let mut names: Vec<&String> = ctx.config.hub_connections.keys().collect();
    names.sort();

    for name in names {
        let entry = &ctx.config.hub_connections[name];
        let status = if active == Some(name.as_str()) {
            "active"
        } else {
            "inactive"
        };
        let short_id = if entry.hub_id.len() > 20 {
            &entry.hub_id[..20]
        } else {
            &entry.hub_id
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

    // JSON mode: emit a structured envelope that the SDK can parse.
    //
    // The SDK's `hub.status()` in @treeship/sdk reads `status`, `endpoint`,
    // and `hub_id` (or legacy `dock_id`) off the top level. We surface a
    // boolean `connected` too so future SDK callers can branch on a single
    // key without re-deriving it from the string `status` field.
    //
    // Shape (no hub configured):
    //   { "status": "detached", "connected": false }
    // Shape (attached):
    //   { "status": "attached", "connected": true,
    //     "name": "...", "hub_id": "...", "key_id": "...",
    //     "endpoint": "..." }
    //
    // Prior to this fix, `cmd_status` only emitted via `printer.info(...)`,
    // which is a no-op in JSON mode (see printer.rs). That caused the SDK
    // to receive empty stdout, throw a JSON.parse error, and silently
    // return `{ connected: false }` for *every* invocation -- the
    // hub.status() round-trip test passed for the wrong reason.
    if printer.format == crate::printer::Format::Json {
        let body = if let Some((name, entry)) = ctx.config.active_hub_connection() {
            serde_json::json!({
                "status":    "attached",
                "connected": true,
                "name":      name,
                "hub_id":    entry.hub_id,
                "key_id":    entry.key_id,
                "endpoint":  entry.endpoint,
            })
        } else {
            serde_json::json!({
                "status":    "detached",
                "connected": false,
            })
        };
        printer.json(&body);
        return Ok(());
    }

    printer.blank();

    if let Some((name, entry)) = ctx.config.active_hub_connection() {
        printer.info(&printer.green("● attached"));
        printer.info(&format!("  name:      {}", name));
        printer.info(&format!("  hub id:    {}", entry.hub_id));
        printer.info(&format!("  key:       {}", entry.key_id));
        printer.info(&format!("  endpoint:  {}", entry.endpoint));
        printer.info("  workspace: treeship hub open");
    } else {
        printer.info(&printer.dim("○ not attached"));
        printer.hint("treeship hub attach");
    }

    printer.blank();
    Ok(())
}

// ---------------------------------------------------------------------------
// use_hub
// ---------------------------------------------------------------------------

pub fn use_hub(
    name_or_id: &str,
    config:     Option<&str>,
    printer:    &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    // Resolve by name first, then by hub_id
    let resolved_name = if ctx.config.hub_connections.contains_key(name_or_id) {
        name_or_id.to_string()
    } else {
        ctx.config
            .hub_connections
            .iter()
            .find(|(_, v)| v.hub_id == name_or_id)
            .map(|(k, _)| k.clone())
            .ok_or_else(|| format!("hub connection {:?} not found\n  Run: treeship hub ls", name_or_id))?
    };

    let mut cfg = ctx.config.clone();
    cfg.active_hub = Some(resolved_name.clone());
    config::save(&cfg, &ctx.config_path)?;

    let entry = &ctx.config.hub_connections[&resolved_name];
    printer.success("switched", &[
        ("hub", resolved_name.as_str()),
        ("hub id", &entry.hub_id),
    ]);
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// push
// ---------------------------------------------------------------------------

pub fn push(
    id:      &str,
    hub:     Option<&str>,
    all:     bool,
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    // Resolve "last" to the most recent artifact id
    let resolved_id = resolve_artifact_id(&ctx, id)?;

    if all {
        // Push to every hub connection in config
        if ctx.config.hub_connections.is_empty() {
            return Err("no hub connections configured -- run: treeship hub attach".into());
        }
        let names: Vec<String> = ctx.config.hub_connections.keys().cloned().collect();
        for name in &names {
            let entry = &ctx.config.hub_connections[name];
            printer.info(&format!("pushing to hub connection {:?}...", name));
            let result = push_artifact_to_hub(&ctx, &resolved_id, entry)?;
            print_push_result(printer, name, &result);
        }
    } else {
        let (name, entry) = ctx.config.resolve_hub(hub)
            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        let result = push_artifact_to_hub(&ctx, &resolved_id, entry)?;
        print_push_result(printer, name, &result);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// pull
// ---------------------------------------------------------------------------

pub fn pull(
    id:      &str,
    hub:     Option<&str>,
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    let (_name, entry) = ctx.config.resolve_hub(hub)
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
// open
// ---------------------------------------------------------------------------

pub fn open(
    hub:     Option<&str>,
    no_open: bool,
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    let (_name, entry) = ctx.config.resolve_hub(hub)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // We need the dock's private key to DPoP-sign the session mint request.
    let stored_secret = entry.hub_secret_key.as_deref()
        .ok_or("this hub connection has no private key on disk; re-run `treeship hub attach`")?;
    let hub_secret_hex = resolve_hub_secret_hex(&ctx.keys, &entry.hub_id, stored_secret)?;

    // 1. Mint a short-lived share token from the Hub. This is the only call
    //    that needs the dock's private key — the browser then uses the opaque
    //    token (no private key involved).
    let session_url = format!("{}/v1/session", entry.endpoint.trim_end_matches('/'));
    let dpop_jwt = build_dpop_jwt(&hub_secret_hex, "POST", &session_url)?;

    let resp: serde_json::Value = ureq::post(&session_url)
        .set("Authorization", &format!("DPoP {}", entry.hub_id))
        .set("DPoP", &dpop_jwt)
        .send_json(&serde_json::json!({}))?
        .into_json()?;

    let token = resp["token"].as_str()
        .ok_or("hub did not return a session token")?;

    // 2. Build the browser URL. The workspace UI lives on treeship.dev
    //    regardless of which Hub endpoint minted the token.
    let url = format!(
        "https://treeship.dev/workspace/{}?session={}",
        entry.hub_id, token,
    );

    printer.blank();
    printer.info(&url);
    printer.hint("link is valid for 15 minutes");
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
// kill
// ---------------------------------------------------------------------------

pub fn kill(
    name:    &str,
    force:   bool,
    config:  Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    if !ctx.config.hub_connections.contains_key(name) {
        return Err(format!("hub connection {:?} not found\n  Run: treeship hub ls", name).into());
    }

    if !force {
        // Prompt for confirmation
        printer.info(&format!("remove hub connection {:?}? this deletes the local keys.", name));
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

    // If removing the active hub, clear active_hub
    if cfg.active_hub.as_deref() == Some(name) {
        cfg.active_hub = None;
    }

    cfg.hub_connections.remove(name);
    config::save(&cfg, &ctx.config_path)?;

    printer.success("removed", &[("hub", name)]);
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// push_artifact  (backward-compatible for wrap --push)
// ---------------------------------------------------------------------------

/// Shared push logic used by `wrap --push`. Uses the active hub from config.
pub fn push_artifact(
    ctx: &crate::ctx::Ctx,
    id:  &str,
) -> Result<PushResult, Box<dyn std::error::Error>> {
    let (_name, entry) = ctx.config.resolve_hub(None)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    push_artifact_to_hub(ctx, id, entry)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Push a single artifact to a specific hub connection.
fn push_artifact_to_hub(
    ctx:   &crate::ctx::Ctx,
    id:    &str,
    entry: &HubConnection,
) -> Result<PushResult, Box<dyn std::error::Error>> {
    let stored_secret = entry
        .hub_secret_key
        .as_deref()
        .ok_or("no hub_secret_key -- run: treeship hub attach")?;
    let hub_secret_hex = resolve_hub_secret_hex(&ctx.keys, &entry.hub_id, stored_secret)?;

    // 1. Load artifact from local storage
    let record = ctx.storage.read(id)?;

    // 2. Build DPoP proof JWT
    let artifacts_url = format!("{}/v1/artifacts", entry.endpoint);
    let dpop_jwt = build_dpop_jwt(&hub_secret_hex, "POST", &artifacts_url)?;

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
        .set("Authorization", &format!("DPoP {}", entry.hub_id))
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

/// Print push result for a given hub connection.
fn print_push_result(printer: &Printer, hub_name: &str, result: &PushResult) {
    let rekor_str = match result.rekor_index {
        Some(idx) => format!("rekor.sigstore.dev #{}", idx),
        None      => "pending".into(),
    };

    printer.success("pushed", &[
        ("hub",   hub_name),
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
            return Err("no artifacts found -- wrap a command first\n\n  Fix: treeship wrap -- echo hello".into());
        }
        Ok(resolved)
    } else {
        Ok(id.to_string())
    }
}

/// Resolve a stored hub secret into the plaintext hex `build_dpop_jwt` expects.
///
/// New connections store the key sealed under the machine key (AUD-02); older
/// configs stored it as raw plaintext hex. This accepts both: a sealed value is
/// unsealed (binding the hub id as AAD), a legacy plaintext value is returned
/// as-is (and re-sealed the next time the connection is written).
fn resolve_hub_secret_hex(
    keys:   &treeship_core::keys::Store,
    hub_id: &str,
    stored: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    if treeship_core::keys::Store::is_sealed_secret(stored) {
        let bytes = keys
            .unseal_secret(hub_id, stored)
            .map_err(|e| format!("could not unseal hub key for {hub_id}: {e}"))?;
        Ok(hex::encode(bytes))
    } else {
        Ok(stored.to_string())
    }
}

// ---------------------------------------------------------------------------
// DPoP JWT builder
// ---------------------------------------------------------------------------

pub(crate) fn build_dpop_jwt(
    hub_secret_hex: &str,
    method:          &str,
    url:             &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Decode the hub secret key from hex
    let secret_bytes = hex::decode(hub_secret_hex)?;
    let secret_arr: [u8; 32] = secret_bytes.try_into()
        .map_err(|_| "hub secret key must be 32 bytes")?;
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

/// Format a device code for display.
/// Shows full code as XXXX-XXXX-XXXX-XXXX so the user can enter
/// the complete code in the browser activation page.
fn format_device_code(code: &str) -> String {
    if code.len() >= 16 {
        format!("{}-{}-{}-{}", &code[..4], &code[4..8], &code[8..12], &code[12..16])
    } else if code.len() >= 8 {
        format!("{}-{}", &code[..4], &code[4..8])
    } else {
        code.to_string()
    }
}
