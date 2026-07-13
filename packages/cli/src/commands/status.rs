use crate::{ctx, printer::Printer};

fn format_duration_ms(ms: u64) -> String {
    let secs = ms / 1000;
    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else {
        let h = secs / 3600;
        let m = (secs % 3600) / 60;
        format!("{}h{}m", h, m)
    }
}

pub fn run(config: Option<&str>, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let cfg = &ctx.config;

    // JSON mode: emit a single structured envelope summarising the full
    // workspace state. The pretty path below uses `printer.section`,
    // `printer.info`, `printer.dim_info`, and `printer.hint` -- ALL of
    // which are no-ops in JSON mode (see printer.rs). So before this
    // branch, `treeship status --format json` produced zero stdout
    // bytes and every SDK / automation caller silently treated the
    // workspace as empty.
    //
    // Shape (top-level groups mirror the pretty sections so callers
    // can map field-for-field):
    //   {
    //     "ship":    { "id": "...", "name": "..." | null },
    //     "session": null | {
    //       "session_id": "...", "name": "..." | null,
    //       "started_at_ms": <u64>, "elapsed_ms": <u64>
    //     },
    //     "keys":    [{"id":"...","algorithm":"...","fingerprint":"...","is_default":bool}],
    //     "artifacts": {
    //       "items": [{"id":"...","payload_type":"...","signed_at":"..."}],
    //       "count": <u64>,    // returned (capped at 5)
    //       "total": <u64>     // underlying storage size
    //     },
    //     "daemon":  { "status": "running"|"stopped",
    //                  "pid": <u32> | null, "uptime_secs": <u64> | null },
    //     "hub":     { "status": "attached"|"detached"|"configured",
    //                  "active": "<name>" | null, "hub_id": "..." | null,
    //                  "endpoint": "..." | null, "count": <u64> }
    //   }
    //
    // `daemon.status` and `hub.status` use the same enum-string convention
    // as Lane D's `hub status` to keep the SDK consistent.
    if printer.format == crate::printer::Format::Json {
        let session = super::session::load_session().map(|m| {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            let elapsed_ms = now_ms.saturating_sub(m.started_at_ms);
            serde_json::json!({
                "session_id":    m.session_id,
                "name":          m.name,
                "started_at_ms": m.started_at_ms,
                "elapsed_ms":    elapsed_ms,
            })
        });

        let keys = ctx.keys.list()?;
        let keys_json: Vec<serde_json::Value> = keys
            .iter()
            .map(|k| {
                serde_json::json!({
                    "id":          k.id,
                    "algorithm":   k.algorithm,
                    "fingerprint": k.fingerprint,
                    "is_default":  k.is_default,
                })
            })
            .collect();

        let artifacts = ctx.storage.list();
        let artifact_items: Vec<serde_json::Value> = artifacts
            .iter()
            .take(5)
            .map(|a| {
                serde_json::json!({
                    "id":           a.id,
                    "payload_type": a.payload_type,
                    "signed_at":    a.signed_at,
                })
            })
            .collect();

        let (daemon_running, daemon_pid, daemon_uptime) = super::daemon::daemon_info();
        let daemon = if daemon_running {
            serde_json::json!({
                "status":      "running",
                "pid":         daemon_pid,
                "uptime_secs": daemon_uptime,
            })
        } else {
            serde_json::json!({
                "status":      "stopped",
                "pid":         serde_json::Value::Null,
                "uptime_secs": serde_json::Value::Null,
            })
        };

        let hub = if let Some((name, entry)) = cfg.active_hub_connection() {
            serde_json::json!({
                "status":   "attached",
                "active":   name,
                "hub_id":   entry.hub_id,
                "endpoint": entry.endpoint,
                "count":    cfg.hub_connections.len(),
            })
        } else if cfg.hub_connections.is_empty() {
            serde_json::json!({
                "status":   "detached",
                "active":   serde_json::Value::Null,
                "hub_id":   serde_json::Value::Null,
                "endpoint": serde_json::Value::Null,
                "count":    0,
            })
        } else {
            serde_json::json!({
                "status":   "configured",
                "active":   serde_json::Value::Null,
                "hub_id":   serde_json::Value::Null,
                "endpoint": serde_json::Value::Null,
                "count":    cfg.hub_connections.len(),
            })
        };

        let body = serde_json::json!({
            "store": {
                "source":      ctx.config_source.label(),
                "config_path": ctx.config_path.display().to_string(),
            },
            "ship": {
                "id":   cfg.ship_id,
                "name": cfg.name,
            },
            "session": session,
            "keys":    keys_json,
            "artifacts": {
                "items": artifact_items,
                "count": artifacts.len().min(5),
                "total": artifacts.len(),
            },
            "daemon": daemon,
            "hub":    hub,
        });
        printer.json(&body);
        return Ok(());
    }

    // Session info (if active)
    if let Some(manifest) = super::session::load_session() {
        let elapsed_ms = {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            now_ms.saturating_sub(manifest.started_at_ms)
        };
        let elapsed_str = format_duration_ms(elapsed_ms);
        let name_str = manifest.name.as_deref().unwrap_or("");

        printer.blank();
        printer.section("session");
        printer.info(&format!(
            "  {}  \"{}\"  started {} ago",
            manifest.session_id, name_str, elapsed_str
        ));
    }

    printer.blank();
    printer.section("ship");
    printer.info(&format!("  {}", cfg.ship_id));
    if let Some(name) = &cfg.name {
        printer.dim_info(&format!("  {name}"));
    }
    // WHICH store this command resolved. Store discovery walks up from the
    // working directory and silently switches between project-local and
    // global config — invisible everywhere but `doctor` until now, and the
    // root cause of a whole class of "wrong keystore" confusion.
    printer.dim_info(&format!(
        "  store: {} -- {}",
        ctx.config_source.label(),
        ctx.config_path.display()
    ));
    printer.blank();

    // Keys
    printer.section("keys");
    let keys = ctx.keys.list()?;
    for k in &keys {
        let marker = if k.is_default { " (default)" } else { "" };
        printer.info(&format!(
            "  {}  {}  {}{}",
            k.id, k.algorithm, k.fingerprint, marker
        ));
    }
    printer.blank();

    // Recent artifacts
    printer.section("recent artifacts");
    let artifacts = ctx.storage.list();
    if artifacts.is_empty() {
        printer.dim_info("  no artifacts yet");
        printer.blank();
        printer.hint("treeship attest action --actor agent://me --action tool.call");
    } else {
        for a in artifacts.iter().take(5) {
            let short_type = a
                .payload_type
                .strip_prefix("application/vnd.treeship.")
                .and_then(|s| s.strip_suffix(".v1+json"))
                .unwrap_or(&a.payload_type);
            printer.info(&format!(
                "  {}  {}  {}",
                &a.id[..16.min(a.id.len())],
                short_type,
                a.signed_at.split('T').next().unwrap_or(&a.signed_at)
            ));
        }
        if artifacts.len() > 5 {
            printer.dim_info(&format!("  ... and {} more", artifacts.len() - 5));
        }
    }
    printer.blank();

    // Daemon status
    printer.section("daemon");
    let (daemon_running, daemon_pid, daemon_uptime) = super::daemon::daemon_info();
    if daemon_running {
        let pid = daemon_pid.unwrap_or(0);
        let uptime_str = daemon_uptime
            .map(|s| format_duration_ms(s * 1000))
            .unwrap_or_else(|| "unknown".to_string());
        printer.info(&format!(
            "  {} running  pid {}  (uptime: {})",
            printer.green("●"),
            pid,
            uptime_str,
        ));
    } else {
        printer.info(&format!("  {} stopped", printer.dim("○")));
        printer.hint("treeship daemon start");
    }
    printer.blank();

    // Hub status
    printer.section("hub");
    if let Some((name, entry)) = cfg.active_hub_connection() {
        printer.info(&format!(
            "  {} {} ({})",
            printer.green("●"),
            name,
            entry.hub_id
        ));
        printer.dim_info(&format!("  endpoint  {}", entry.endpoint));
    } else if cfg.hub_connections.is_empty() {
        printer.info(&format!("  {} no hub connections", printer.dim("○")));
        printer.hint("treeship hub attach");
    } else {
        printer.info(&format!(
            "  {} {} hub connections, none active",
            printer.dim("○"),
            cfg.hub_connections.len()
        ));
        printer.hint("treeship hub use <name>");
    }
    printer.blank();

    Ok(())
}
