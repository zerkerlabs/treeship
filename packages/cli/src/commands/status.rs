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
    printer.blank();

    // Keys
    printer.section("keys");
    let keys = ctx.keys.list()?;
    for k in &keys {
        let marker = if k.is_default { " (default)" } else { "" };
        printer.info(&format!("  {}  {}  {}{}", k.id, k.algorithm, k.fingerprint, marker));
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
            let short_type = a.payload_type
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

    // Dock status
    printer.section("docks");
    if let Some((name, entry)) = cfg.active_dock_entry() {
        printer.info(&format!("  {} {} ({})", printer.green("●"), name, entry.dock_id));
        printer.dim_info(&format!("  endpoint  {}", entry.endpoint));
    } else if cfg.docks.is_empty() {
        printer.info(&format!("  {} no docks", printer.dim("○")));
        printer.hint("treeship dock login");
    } else {
        printer.info(&format!("  {} {} docks, none active", printer.dim("○"), cfg.docks.len()));
        printer.hint("treeship dock use <name>");
    }
    printer.blank();

    Ok(())
}
