use crate::{ctx, printer::Printer};

pub fn run(config: Option<&str>, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let cfg = &ctx.config;

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

    // Hub status
    printer.section("hub");
    match cfg.hub.status.as_str() {
        "docked" => {
            let endpoint = cfg.hub.endpoint.as_deref().unwrap_or("treeship.dev");
            let ws = cfg.hub.workspace_id.as_deref().unwrap_or("-");
            printer.info(&format!("  {} docked to {}", printer.green("●"), endpoint));
            printer.dim_info(&format!("  workspace  {ws}"));
        }
        _ => {
            printer.info(&format!("  {} undocked", printer.dim("○")));
            printer.blank();
            printer.hint("treeship dock login");
        }
    }
    printer.blank();

    Ok(())
}
