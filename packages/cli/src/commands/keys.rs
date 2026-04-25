use crate::{ctx, printer::Printer};

pub fn list(config: Option<&str>, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx   = ctx::open(config)?;
    let infos = ctx.keys.list()?;

    if infos.is_empty() {
        printer.info("no keys found -- run 'treeship init'");
        return Ok(());
    }

    if printer.format == crate::printer::Format::Json {
        let out: Vec<_> = infos.iter().map(|k| serde_json::json!({
            "id":               k.id,
            "algorithm":        k.algorithm,
            "is_default":       k.is_default,
            "created_at":       k.created_at,
            "fingerprint":      k.fingerprint,
            "valid_until":      k.valid_until,
            "successor_key_id": k.successor_key_id,
        })).collect();
        printer.json(&out);
        return Ok(());
    }

    for k in &infos {
        let default_marker = if k.is_default { " (default)" } else { "" };
        let lifecycle = match (&k.valid_until, &k.successor_key_id) {
            (Some(until), Some(succ)) => format!("  rotated -> {succ}, valid until {until}"),
            (Some(until), None)       => format!("  valid until {until}"),
            (None, Some(succ))        => format!("  successor: {succ}"),
            (None, None)              => String::new(),
        };
        printer.info(&format!(
            "  {}  {}  {}{}{}",
            k.id, k.algorithm, k.fingerprint, default_marker, lifecycle
        ));
    }
    Ok(())
}

pub fn rotate(
    key_id: Option<&str>,
    grace_hours: u64,
    set_default: bool,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;
    let grace = std::time::Duration::from_secs(grace_hours.saturating_mul(3600));
    let result = ctx.keys.rotate(key_id, grace, set_default)?;

    if printer.format == crate::printer::Format::Json {
        printer.json(&serde_json::json!({
            "predecessor": {
                "id":          result.predecessor.id,
                "fingerprint": result.predecessor.fingerprint,
                "valid_until": result.predecessor.valid_until,
            },
            "successor": {
                "id":          result.successor.id,
                "fingerprint": result.successor.fingerprint,
                "is_default":  result.successor.is_default,
            },
            "grace_period_until": result.grace_period_until,
        }));
        return Ok(());
    }

    printer.info("rotated");
    printer.info(&format!("  predecessor:  {}  ({})", result.predecessor.id, result.predecessor.fingerprint));
    printer.info(&format!("  successor:    {}  ({})", result.successor.id, result.successor.fingerprint));
    printer.info(&format!("  valid until:  {} (predecessor accepts new sigs until then)", result.grace_period_until));
    if set_default {
        printer.info("  default:      successor is now the default signer");
    } else {
        printer.info("  default:      unchanged (use 'treeship keys list' to confirm)");
    }
    Ok(())
}
