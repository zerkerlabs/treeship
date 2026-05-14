use crate::{ctx, printer::Printer};

pub fn run(
    follow: bool,
    tail: usize,
    config: Option<&str>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(config)?;

    if follow {
        return run_follow(&ctx, printer);
    }

    let entries = ctx.storage.list();

    // JSON mode: emit a structured list envelope. The pretty path uses
    // `printer.dim_info` / `printer.info`, both of which are no-ops in
    // JSON mode, so without this branch `treeship log --format json`
    // emits zero bytes -- breaking any SDK / automation caller that
    // parses stdout.
    //
    // Shape:
    //   {
    //     "items": [
    //       {
    //         "id":            "...",
    //         "payload_type":  "application/vnd.treeship.<kind>.v1+json",
    //         "signed_at":     "...",
    //       },
    //       ...
    //     ],
    //     "count": <items.len()>,
    //     "total": <entries.len()>
    //   }
    //
    // `count` is the number actually returned (capped by --tail) and
    // `total` is the underlying storage size, so callers can detect
    // truncation without re-running with a larger tail.
    if printer.format == crate::printer::Format::Json {
        let count = entries.len().min(tail);
        let items: Vec<serde_json::Value> = entries
            .iter()
            .take(count)
            .map(|e| {
                serde_json::json!({
                    "id":           e.id,
                    "payload_type": e.payload_type,
                    "signed_at":    e.signed_at,
                })
            })
            .collect();
        let body = serde_json::json!({
            "items": items,
            "count": items.len(),
            "total": entries.len(),
        });
        printer.json(&body);
        return Ok(());
    }

    if entries.is_empty() {
        printer.blank();
        printer.dim_info("  No receipts yet.");
        printer.blank();
        printer.hint("treeship wrap -- <command>  to create your first receipt");
        printer.blank();
        return Ok(());
    }

    let count = entries.len().min(tail);
    let display = &entries[..count];

    printer.blank();
    printer.dim_info(&format!("Recent receipts (last {})", count));
    printer.blank();

    for entry in display {
        print_entry(entry, printer);
    }

    printer.blank();

    Ok(())
}

fn run_follow(ctx: &ctx::Ctx, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    printer.blank();
    printer.dim_info("  Watching for new receipts... (Ctrl+C to stop)");
    printer.blank();

    let mut seen_count = ctx.storage.list().len();

    // Print existing entries first (last 5 as context)
    let entries = ctx.storage.list();
    let start = if entries.len() > 5 { entries.len() - 5 } else { 0 };
    for entry in &entries[start..] {
        print_entry(entry, printer);
    }
    if !entries.is_empty() {
        printer.dim_info("  ---");
    }

    loop {
        std::thread::sleep(std::time::Duration::from_millis(500));

        let current = ctx.storage.list();
        if current.len() > seen_count {
            // Print new entries (they appear at the front since list() is most-recent-first)
            let new_count = current.len() - seen_count;
            // The new entries are at indices 0..new_count (most recent first)
            for entry in current[..new_count].iter().rev() {
                print_entry(entry, printer);
            }
            seen_count = current.len();
        }
    }
}

fn print_entry(entry: &treeship_core::storage::IndexEntry, printer: &Printer) {
    let short_type = entry
        .payload_type
        .strip_prefix("application/vnd.treeship.")
        .and_then(|s| s.strip_suffix(".v1+json"))
        .unwrap_or(&entry.payload_type);

    // Format the type as a badge
    let badge = format!("[{}]", short_type);

    let short_id = if entry.id.len() > 14 {
        &entry.id[..14]
    } else {
        &entry.id
    };

    // Format timestamp -- show date + time portion
    let ts = if entry.signed_at.len() >= 19 {
        &entry.signed_at[..19]
    } else {
        &entry.signed_at
    };

    printer.info(&format!(
        "  {}  {:12}  {}",
        ts,
        badge,
        short_id,
    ));
}
