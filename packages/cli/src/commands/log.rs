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
    let start = if entries.len() > 5 {
        entries.len() - 5
    } else {
        0
    };
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

/// `application/vnd.treeship.action.v1+json` -> `action`
/// `application/vnd.treeship.action.v2+json` -> `action/v2`
///
/// Anything that does not match the shape is returned unchanged rather than
/// mangled: an unrecognised payload type should look unrecognised.
fn short_payload_label(payload_type: &str) -> String {
    let Some(rest) = payload_type.strip_prefix("application/vnd.treeship.") else {
        return payload_type.to_string();
    };
    let Some(body) = rest.strip_suffix("+json") else {
        return payload_type.to_string();
    };
    match body.rsplit_once('.') {
        Some((kind, "v1")) => kind.to_string(),
        Some((kind, ver)) if ver.starts_with('v') => format!("{kind}/{ver}"),
        _ => payload_type.to_string(),
    }
}

fn print_entry(entry: &treeship_core::storage::IndexEntry, printer: &Printer) {
    // v1 shows as `action`; anything later keeps its version, because the
    // version is the interesting part -- an action/v2 carries a mandate and a
    // v1 does not. Previously only `.v1+json` was stripped, so a v2 receipt
    // fell through and printed the whole MIME string as its badge.
    let short_type = short_payload_label(&entry.payload_type);

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

    printer.info(&format!("  {}  {:12}  {}", ts, badge, short_id,));
}

#[cfg(test)]
mod tests {
    use super::short_payload_label;

    #[test]
    fn v1_drops_the_version_and_v2_keeps_it() {
        // v1 is the unmarked default; a later version is worth showing,
        // because an action/v2 carries a mandate and a v1 does not.
        assert_eq!(
            short_payload_label("application/vnd.treeship.action.v1+json"),
            "action"
        );
        assert_eq!(
            short_payload_label("application/vnd.treeship.action.v2+json"),
            "action/v2"
        );
        assert_eq!(
            short_payload_label("application/vnd.treeship.approval.v1+json"),
            "approval"
        );
    }

    #[test]
    fn unrecognised_types_are_left_alone() {
        // Better to show something obviously foreign than to half-parse it
        // into a label that looks like a known kind.
        for t in [
            "application/json",
            "application/vnd.treeship.action",
            "application/vnd.other.action.v1+json",
            "",
        ] {
            assert_eq!(short_payload_label(t), t, "mangled {t}");
        }
    }
}
