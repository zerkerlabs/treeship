use crate::{ctx, printer::Printer};

pub fn list(config: Option<&str>, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx   = ctx::open(config)?;
    let infos = ctx.keys.list()?;

    if infos.is_empty() {
        printer.info("no keys found — run 'treeship init'");
        return Ok(());
    }

    if printer.format == crate::printer::Format::Json {
        let out: Vec<_> = infos.iter().map(|k| serde_json::json!({
            "id":          k.id,
            "algorithm":   k.algorithm,
            "is_default":  k.is_default,
            "created_at":  k.created_at,
            "fingerprint": k.fingerprint,
        })).collect();
        printer.json(&out);
        return Ok(());
    }

    for k in &infos {
        let default_marker = if k.is_default { " (default)" } else { "" };
        printer.info(&format!(
            "  {}  {}  {}{}",
            k.id, k.algorithm, k.fingerprint, default_marker
        ));
    }
    Ok(())
}
