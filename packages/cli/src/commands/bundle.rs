use std::path::PathBuf;

use treeship_core::bundle;

use crate::{ctx, printer::Printer};

pub struct CreateArgs {
    pub artifacts:   Vec<String>,
    pub tag:         Option<String>,
    pub description: Option<String>,
    pub config:      Option<String>,
}

pub fn create(args: CreateArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;
    let signer = ctx.keys.default_signer()?;

    let id_refs: Vec<&str> = args.artifacts.iter().map(|s| s.as_str()).collect();

    let result = bundle::create(
        &id_refs,
        args.tag.as_deref(),
        args.description.as_deref(),
        &ctx.storage,
        signer.as_ref(),
    ).map_err(|e| format!("{e}"))?;

    let mut fields: Vec<(&str, String)> = vec![
        ("id",        result.artifact_id.clone()),
        ("artifacts", format!("{}", result.statement.artifacts.len())),
        ("signed",    result.statement.timestamp.clone()),
    ];
    if let Some(t) = &result.statement.tag {
        fields.push(("tag", t.clone()));
    }

    let field_refs: Vec<(&str, &str)> = fields.iter().map(|(k, v)| (*k, v.as_str())).collect();
    printer.success("bundle created", &field_refs);
    printer.hint(&format!("treeship bundle export {} --out bundle.treeship", result.artifact_id));
    printer.blank();
    Ok(())
}

pub struct ExportArgs {
    pub bundle_id: String,
    pub out:       String,
    pub config:    Option<String>,
}

pub fn export(args: ExportArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;
    let out_path = PathBuf::from(&args.out);

    bundle::export(&args.bundle_id, &out_path, &ctx.storage)
        .map_err(|e| format!("{e}"))?;

    printer.success("bundle exported", &[
        ("id",   &args.bundle_id),
        ("file", &args.out),
    ]);
    printer.hint(&format!("share {} or run: treeship bundle import {}", args.out, args.out));
    printer.blank();
    Ok(())
}

pub struct ImportArgs {
    pub file:   String,
    pub config: Option<String>,
}

pub fn import(args: ImportArgs, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let ctx = ctx::open(args.config.as_deref())?;
    let path = PathBuf::from(&args.file);

    let bundle_id = bundle::import(&path, &ctx.storage)
        .map_err(|e| format!("{e}"))?;

    printer.success("bundle imported", &[
        ("id",   &bundle_id),
        ("from", &args.file),
    ]);
    printer.hint(&format!("treeship verify {}", bundle_id));
    printer.blank();
    Ok(())
}
