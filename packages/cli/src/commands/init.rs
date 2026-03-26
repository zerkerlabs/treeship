use std::path::PathBuf;

use treeship_core::keys::Store as KeyStore;
use treeship_core::storage::Store as ArtifactStore;

use crate::{
    config::{self, default_config_path},
    printer::Printer,
};

pub fn run(
    name:        Option<String>,
    config_path: Option<String>,
    force:       bool,
    printer:     &Printer,
) -> Result<(), Box<dyn std::error::Error>> {

    let config_path: PathBuf = match config_path {
        Some(p) => PathBuf::from(p),
        None    => default_config_path()?,
    };

    if config_path.exists() && !force {
        return Err(format!(
            "already initialized at {}\n\n  Use --force to regenerate, or --config <path> for a different location.",
            config_path.display()
        ).into());
    }

    let keys_dir = config_path.parent()
        .unwrap_or(&config_path)
        .join("keys");

    let key_store = KeyStore::open(&keys_dir)?;
    let key_info  = key_store.generate(true)?;
    let ship_id   = format!("ship_{}", key_info.fingerprint);

    let cfg = config::new_config(&config_path, &ship_id, &key_info.id, name);
    config::save(&cfg, &config_path)?;

    ArtifactStore::open(&cfg.storage_dir)?;

    // --- output ---

    printer.blank();
    printer.success("treeship initialized", &[
        ("ship",    &ship_id),
        ("key",     &format!("{} (ed25519)", key_info.id)),
        ("config",  &config_path.to_string_lossy()),
        ("storage", &cfg.storage_dir),
    ]);

    printer.blank();
    printer.dim_info("your keys are encrypted at rest and tied to this machine.");
    printer.blank();

    // Show three concrete next steps
    printer.dim_info("next steps:");
    printer.hint("treeship attest action --actor agent://me --action tool.call");
    printer.hint("treeship wrap -- <any command>");
    printer.hint("treeship status");

    printer.blank();

    Ok(())
}
