use std::io::{self, BufRead, IsTerminal, Write};
use std::path::PathBuf;

use treeship_core::keys::Store as KeyStore;
use treeship_core::rules::ProjectConfig;
use treeship_core::storage::Store as ArtifactStore;

use crate::{
    config::{self, default_config_path},
    printer::Printer,
};

pub fn run(
    name:        Option<String>,
    config_path: Option<String>,
    force:       bool,
    template:    Option<String>,
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

    // ---- 1. Generate keypair (existing behavior) ----

    let keys_dir = config_path.parent()
        .unwrap_or(&config_path)
        .join("keys");

    let key_store = KeyStore::open(&keys_dir)?;

    // Set restrictive permissions on keys directory (0700 -- owner only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if keys_dir.exists() {
            let _ = std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o700));
        }
    }

    let key_info  = key_store.generate(true)?;
    let ship_id   = format!("ship_{}", key_info.fingerprint);

    let cfg = config::new_config(&config_path, &ship_id, &key_info.id, name);
    config::save(&cfg, &config_path)?;

    ArtifactStore::open(&cfg.storage_dir)?;

    printer.blank();
    printer.success("Keypair generated", &[
        ("Ship ID", &ship_id),
        ("Key ID",  &format!("{} (ed25519)", key_info.id)),
    ]);

    // ---- Template path ----
    if let Some(ref tmpl_name) = template {
        let (project_config, onboarding) = super::template::apply_for_init(tmpl_name)?;
        write_project_config(&project_config)?;

        printer.blank();
        printer.success("Configuration saved to .treeship/config.yaml", &[
            ("Template", tmpl_name),
        ]);

        // Show onboarding message
        if let Some(ref msg) = onboarding {
            printer.blank();
            for line in msg.lines() {
                printer.info(line);
            }
        }

        // Offer to install shell hooks if auto_start
        if project_config.session.auto_start {
            printer.blank();
            let hook_input = prompt("Install shell hooks for automatic attestation? [Y/n]: ");
            let install_hooks = !matches!(hook_input.trim().to_lowercase().as_str(), "n" | "no");
            if install_hooks {
                match super::install::install(printer) {
                    Ok(()) => {},
                    Err(e) => {
                        printer.warn("Could not install hooks", &[("error", &e.to_string())]);
                    }
                }
            }
        }

        printer.blank();
        return Ok(());
    }

    let interactive = io::stdin().is_terminal();

    if !interactive {
        // Non-interactive: use defaults, skip prompts
        let project_config = ProjectConfig::default_for("general", "agent://my-agent");
        write_project_config(&project_config)?;

        printer.blank();
        printer.success("Configuration saved to .treeship/config.yaml", &[]);
        printer.blank();
        printer.hint("treeship wrap -- <command>  to create your first receipt");
        printer.hint("treeship install  to set up shell hooks");
        printer.blank();
        return Ok(());
    }

    // ---- 2. Interactive setup ----

    printer.blank();
    printer.dim_info("Setting up automatic attestation...");
    printer.blank();

    // Project type
    printer.info("What kind of project?");
    printer.info("  [1] Agent workflow  [2] CI/CD  [3] General");
    let project_choice = prompt("  (default: 1): ");
    let project_type = match project_choice.trim() {
        "2" => "cicd",
        "3" => "general",
        _   => "agent",
    };

    // Detect language from cwd
    let lang = detect_language();

    printer.blank();

    // Actor URI
    let default_actor = match project_type {
        "agent" => "agent://my-agent",
        "cicd"  => "agent://ci",
        _       => "agent://dev",
    };
    let actor_input = prompt(&format!("Agent actor URI (default: {}): ", default_actor));
    let actor = if actor_input.trim().is_empty() {
        default_actor.to_string()
    } else {
        actor_input.trim().to_string()
    };

    printer.blank();

    // Auto-push
    let push_input = prompt("Auto-push receipts to Hub? [y/N]: ");
    let auto_push = matches!(push_input.trim().to_lowercase().as_str(), "y" | "yes");

    // Build project config
    let core_type = match (project_type, lang.as_str()) {
        (_, "node")   => "node",
        (_, "rust")   => "rust",
        (_, "python") => "python",
        _             => "general",
    };

    let mut project_config = ProjectConfig::default_for(core_type, &actor);
    project_config.session.auto_push = auto_push;

    if auto_push {
        project_config.hub = Some(treeship_core::rules::HubConfig {
            endpoint: Some("https://api.treeship.dev".into()),
            auto_push: true,
            push_on: vec!["session_close".into()],
        });
    }

    // Write .treeship/config.yaml
    write_project_config(&project_config)?;

    printer.blank();
    printer.success("Configuration saved to .treeship/config.yaml", &[]);

    // Offer to install shell hooks
    printer.blank();
    let hook_input = prompt("Install shell hooks for automatic attestation? [Y/n]: ");
    let install_hooks = !matches!(hook_input.trim().to_lowercase().as_str(), "n" | "no");

    if install_hooks {
        match super::install::install(printer) {
            Ok(()) => {},
            Err(e) => {
                printer.warn("Could not install hooks", &[("error", &e.to_string())]);
            }
        }
    }

    // Final summary
    printer.blank();
    printer.info("From now on:");

    // Show a few example commands that will be attested
    for rule in project_config.attest.commands.iter().take(3) {
        let action = if rule.require_approval {
            "blocked until approved"
        } else {
            "automatically attested"
        };
        // Show a short version of the pattern
        let cmd = rule.pattern.trim_end_matches('*');
        printer.info(&format!("  {}  ->  {}", cmd, action));
    }

    printer.blank();
    printer.hint("treeship log --follow  to watch receipts");
    printer.hint("treeship status  to check your Treeship");
    printer.blank();

    Ok(())
}

// ---- helpers ---------------------------------------------------------------

fn prompt(msg: &str) -> String {
    print!("{}", msg);
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
    line
}

fn detect_language() -> String {
    let cwd = std::env::current_dir().unwrap_or_default();
    if cwd.join("package.json").exists() || cwd.join("node_modules").exists() {
        "node".into()
    } else if cwd.join("Cargo.toml").exists() {
        "rust".into()
    } else if cwd.join("pyproject.toml").exists()
        || cwd.join("setup.py").exists()
        || cwd.join("requirements.txt").exists()
    {
        "python".into()
    } else {
        "general".into()
    }
}

fn write_project_config(
    project_config: &ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let ts_dir = cwd.join(".treeship");
    std::fs::create_dir_all(&ts_dir)?;

    // Set restrictive permissions on .treeship directory (0700 -- owner only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&ts_dir, std::fs::Permissions::from_mode(0o700));
    }

    let yaml = serde_yaml::to_string(project_config)?;
    let config_path = ts_dir.join("config.yaml");
    std::fs::write(&config_path, yaml)?;

    // Set restrictive permissions on config.yaml
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600));
    }

    // Write a config.json marker so the daemon trust check passes.
    // The daemon requires both config.yaml and config.json to exist in .treeship/.
    let global_config = crate::config::default_config_path()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let marker = serde_json::json!({
        "extends": global_config,
        "project": true,
    });
    let marker_path = ts_dir.join("config.json");
    std::fs::write(&marker_path, serde_json::to_vec_pretty(&marker)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}
