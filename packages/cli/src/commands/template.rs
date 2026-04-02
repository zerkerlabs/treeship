use std::path::PathBuf;

use crate::printer::Printer;
use crate::templates;

// ---------------------------------------------------------------------------
// treeship templates -- list all available templates
// ---------------------------------------------------------------------------

pub fn list(printer: &Printer) {
    printer.blank();
    printer.section("OFFICIAL TEMPLATES");
    printer.blank();

    for (category, tmpls) in templates::by_category() {
        printer.info(&format!("  {category}"));
        for t in &tmpls {
            let pad = " ".repeat(24_usize.saturating_sub(t.name.len()));
            printer.info(&format!("    {}{}{}", t.name, pad, printer.dim(t.description)));
        }
        printer.blank();
    }

    printer.dim_info("  Apply:    treeship init --template <name>");
    printer.dim_info("  Preview:  treeship template preview <name>");
    printer.blank();
}

// ---------------------------------------------------------------------------
// treeship template preview <name>
// ---------------------------------------------------------------------------

pub fn preview(name: &str, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let tmpl = resolve_template(name)?;
    let parsed: TemplateYaml = serde_yaml::from_str(tmpl.yaml)
        .map_err(|e| format!("failed to parse template YAML: {e}"))?;

    printer.blank();
    printer.section(&format!("Template: {}", parsed.name));
    printer.info(&"─".repeat(42));
    printer.blank();
    printer.info(&format!("  {}", parsed.description.trim()));
    printer.blank();

    // Triggers
    if !parsed.attest.commands.is_empty() {
        printer.info("  Triggers");
        for cmd in &parsed.attest.commands {
            let pad = " ".repeat(18_usize.saturating_sub(cmd.pattern.len()));
            let extras = if cmd.require_approval.unwrap_or(false) {
                " (approval required)"
            } else {
                ""
            };
            printer.info(&format!("    {}{}-> {}{}", cmd.pattern, pad, cmd.label, extras));
        }
        printer.blank();
    }

    // Paths
    if let Some(ref paths) = parsed.attest.paths {
        if !paths.is_empty() {
            printer.info("  Watched paths");
            for p in paths {
                let label = p.label.as_deref().unwrap_or("file change");
                printer.info(&format!("    {} (on {}) -> {}", p.path, p.on, label));
            }
            printer.blank();
        }
    }

    // Capture
    if let Some(ref cap) = parsed.capture {
        printer.info("  Capture");
        if cap.output_digest.unwrap_or(false)    { printer.info("    output digest    yes"); }
        if cap.file_changes.unwrap_or(false)     { printer.info("    file changes     yes"); }
        if cap.git_state.unwrap_or(false)        { printer.info("    git state        yes"); }
        if cap.lockfile_changes.unwrap_or(false)  { printer.info("    lockfile         yes"); }
        if cap.environment.unwrap_or(false)       { printer.info("    environment      yes"); }
        if cap.model_metadata.unwrap_or(false)    { printer.info("    model metadata   yes"); }
        printer.blank();
    }

    // Approvals
    if let Some(ref approvals) = parsed.approvals {
        if !approvals.require_for.is_empty() {
            printer.info("  Approvals");
            for r in &approvals.require_for {
                printer.info(&format!("    required for: {}", r.label));
            }
            printer.blank();
        }
    } else {
        printer.info("  Approvals");
        printer.info("    none required");
        printer.blank();
    }

    // Hub
    if let Some(ref hub) = parsed.hub {
        printer.info("  Hub");
        printer.info(&format!("    auto push: {}", if hub.auto_push.unwrap_or(false) { "yes" } else { "no" }));
        if !hub.push_on.is_empty() {
            printer.info(&format!("    push on:   {}", hub.push_on.join(", ")));
        }
        printer.blank();
    }

    printer.dim_info(&format!("  Apply: treeship init --template {}", parsed.name));
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// treeship template apply <name> -- apply to existing project
// ---------------------------------------------------------------------------

pub fn apply(name: &str, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let tmpl = resolve_template(name)?;
    let parsed: TemplateYaml = serde_yaml::from_str(tmpl.yaml)
        .map_err(|e| format!("failed to parse template YAML: {e}"))?;

    let project_config = template_to_project_config(&parsed)?;
    write_project_config(&project_config)?;

    printer.blank();
    printer.success(&format!("Template '{}' applied", parsed.name), &[]);
    printer.blank();

    // Show onboarding message
    if let Some(ref onboarding) = parsed.onboarding {
        for line in onboarding.lines() {
            printer.info(line);
        }
        printer.blank();
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// treeship template validate <file> -- validate a custom template YAML
// ---------------------------------------------------------------------------

pub fn validate(file: &str, printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let path = PathBuf::from(file);
    if !path.exists() {
        return Err(format!("file not found: {}", path.display()).into());
    }

    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;

    printer.blank();
    printer.section(&format!("Validating: {}", path.display()));
    printer.blank();

    let mut pass = true;

    // Check: valid YAML
    let parsed: Result<TemplateYaml, _> = serde_yaml::from_str(&contents);
    match parsed {
        Ok(ref t) => {
            printer.info(&format!("  {} valid YAML", printer.green("PASS")));

            // Check: name present
            if t.name.is_empty() {
                printer.info(&format!("  {} name is empty", printer.red("FAIL")));
                pass = false;
            } else {
                printer.info(&format!("  {} name: {}", printer.green("PASS"), t.name));
            }

            // Check: description present
            if t.description.trim().is_empty() {
                printer.info(&format!("  {} description is empty", printer.red("FAIL")));
                pass = false;
            } else {
                printer.info(&format!("  {} description present", printer.green("PASS")));
            }

            // Check: session.actor present
            if let Some(ref session) = t.session {
                if session.actor.is_empty() {
                    printer.info(&format!("  {} session.actor is empty", printer.red("FAIL")));
                    pass = false;
                } else {
                    printer.info(&format!("  {} session.actor: {}", printer.green("PASS"), session.actor));
                }
            } else {
                printer.info(&format!("  {} session section missing", printer.red("FAIL")));
                pass = false;
            }

            // Check: version present
            if t.version.unwrap_or(0) == 0 {
                printer.info(&format!("  {} version should be >= 1", printer.yellow("WARN")));
            } else {
                printer.info(&format!("  {} version: {}", printer.green("PASS"), t.version.unwrap()));
            }

            // Check: can convert to ProjectConfig
            match template_to_project_config(t) {
                Ok(_) => {
                    printer.info(&format!("  {} converts to ProjectConfig", printer.green("PASS")));
                }
                Err(e) => {
                    printer.info(&format!("  {} ProjectConfig conversion: {e}", printer.red("FAIL")));
                    pass = false;
                }
            }
        }
        Err(e) => {
            printer.info(&format!("  {} invalid YAML: {e}", printer.red("FAIL")));
            pass = false;
        }
    }

    printer.blank();
    if pass {
        printer.success("Template is valid", &[]);
    } else {
        printer.failure("Template has errors", &[]);
    }
    printer.blank();

    if pass { Ok(()) } else { Err("validation failed".into()) }
}

// ---------------------------------------------------------------------------
// treeship template save -- save current config as a template
// ---------------------------------------------------------------------------

pub fn save(
    name: Option<String>,
    printer: &Printer,
) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let config_path = cwd.join(".treeship").join("config.yaml");

    if !config_path.exists() {
        return Err("no .treeship/config.yaml in current directory".into());
    }

    let contents = std::fs::read_to_string(&config_path)?;

    // Ask for name if not provided
    let template_name = match name {
        Some(n) => n,
        None => {
            use std::io::{self, Write};
            print!("Template name: ");
            let _ = io::stdout().flush();
            let mut line = String::new();
            let _ = io::stdin().read_line(&mut line);
            let trimmed = line.trim().to_string();
            if trimmed.is_empty() {
                return Err("template name is required".into());
            }
            trimmed
        }
    };

    // Slugify the name
    let slug: String = template_name
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' { c } else { '-' })
        .collect();

    // Build output path: ~/.treeship/templates/<slug>.yaml
    let home = home::home_dir().ok_or("cannot determine home directory")?;
    let templates_dir = home.join(".treeship").join("templates");
    std::fs::create_dir_all(&templates_dir)?;

    let out_path = templates_dir.join(format!("{slug}.yaml"));

    // Add template metadata header
    let header = format!(
        "name: {slug}\nversion: 1\ndescription: >\n  Custom template saved from project config.\n\n"
    );

    // Strip ship_id lines and hub/dock credentials from the YAML
    let cleaned: String = contents
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.starts_with("ship_id:")
                && !trimmed.starts_with("dock_public_key:")
                && !trimmed.starts_with("dock_secret_key:")
                && !trimmed.starts_with("dock_id:")
                && !trimmed.starts_with("hub_public_key:")
                && !trimmed.starts_with("hub_secret_key:")
                && !trimmed.starts_with("hub_id:")
                && !trimmed.starts_with("workspace_id:")
        })
        .collect::<Vec<&str>>()
        .join("\n");

    let output = format!("{header}{cleaned}\n");
    std::fs::write(&out_path, output)?;

    printer.blank();
    printer.success("Template saved", &[
        ("Name", &slug),
        ("Path", &out_path.to_string_lossy()),
    ]);
    printer.blank();
    printer.hint(&format!("treeship template validate {}", out_path.display()));
    printer.blank();

    Ok(())
}

// ---------------------------------------------------------------------------
// Apply template during init flow
// ---------------------------------------------------------------------------

/// Apply a template by name (from embedded registry) or file path.
/// Returns the onboarding message to display, if any.
pub fn apply_for_init(
    name_or_path: &str,
) -> Result<(treeship_core::rules::ProjectConfig, Option<String>), Box<dyn std::error::Error>> {
    let yaml_str = if std::path::Path::new(name_or_path).exists() {
        // Load from file path
        std::fs::read_to_string(name_or_path)?
    } else {
        // Look up embedded template
        let tmpl = templates::get(name_or_path)
            .ok_or_else(|| format!(
                "template '{}' not found\n\n  Run 'treeship templates' to see available templates.",
                name_or_path
            ))?;
        tmpl.yaml.to_string()
    };

    let parsed: TemplateYaml = serde_yaml::from_str(&yaml_str)
        .map_err(|e| format!("failed to parse template YAML: {e}"))?;

    let project_config = template_to_project_config(&parsed)?;
    let onboarding = parsed.onboarding.clone();

    Ok((project_config, onboarding))
}

// ---------------------------------------------------------------------------
// Internal: template YAML format (superset of ProjectConfig)
// ---------------------------------------------------------------------------

#[derive(Debug, serde::Deserialize)]
struct TemplateYaml {
    #[serde(default)]
    name: String,
    #[serde(default)]
    version: Option<u32>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    audience: Vec<String>,
    #[serde(default)]
    session: Option<TemplateSession>,
    #[serde(default)]
    attest: TemplateAttest,
    #[serde(default)]
    capture: Option<TemplateCapture>,
    #[serde(default)]
    approvals: Option<TemplateApprovals>,
    #[serde(default)]
    hub: Option<TemplateHub>,
    #[serde(default)]
    onboarding: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
struct TemplateSession {
    #[serde(default)]
    actor: String,
    #[serde(default)]
    auto_start: bool,
    #[serde(default)]
    auto_checkpoint: bool,
    #[serde(default)]
    auto_push: bool,
}

#[derive(Debug, Default, serde::Deserialize)]
struct TemplateAttest {
    #[serde(default)]
    commands: Vec<TemplateCommand>,
    #[serde(default)]
    paths: Option<Vec<TemplatePath>>,
}

#[derive(Debug, serde::Deserialize)]
struct TemplateCommand {
    pattern: String,
    label: String,
    #[serde(default)]
    require_approval: Option<bool>,
    #[serde(default)]
    capture_output_digest: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
struct TemplatePath {
    path: String,
    on: String,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    alert: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
struct TemplateCapture {
    #[serde(default)]
    output_digest: Option<bool>,
    #[serde(default)]
    file_changes: Option<bool>,
    #[serde(default)]
    git_state: Option<bool>,
    #[serde(default)]
    lockfile_changes: Option<bool>,
    #[serde(default)]
    environment: Option<bool>,
    #[serde(default)]
    model_metadata: Option<bool>,
}

#[derive(Debug, serde::Deserialize)]
struct TemplateApprovals {
    #[serde(default)]
    require_for: Vec<TemplateLabelRef>,
}

#[derive(Debug, serde::Deserialize)]
struct TemplateLabelRef {
    label: String,
}

#[derive(Debug, serde::Deserialize)]
struct TemplateHub {
    #[serde(default)]
    auto_push: Option<bool>,
    #[serde(default)]
    push_on: Vec<String>,
    #[serde(default)]
    endpoint: Option<String>,
}

// ---------------------------------------------------------------------------
// Convert TemplateYaml -> ProjectConfig
// ---------------------------------------------------------------------------

fn template_to_project_config(
    t: &TemplateYaml,
) -> Result<treeship_core::rules::ProjectConfig, Box<dyn std::error::Error>> {
    use treeship_core::rules::*;

    let session = match &t.session {
        Some(s) => SessionConfig {
            actor: s.actor.clone(),
            auto_start: s.auto_start,
            auto_checkpoint: s.auto_checkpoint,
            auto_push: s.auto_push,
        },
        None => SessionConfig {
            actor: "agent://default".into(),
            auto_start: true,
            auto_checkpoint: false,
            auto_push: false,
        },
    };

    let commands: Vec<CommandRule> = t.attest.commands.iter().map(|c| CommandRule {
        pattern: c.pattern.clone(),
        label: c.label.clone(),
        require_approval: c.require_approval.unwrap_or(false),
    }).collect();

    let paths: Vec<PathRule> = t.attest.paths.as_ref().map(|ps| {
        ps.iter().map(|p| PathRule {
            path: p.path.clone(),
            on: p.on.clone(),
            label: p.label.clone(),
            alert: p.alert.unwrap_or(false),
        }).collect()
    }).unwrap_or_default();

    let approvals = t.approvals.as_ref().map(|a| ApprovalConfig {
        require_for: a.require_for.iter().map(|r| LabelRef {
            label: r.label.clone(),
        }).collect(),
        auto_approve: vec![],
        timeout: None,
    });

    let hub = t.hub.as_ref().map(|h| HubConfig {
        endpoint: h.endpoint.clone(),
        auto_push: h.auto_push.unwrap_or(false),
        push_on: h.push_on.clone(),
    });

    Ok(ProjectConfig {
        treeship: TreeshipMeta { version: t.version.unwrap_or(1) },
        session,
        attest: AttestConfig { commands, paths },
        approvals,
        hub,
    })
}

// ---------------------------------------------------------------------------
// Resolve template from name or path
// ---------------------------------------------------------------------------

fn resolve_template(name: &str) -> Result<&'static templates::Template, Box<dyn std::error::Error>> {
    templates::get(name).ok_or_else(|| {
        let available: Vec<&str> = templates::list().iter().map(|t| t.name).collect();
        format!(
            "template '{}' not found\n\n  Available templates:\n    {}\n\n  Run 'treeship templates' for details.",
            name,
            available.join("\n    ")
        ).into()
    })
}

// ---------------------------------------------------------------------------
// Write project config to .treeship/config.yaml
// ---------------------------------------------------------------------------

fn write_project_config(
    project_config: &treeship_core::rules::ProjectConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    let cwd = std::env::current_dir()?;
    let ts_dir = cwd.join(".treeship");
    std::fs::create_dir_all(&ts_dir)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&ts_dir, std::fs::Permissions::from_mode(0o700));
    }

    let yaml = serde_yaml::to_string(project_config)?;
    let config_path = ts_dir.join("config.yaml");
    std::fs::write(&config_path, yaml)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(())
}
