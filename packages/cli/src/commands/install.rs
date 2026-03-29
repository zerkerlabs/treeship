use std::path::PathBuf;

use crate::printer::Printer;

const MARKER_START: &str = "# Treeship shell hook -- installed by treeship install";
const MARKER_END: &str = "# End Treeship shell hook";

const ZSH_HOOK: &str = r#"# Treeship shell hook -- installed by treeship install
treeship_preexec() {
  treeship hook pre "$1" 2>/dev/null
}
autoload -Uz add-zsh-hook
add-zsh-hook preexec treeship_preexec

treeship_precmd() {
  treeship hook post "$?" 2>/dev/null
}
add-zsh-hook precmd treeship_precmd
# End Treeship shell hook"#;

const BASH_HOOK: &str = r#"# Treeship shell hook -- installed by treeship install
treeship_preexec() {
  treeship hook pre "$BASH_COMMAND" 2>/dev/null
}
trap 'treeship_preexec' DEBUG

PROMPT_COMMAND="treeship hook post \$? 2>/dev/null; ${PROMPT_COMMAND}"
# End Treeship shell hook"#;

const FISH_HOOK: &str = r#"# Treeship shell hook -- installed by treeship install
function treeship_preexec --on-event fish_preexec
  treeship hook pre "$argv" 2>/dev/null
end

function treeship_postexec --on-event fish_postexec
  treeship hook post $status 2>/dev/null
end
# End Treeship shell hook"#;

#[derive(Debug, Clone, Copy)]
enum Shell {
    Zsh,
    Bash,
    Fish,
}

impl Shell {
    fn detect() -> Option<Self> {
        let shell_env = std::env::var("SHELL").unwrap_or_default();
        if shell_env.contains("zsh") {
            Some(Shell::Zsh)
        } else if shell_env.contains("bash") {
            Some(Shell::Bash)
        } else if shell_env.contains("fish") {
            Some(Shell::Fish)
        } else {
            None
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Shell::Zsh => "zsh",
            Shell::Bash => "bash",
            Shell::Fish => "fish",
        }
    }

    fn config_path(&self) -> Option<PathBuf> {
        let home = home::home_dir()?;
        Some(match self {
            Shell::Zsh => home.join(".zshrc"),
            Shell::Bash => home.join(".bashrc"),
            Shell::Fish => home.join(".config").join("fish").join("config.fish"),
        })
    }

    fn hook_text(&self) -> &'static str {
        match self {
            Shell::Zsh => ZSH_HOOK,
            Shell::Bash => BASH_HOOK,
            Shell::Fish => FISH_HOOK,
        }
    }
}

/// Check if the hook is already installed in a config file.
fn already_installed(path: &PathBuf) -> bool {
    if let Ok(contents) = std::fs::read_to_string(path) {
        contents.contains(MARKER_START)
    } else {
        false
    }
}

/// Remove treeship hook lines from a config file.
fn remove_hook(path: &PathBuf) -> Result<bool, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(false);
    }
    let contents = std::fs::read_to_string(path)?;
    if !contents.contains(MARKER_START) {
        return Ok(false);
    }

    let mut result = String::new();
    let mut skipping = false;

    for line in contents.lines() {
        if line.trim() == MARKER_START.trim() {
            skipping = true;
            continue;
        }
        if line.trim() == MARKER_END.trim() {
            skipping = false;
            continue;
        }
        if !skipping {
            result.push_str(line);
            result.push('\n');
        }
    }

    // Trim trailing blank lines that we may have added
    let trimmed = result.trim_end().to_string() + "\n";
    std::fs::write(path, trimmed)?;

    Ok(true)
}

pub fn install(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let shell = Shell::detect().ok_or(
        "could not detect shell from $SHELL -- set SHELL to /bin/zsh, /bin/bash, or /usr/bin/fish",
    )?;

    let config_path = shell.config_path().ok_or("could not determine home directory")?;

    if already_installed(&config_path) {
        printer.info(&format!(
            "{} Shell hooks already installed ({})",
            printer.green("ok"),
            config_path.display(),
        ));
        return Ok(());
    }

    // Ensure parent directory exists (relevant for fish)
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Append hook to shell config
    let mut contents = if config_path.exists() {
        std::fs::read_to_string(&config_path)?
    } else {
        String::new()
    };

    if !contents.ends_with('\n') && !contents.is_empty() {
        contents.push('\n');
    }
    contents.push('\n');
    contents.push_str(shell.hook_text());
    contents.push('\n');

    std::fs::write(&config_path, &contents)?;

    printer.blank();
    printer.success("Shell hooks installed", &[
        ("shell", &format!("{} (~{})", shell.name(), config_path.file_name().unwrap_or_default().to_string_lossy())),
    ]);
    printer.blank();
    printer.info("  From now on, matching commands are attested automatically.");
    printer.info("  Edit .treeship/config.yaml to change which commands are attested.");
    printer.blank();
    printer.hint("treeship log --follow  to watch receipts as they're created");
    printer.blank();

    Ok(())
}

pub fn uninstall(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let shell = Shell::detect().ok_or(
        "could not detect shell from $SHELL",
    )?;

    let config_path = shell.config_path().ok_or("could not determine home directory")?;

    if remove_hook(&config_path)? {
        printer.blank();
        printer.success("Shell hooks removed", &[
            ("shell", &format!("{} (~{})", shell.name(), config_path.file_name().unwrap_or_default().to_string_lossy())),
        ]);
        printer.blank();
    } else {
        printer.info("  No Treeship hooks found to remove.");
    }

    Ok(())
}
