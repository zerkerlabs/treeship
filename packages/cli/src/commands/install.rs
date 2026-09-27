use std::path::PathBuf;

use crate::printer::Printer;

const MARKER_START: &str = "# Treeship shell hook -- installed by treeship install";
const MARKER_END: &str = "# End Treeship shell hook";

/// Resolve the absolute path to the current treeship binary for use in
/// shell hooks. Using an absolute path prevents PATH hijacking attacks
/// where a malicious binary could intercept all attested commands.
fn treeship_binary_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "treeship".to_string())
}

fn zsh_hook(bin: &str) -> String {
    format!(
        r#"# Treeship shell hook -- installed by treeship install
treeship_preexec() {{
  TREESHIP_LAST_CMD="$1"
  {bin} hook pre -- "$1" 2>/dev/null
}}
autoload -Uz add-zsh-hook
add-zsh-hook preexec treeship_preexec

treeship_precmd() {{
  {bin} hook post "$?" -- "$TREESHIP_LAST_CMD" 2>/dev/null
  unset TREESHIP_LAST_CMD
}}
add-zsh-hook precmd treeship_precmd
# End Treeship shell hook"#,
        bin = bin
    )
}

fn bash_hook(bin: &str) -> String {
    format!(
        r#"# Treeship shell hook -- installed by treeship install
treeship_preexec() {{
  case "$BASH_COMMAND" in "{bin} hook post "*) return ;; esac
  TREESHIP_LAST_CMD="$BASH_COMMAND"
  {bin} hook pre -- "$BASH_COMMAND" 2>/dev/null
}}
trap 'treeship_preexec' DEBUG

PROMPT_COMMAND="{bin} hook post \$? -- \"\$TREESHIP_LAST_CMD\" 2>/dev/null; ${{PROMPT_COMMAND}}"
# End Treeship shell hook"#,
        bin = bin
    )
}

fn fish_hook(bin: &str) -> String {
    format!(
        r#"# Treeship shell hook -- installed by treeship install
function treeship_preexec --on-event fish_preexec
  {bin} hook pre -- "$argv" 2>/dev/null
end

function treeship_postexec --on-event fish_postexec
  {bin} hook post $status -- "$argv" 2>/dev/null
end
# End Treeship shell hook"#,
        bin = bin
    )
}

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

    fn hook_text(&self, bin_path: &str) -> String {
        match self {
            Shell::Zsh => zsh_hook(bin_path),
            Shell::Bash => bash_hook(bin_path),
            Shell::Fish => fish_hook(bin_path),
        }
    }
}

/// The installed hook block, marker lines included, when one is present.
fn installed_block(path: &PathBuf) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    let start = contents.find(MARKER_START)?;
    let end = contents[start..].find(MARKER_END)? + start + MARKER_END.len();
    Some(contents[start..end].to_string())
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
    crate::safe_fs::write_home_path(path, trimmed.as_bytes(), 0o644)?;

    Ok(true)
}

pub fn install(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let shell = Shell::detect().ok_or(
        "could not detect shell from $SHELL -- set SHELL to /bin/zsh, /bin/bash, or /usr/bin/fish",
    )?;

    let config_path = shell
        .config_path()
        .ok_or("could not determine home directory")?;

    // Use absolute path to the treeship binary to prevent PATH hijacking
    let bin_path = treeship_binary_path();

    // An installed block from an older release is replaced with the current
    // one (the 0.31.11 hooks pass the command to `hook post`); an identical
    // block is left alone.
    let mut updated = false;
    if let Some(block) = installed_block(&config_path) {
        if block.trim() == shell.hook_text(&bin_path).trim() {
            printer.info(&format!(
                "{} Shell hooks already installed ({})",
                printer.green("ok"),
                config_path.display(),
            ));
            return Ok(());
        }
        remove_hook(&config_path)?;
        updated = true;
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
    contents.push_str(&shell.hook_text(&bin_path));
    contents.push('\n');

    crate::safe_fs::write_home_path(&config_path, contents.as_bytes(), 0o644)?;

    printer.blank();
    printer.success(
        if updated {
            "Shell hooks updated"
        } else {
            "Shell hooks installed"
        },
        &[(
            "shell",
            &format!(
                "{} (~{})",
                shell.name(),
                config_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
            ),
        )],
    );
    printer.blank();
    printer.info("  From now on, matching commands are attested automatically.");
    printer.info("  Edit .treeship/config.yaml to change which commands are attested.");
    printer.blank();
    printer.hint("treeship log --follow  to watch receipts as they're created");
    printer.blank();

    Ok(())
}

pub fn uninstall(printer: &Printer) -> Result<(), Box<dyn std::error::Error>> {
    let shell = Shell::detect().ok_or("could not detect shell from $SHELL")?;

    let config_path = shell
        .config_path()
        .ok_or("could not determine home directory")?;

    if remove_hook(&config_path)? {
        printer.blank();
        printer.success(
            "Shell hooks removed",
            &[(
                "shell",
                &format!(
                    "{} (~{})",
                    shell.name(),
                    config_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                ),
            )],
        );
        printer.blank();
    } else {
        printer.info("  No Treeship hooks found to remove.");
    }

    Ok(())
}
