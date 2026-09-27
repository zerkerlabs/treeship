use std::path::{Path, PathBuf};

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
  {bin} --quiet hook pre -- "$1" 2>/dev/null
}}
autoload -Uz add-zsh-hook
add-zsh-hook preexec treeship_preexec

treeship_precmd() {{
  {bin} --quiet hook post "$?" -- "${{TREESHIP_LAST_CMD-}}" 2>/dev/null
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
# The DEBUG trap fires for every simple command; only the first one after
# a prompt is the line the person typed. That line comes from history when
# history just added it (a compound `a && b` arrives whole); a line history
# did not record (ignorespace, `set +o history`) is taken from BASH_COMMAND,
# never from the previous history entry.
treeship_precmd() {{
  {bin} --quiet hook post "$1" -- "${{TREESHIP_LAST_CMD-}}" 2>/dev/null
  unset TREESHIP_LAST_CMD
  TREESHIP_HIST_N=$(HISTTIMEFORMAT= builtin history 1 2>/dev/null)
  TREESHIP_HIST_N="${{TREESHIP_HIST_N#"${{TREESHIP_HIST_N%%[![:space:]]*}}"}}"
  TREESHIP_HIST_N="${{TREESHIP_HIST_N%%[![:digit:]]*}}"
}}
treeship_preexec() {{
  case "$BASH_COMMAND" in "treeship_precmd "*) unset TREESHIP_AT_PROMPT; return ;; esac
  [ -n "${{TREESHIP_AT_PROMPT-}}" ] || return
  unset TREESHIP_AT_PROMPT
  local line num
  line=$(HISTTIMEFORMAT= builtin history 1 2>/dev/null)
  line="${{line#"${{line%%[![:space:]]*}}"}}"
  num="${{line%%[![:digit:]]*}}"
  line="${{line#"$num"}}"
  line="${{line#"${{line%%[![:space:]]*}}"}}"
  if [ -z "$num" ] || [ "$num" = "${{TREESHIP_HIST_N-}}" ]; then line="$BASH_COMMAND"; fi
  TREESHIP_LAST_CMD="$line"
  {bin} --quiet hook pre -- "$line" 2>/dev/null
}}
trap 'treeship_preexec' DEBUG

PROMPT_COMMAND="treeship_precmd \$?; ${{PROMPT_COMMAND:+$PROMPT_COMMAND; }}TREESHIP_AT_PROMPT=1"
# End Treeship shell hook"#,
        bin = bin
    )
}

fn fish_hook(bin: &str) -> String {
    format!(
        r#"# Treeship shell hook -- installed by treeship install
function treeship_preexec --on-event fish_preexec
  {bin} --quiet hook pre -- "$argv" 2>/dev/null
end

function treeship_postexec --on-event fish_postexec
  {bin} --quiet hook post $status -- "$argv" 2>/dev/null
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

/// The byte range of the installed hook block in `contents`, marker lines
/// included, when one is present.
fn block_range(contents: &str) -> Option<std::ops::Range<usize>> {
    let start = contents.find(MARKER_START)?;
    let end = contents[start..].find(MARKER_END)? + start + MARKER_END.len();
    Some(start..end)
}

/// The installed hook block, marker lines included, when one is present.
fn installed_block(path: &PathBuf) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    let range = block_range(&contents)?;
    Some(contents[range].to_string())
}

/// Replace the installed block in `contents` with `hook`, touching no other
/// byte: the block keeps its place, the rest of the file its line endings,
/// trailing whitespace and (missing) final newline. A block written in
/// CRLF stays CRLF.
fn replace_block(contents: &str, hook: &str) -> Option<String> {
    let range = block_range(contents)?;
    let old = &contents[range.clone()];
    let hook = if old.contains("\r\n") {
        hook.replace('\n', "\r\n")
    } else {
        hook.to_string()
    };
    Some(format!(
        "{}{}{}",
        &contents[..range.start],
        hook,
        &contents[range.end..]
    ))
}

/// Remove the installed block, the line ending after it and the blank line
/// `install` put before it, nothing else.
fn without_block(contents: &str) -> Option<String> {
    let range = block_range(contents)?;
    let mut end = range.end;
    let rest = &contents[end..];
    if rest.starts_with("\r\n") {
        end += 2;
    } else if rest.starts_with('\n') {
        end += 1;
    }
    let mut start = range.start;
    let before = &contents[..start];
    if before.ends_with("\r\n\r\n") {
        start -= 2;
    } else if before.ends_with("\n\n") {
        start -= 1;
    }
    Some(format!("{}{}", &contents[..start], &contents[end..]))
}

/// Remove treeship hook lines from a config file.
fn remove_hook(path: &PathBuf) -> Result<bool, Box<dyn std::error::Error>> {
    if !path.exists() {
        return Ok(false);
    }
    let contents = std::fs::read_to_string(path)?;
    let Some(result) = without_block(&contents) else {
        return Ok(false);
    };
    crate::safe_fs::write_home_path(path, result.as_bytes(), 0o644)?;

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
    if let Some(block) = installed_block(&config_path) {
        if block.replace("\r\n", "\n").trim() == shell.hook_text(&bin_path).trim() {
            printer.info(&format!(
                "{} Shell hooks already installed ({})",
                printer.green("ok"),
                config_path.display(),
            ));
            return Ok(());
        }
        // Only the bytes between the markers change.
        let contents = std::fs::read_to_string(&config_path)?;
        let replaced = replace_block(&contents, &shell.hook_text(&bin_path))
            .ok_or("the installed hook block has no end marker")?;
        crate::safe_fs::write_home_path(&config_path, replaced.as_bytes(), 0o644)?;
        print_installed(true, shell, &config_path, printer);
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
    contents.push_str(&shell.hook_text(&bin_path));
    contents.push('\n');

    crate::safe_fs::write_home_path(&config_path, contents.as_bytes(), 0o644)?;

    printer.blank();
    print_installed(false, shell, &config_path, printer);
    Ok(())
}

fn print_installed(updated: bool, shell: Shell, config_path: &Path, printer: &Printer) {
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
