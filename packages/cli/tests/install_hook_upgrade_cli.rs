//! `treeship install` replaces a hook block from an earlier release with the
//! current one (the 0.31.11 hooks pass the finished command to `hook post`),
//! and leaves a current block alone.

use std::process::{Command, Output};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

const OLD_BLOCK: &str = r#"# Treeship shell hook -- installed by treeship install
treeship_preexec() {
  /old/treeship hook pre "$1" 2>/dev/null
}
autoload -Uz add-zsh-hook
add-zsh-hook preexec treeship_preexec

treeship_precmd() {
  /old/treeship hook post "$?" 2>/dev/null
}
add-zsh-hook precmd treeship_precmd
# End Treeship shell hook"#;

#[test]
fn install_replaces_an_older_hook_block_and_keeps_a_current_one() {
    let home = tempfile::tempdir().unwrap();
    let rc = home.path().join(".zshrc");
    std::fs::write(
        &rc,
        format!("export EDITOR=vi\n\n{OLD_BLOCK}\n\nalias ll='ls -l'\n"),
    )
    .unwrap();
    let run = || {
        Command::new(cli_path())
            .current_dir(home.path())
            .env("HOME", home.path())
            .env("SHELL", "/bin/zsh")
            .env_remove("TREESHIP_CONFIG")
            .arg("install")
            .output()
            .expect("run treeship")
    };

    let out = run();
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("Shell hooks updated"), "{}", text(&out));
    let after = std::fs::read_to_string(&rc).unwrap();
    assert_eq!(after.matches("# Treeship shell hook").count(), 1, "{after}");
    assert!(
        after.contains("export EDITOR=vi") && after.contains("alias ll='ls -l'"),
        "{after}"
    );
    assert!(
        !after.contains("/old/treeship"),
        "the old block survived:\n{after}"
    );
    assert!(
        after.contains(r#"hook post "$?" -- "${TREESHIP_LAST_CMD-}""#),
        "the new hook does not pass the command:\n{after}"
    );
    assert!(after.contains(r#"TREESHIP_LAST_CMD="$1""#), "{after}");

    // A second run finds the current block and changes nothing.
    let out = run();
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("already installed"), "{}", text(&out));
    assert_eq!(std::fs::read_to_string(&rc).unwrap(), after);
}

/// The upgrade touches only the bytes between the markers: a CRLF file stays
/// CRLF byte for byte outside the block, content after the block stays after
/// it, and a missing final newline stays missing.
#[test]
fn install_changes_only_the_block_bytes() {
    let home = tempfile::tempdir().unwrap();
    let rc = home.path().join(".zshrc");
    let before = format!(
        "export EDITOR=vi  \r\n\r\n{}\r\nalias ll='ls -l'\r\n# no final newline",
        OLD_BLOCK.replace('\n', "\r\n")
    );
    std::fs::write(&rc, &before).unwrap();
    let out = Command::new(cli_path())
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("SHELL", "/bin/zsh")
        .env_remove("TREESHIP_CONFIG")
        .arg("install")
        .output()
        .expect("run treeship");
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("Shell hooks updated"), "{}", text(&out));
    let after = std::fs::read_to_string(&rc).unwrap();
    assert!(
        after.starts_with("export EDITOR=vi  \r\n\r\n# Treeship shell hook"),
        "bytes before the block changed:\n{after:?}"
    );
    assert!(
        after.ends_with("# End Treeship shell hook\r\nalias ll='ls -l'\r\n# no final newline"),
        "bytes after the block changed:\n{after:?}"
    );
    assert!(!after.contains("/old/treeship"), "{after}");
    assert!(
        after.contains("hook post \"$?\" -- \"${TREESHIP_LAST_CMD-}\" 2>/dev/null\r\n"),
        "the new block did not take the file's CRLF line endings:\n{after:?}"
    );
    assert!(!after.contains("\n\n"), "a bare LF crept in:\n{after:?}");

    // Uninstall removes the block and its line ending, nothing else.
    let out = Command::new(cli_path())
        .current_dir(home.path())
        .env("HOME", home.path())
        .env("SHELL", "/bin/zsh")
        .env_remove("TREESHIP_CONFIG")
        .arg("uninstall")
        .output()
        .expect("run treeship");
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        std::fs::read_to_string(&rc).unwrap(),
        "export EDITOR=vi  \r\nalias ll='ls -l'\r\n# no final newline",
        "uninstall must also take back the blank line install put before the block"
    );
}

/// Install then uninstall on a file with no final newline gives the file back.
#[test]
fn install_then_uninstall_gives_the_file_back() {
    let home = tempfile::tempdir().unwrap();
    let rc = home.path().join(".zshrc");
    std::fs::write(&rc, "export EDITOR=vi").unwrap();
    let run = |cmd: &str| {
        Command::new(cli_path())
            .current_dir(home.path())
            .env("HOME", home.path())
            .env("SHELL", "/bin/zsh")
            .env_remove("TREESHIP_CONFIG")
            .arg(cmd)
            .output()
            .expect("run treeship")
    };
    assert!(run("install").status.success());
    let with_hook = std::fs::read_to_string(&rc).unwrap();
    assert!(
        with_hook.starts_with("export EDITOR=vi\n\n# Treeship shell hook"),
        "{with_hook:?}"
    );
    assert!(run("uninstall").status.success());
    assert_eq!(std::fs::read_to_string(&rc).unwrap(), "export EDITOR=vi\n");
}
