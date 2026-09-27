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
        after.contains(r#"hook post "$?" -- "$TREESHIP_LAST_CMD""#),
        "the new hook does not pass the command:\n{after}"
    );
    assert!(after.contains(r#"TREESHIP_LAST_CMD="$1""#), "{after}");

    // A second run finds the current block and changes nothing.
    let out = run();
    assert!(out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("already installed"), "{}", text(&out));
    assert_eq!(std::fs::read_to_string(&rc).unwrap(), after);
}
