//! The shell snippets `treeship install` writes, driven through real
//! interactive shells. bash: the DEBUG trap fires once per simple command,
//! so a compound line must reach `hook post` whole, once, and an empty Enter
//! must record nothing. zsh: `setopt nounset` must not print
//! "parameter not set" on an empty Enter.

use std::io::Write;
use std::process::{Command, Output, Stdio};

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

fn artifacts(store: &std::path::Path) -> usize {
    std::fs::read_dir(store.join(".treeship/artifacts"))
        .map(|d| {
            d.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("art_"))
                .count()
        })
        .unwrap_or(0)
}

/// A HOME with the hook installed for `shell`, and a project with the default
/// rules (which match `git commit`).
fn setup(shell: &str) -> (tempfile::TempDir, tempfile::TempDir) {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let cfg = project.path().join(".treeship/config.json");
    let out = Command::new(cli_path())
        .current_dir(project.path())
        .env("HOME", home.path())
        .env_remove("TREESHIP_CONFIG")
        .args(["init", "--name", "w", "--config", &cfg.to_string_lossy()])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let out = Command::new(cli_path())
        .current_dir(project.path())
        .env("HOME", home.path())
        .env("SHELL", shell)
        .env_remove("TREESHIP_CONFIG")
        .arg("install")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    (home, project)
}

fn drive(mut cmd: Command, input: &str) -> Output {
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn shell");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn bash_records_a_compound_line_once_and_an_empty_enter_records_nothing() {
    let (home, project) = setup("/bin/bash");
    let rc = home.path().join(".bashrc");
    let mut cmd = Command::new("bash");
    cmd.current_dir(project.path())
        .env("HOME", home.path())
        .env("HISTFILE", home.path().join(".bash_history"))
        .env_remove("TREESHIP_CONFIG")
        .env_remove("PROMPT_COMMAND")
        .args(["--noprofile", "--rcfile", rc.to_str().unwrap(), "-i"]);
    // Two empty lines after the compound line: each runs PROMPT_COMMAND and
    // must not turn the previous line's history entry into a second receipt.
    let out = drive(cmd, "git commit -m x && echo ok\n\n\nexit\n");
    let all = text(&out);
    assert_eq!(
        artifacts(project.path()),
        1,
        "the compound line must be recorded exactly once:\n{all}"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("stale hook state") && !stdout.contains("art_"),
        "the hook printed into the prompt:\n{all}"
    );
    assert!(all.contains("ok"), "{all}");

    // A line that matches nothing records nothing, and the pending state of
    // an earlier matched line is not charged to it.
    let mut cmd = Command::new("bash");
    cmd.current_dir(project.path())
        .env("HOME", home.path())
        .env("HISTFILE", home.path().join(".bash_history"))
        .env_remove("TREESHIP_CONFIG")
        .env_remove("PROMPT_COMMAND")
        .args(["--noprofile", "--rcfile", rc.to_str().unwrap(), "-i"]);
    let out = drive(cmd, "echo one\necho two && echo three\nexit\n");
    assert_eq!(artifacts(project.path()), 1, "{}", text(&out));
}

#[test]
fn zsh_with_nounset_stays_quiet_on_an_empty_enter() {
    if Command::new("zsh").arg("--version").output().is_err() {
        eprintln!("zsh not installed; skipping");
        return;
    }
    let (home, project) = setup("/bin/zsh");
    // The hook block went to ~/.zshrc; nounset goes in front of it.
    let rc = home.path().join(".zshrc");
    let block = std::fs::read_to_string(&rc).unwrap();
    std::fs::write(&rc, format!("setopt nounset\n{block}")).unwrap();
    let mut cmd = Command::new("zsh");
    cmd.current_dir(project.path())
        .env("HOME", home.path())
        .env("ZDOTDIR", home.path())
        .env_remove("TREESHIP_CONFIG")
        .arg("-i");
    let out = drive(cmd, "\n\ngit commit -m y && echo ok\n\nexit\n");
    let all = text(&out);
    assert!(
        !all.contains("parameter not set"),
        "nounset tripped on the hook's variables:\n{all}"
    );
    assert_eq!(artifacts(project.path()), 1, "{all}");
}

fn bash_in(home: &std::path::Path, project: &std::path::Path) -> Command {
    let mut cmd = Command::new("bash");
    cmd.current_dir(project)
        .env("HOME", home)
        .env("HISTFILE", home.join(".bash_history"))
        .env_remove("TREESHIP_CONFIG")
        .env_remove("PROMPT_COMMAND")
        .args([
            "--noprofile",
            "--rcfile",
            home.join(".bashrc").to_str().unwrap(),
            "-i",
        ]);
    cmd
}

/// A line history did not record must not inherit the previous entry: with
/// `ignorespace`, ` echo ok` after a matched git line used to be signed as
/// that git commit. Same with history switched off.
#[test]
fn bash_never_signs_a_line_history_did_not_record() {
    let (home, project) = setup("/bin/bash");
    let mut cmd = bash_in(home.path(), project.path());
    cmd.env("HISTCONTROL", "ignorespace");
    let out = drive(
        cmd,
        "git commit -m one && echo ok\n echo ok\n echo ok\nexit\n",
    );
    assert_eq!(
        artifacts(project.path()),
        1,
        "a space-prefixed line was recorded as the earlier git commit:\n{}",
        text(&out)
    );

    let cmd = bash_in(home.path(), project.path());
    let out = drive(
        cmd,
        "set +o history\ngit commit -m two && echo ok\necho ok\ngit commit -m three\nexit\n",
    );
    // Without history the first simple command stands for the line: both
    // git lines are recorded, `echo ok` is not, and nothing is recorded twice.
    assert_eq!(artifacts(project.path()), 3, "{}", text(&out));
}

/// bash rewrites redirections in BASH_COMMAND (`2>/dev/null` becomes
/// `2> /dev/null`); the history line, taken whole, is what was typed.
#[test]
fn bash_records_a_redirected_pipeline_as_typed() {
    let (home, project) = setup("/bin/bash");
    let cmd = bash_in(home.path(), project.path());
    let out = drive(cmd, "git commit -m x 2>/dev/null | cat\nexit\n");
    assert_eq!(artifacts(project.path()), 1, "{}", text(&out));
    let recorded = recorded_commands(project.path());
    assert!(
        recorded
            .iter()
            .any(|c| c == "git commit -m x 2>/dev/null | cat"),
        "the recorded command is not the typed line: {recorded:?}"
    );
}

/// The `command` of every signed action in the project's store, read from
/// the stored DSSE envelopes.
fn recorded_commands(store: &std::path::Path) -> Vec<String> {
    use base64::Engine;
    let mut out = Vec::new();
    for entry in std::fs::read_dir(store.join(".treeship/artifacts"))
        .unwrap()
        .flatten()
    {
        let Ok(raw) = std::fs::read(entry.path()) else {
            continue;
        };
        let Ok(env) = serde_json::from_slice::<serde_json::Value>(&raw) else {
            continue;
        };
        let Some(payload) = env["envelope"]["payload"].as_str() else {
            continue;
        };
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(payload)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload))
            .unwrap_or_default();
        let Ok(stmt) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let cmd = stmt["meta"]["command"]
            .as_str()
            .or_else(|| stmt["predicate"]["meta"]["command"].as_str())
            .or_else(|| stmt["predicate"]["command"].as_str());
        if let Some(c) = cmd {
            out.push(c.to_string());
        } else {
            out.push(String::from_utf8_lossy(&bytes).to_string());
        }
    }
    out
}
