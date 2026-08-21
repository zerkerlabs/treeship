use std::process::Command;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

/// `treeship init` in a brand-new directory said "already initialized".
///
/// `default_config_path` walks up for a project-local config and falls back to
/// `~/.treeship/config.json` when it finds none. The guard then saw a file at
/// the resolved path and refused — naming the *home* config as though it were
/// this directory's:
///
///     $ cd /a/brand/new/dir && treeship init
///     ✗ already initialized at /Users/you/.treeship/config.json
///
/// Nothing about that directory was initialized. Every command run there then
/// used the home workspace silently, so receipts from unrelated projects
/// shared one store and `--config` was the only way to separate them.
///
/// The walk itself is careful and deliberately skips the global path. It was
/// this guard that conflated "a config exists somewhere" with "this location
/// is initialized".
#[test]
fn init_in_a_fresh_dir_does_not_claim_the_global_workspace_is_this_one() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();

    // A global workspace exists, as it does for any real user.
    let seed = Command::new(cli_path())
        .current_dir(home.path())
        .env("HOME", home.path())
        .args(["init", "--global"])
        .output()
        .expect("run treeship");
    assert!(
        seed.status.success(),
        "seed: {}",
        String::from_utf8_lossy(&seed.stderr)
    );

    // Now init in an unrelated directory that has no workspace of its own.
    let out = Command::new(cli_path())
        .current_dir(project.path())
        .env("HOME", home.path())
        .args(["init"])
        .output()
        .expect("run treeship");

    let msg = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        !msg.contains("already initialized"),
        "a fresh directory is not 'already initialized' because the global \
         config exists: {msg}"
    );
    // It must say what is actually true and give both ways forward, or the
    // reader is left where the old message left them.
    assert!(
        msg.contains("no Treeship workspace here"),
        "the message must say the directory has no workspace: {msg}"
    );
    assert!(
        msg.contains("--config") && msg.contains("--global"),
        "both the project-local and global paths must be offered: {msg}"
    );
}

/// The narrowing must not break the case it was carved out of: re-running
/// init where a workspace really does exist still refuses.
#[test]
fn init_still_refuses_when_this_directory_is_already_initialized() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();

    let run = |args: &[&str]| {
        Command::new(cli_path())
            .current_dir(project.path())
            .env("HOME", home.path())
            .args(args)
            .output()
            .expect("run treeship")
    };

    let first = run(&["init", "--config", ".treeship/config.json"]);
    assert!(
        first.status.success(),
        "first init: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let second = run(&["init", "--config", ".treeship/config.json"]);
    assert!(!second.status.success(), "re-init must still refuse");
    let msg = format!(
        "{}{}",
        String::from_utf8_lossy(&second.stdout),
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(msg.contains("already initialized"), "{msg}");
}
