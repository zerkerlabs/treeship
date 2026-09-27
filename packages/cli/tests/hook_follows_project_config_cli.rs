//! The Claude Code hook records into the workspace of the project it runs
//! in (the `.treeship/config.json` beside the `config.yaml` it found), not
//! into whatever an exported TREESHIP_CONFIG names. Track 2 of the 0.31.10
//! retest: a session started with `--config` in the project, TREESHIP_CONFIG
//! exported to another store, and the hook's receipt landed in the other
//! store.

use std::process::{Command, Output};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

fn run(
    dir: &std::path::Path,
    home: &std::path::Path,
    env: &[(&str, &str)],
    args: &[&str],
) -> Output {
    let mut cmd = Command::new(cli_path());
    cmd.current_dir(dir)
        .env("HOME", home)
        .env_remove("TREESHIP_CONFIG")
        .args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().expect("run treeship")
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

#[test]
fn hook_post_records_into_the_projects_workspace_not_the_exported_config() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let project_cfg = project.path().join(".treeship/config.json");
    let other_cfg = other.path().join(".treeship/config.json");
    for (dir, cfg) in [(project.path(), &project_cfg), (other.path(), &other_cfg)] {
        let out = run(
            dir,
            home.path(),
            &[],
            &["init", "--name", "w", "--config", &cfg.to_string_lossy()],
        );
        assert!(out.status.success(), "{}", text(&out));
    }
    let out = run(
        project.path(),
        home.path(),
        &[],
        &[
            "session",
            "start",
            "--name",
            "s",
            "--config",
            &project_cfg.to_string_lossy(),
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    let before_project = artifacts(project.path());
    let before_other = artifacts(other.path());

    // The hook runs as Claude Code runs it: from the project, no --config,
    // with the user's shell environment (TREESHIP_CONFIG pointing elsewhere).
    let env = [("TREESHIP_CONFIG", other_cfg.to_str().unwrap())];
    let out = run(
        project.path(),
        home.path(),
        &env,
        &["hook", "pre", "git commit -m x"],
    );
    assert!(out.status.success(), "{}", text(&out));
    let out = run(project.path(), home.path(), &env, &["hook", "post", "0"]);
    assert!(out.status.success(), "{}", text(&out));

    assert_eq!(
        artifacts(project.path()),
        before_project + 1,
        "the hook's receipt did not land in the project's store:\n{}",
        text(&out)
    );
    assert_eq!(
        artifacts(other.path()),
        before_other,
        "the hook's receipt landed in the store TREESHIP_CONFIG named"
    );
}
