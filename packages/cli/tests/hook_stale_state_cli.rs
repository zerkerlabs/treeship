//! Retest item 8: a `hook pre` whose `hook post` never ran leaves state
//! behind; a later `post` for a different command must not record the old
//! command against the new run.

use std::process::{Command, Output};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

fn run(dir: &std::path::Path, home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(cli_path())
        .current_dir(dir)
        .env("HOME", home)
        .env_remove("TREESHIP_CONFIG")
        .args(args)
        .output()
        .expect("run treeship")
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
fn a_post_for_another_command_drops_stale_pre_state_and_records_nothing() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let cfg = project.path().join(".treeship/config.json");
    let out = run(
        project.path(),
        home.path(),
        &["init", "--name", "w", "--config", &cfg.to_string_lossy()],
    );
    assert!(out.status.success(), "{}", text(&out));

    let out = run(
        project.path(),
        home.path(),
        &["hook", "pre", "git commit -m x"],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(project.path().join(".treeship/.pending_hook").exists());
    let before = artifacts(project.path());

    let out = run(
        project.path(),
        home.path(),
        &["hook", "post", "0", "kubectl apply -f deploy.yaml"],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        artifacts(project.path()),
        before,
        "the stale git commit was recorded against a kubectl run:\n{}",
        text(&out)
    );
    assert!(
        !project.path().join(".treeship/.pending_hook").exists(),
        "stale state was left behind"
    );

    // A matching post still records.
    let out = run(
        project.path(),
        home.path(),
        &["hook", "pre", "git commit -m y"],
    );
    assert!(out.status.success(), "{}", text(&out));
    let out = run(
        project.path(),
        home.path(),
        &["hook", "post", "0", "git commit -m y"],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(artifacts(project.path()), before + 1, "{}", text(&out));
}
