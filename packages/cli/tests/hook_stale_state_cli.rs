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

fn set_pending_age(project: &std::path::Path, age_ms: u64) {
    let path = project.join(".treeship/.pending_hook");
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    v["start_ms"] = serde_json::json!(now - age_ms);
    std::fs::write(&path, serde_json::to_string(&v).unwrap()).unwrap();
}

/// A hook installed before 0.31.11 passes no command. Its `post` still
/// records fresh state, and drops state older than a day.
#[test]
fn a_post_without_a_command_records_fresh_state_and_drops_day_old_state() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    let cfg = project.path().join(".treeship/config.json");
    let out = run(
        project.path(),
        home.path(),
        &["init", "--name", "w", "--config", &cfg.to_string_lossy()],
    );
    assert!(out.status.success(), "{}", text(&out));
    let before = artifacts(project.path());

    // Fresh state, no command given: recorded, as before.
    let out = run(
        project.path(),
        home.path(),
        &["hook", "pre", "git commit -m a"],
    );
    assert!(out.status.success(), "{}", text(&out));
    let out = run(project.path(), home.path(), &["hook", "post", "0"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(artifacts(project.path()), before + 1, "{}", text(&out));

    // Day-old state, no command given: dropped.
    let out = run(
        project.path(),
        home.path(),
        &["hook", "pre", "git commit -m b"],
    );
    assert!(out.status.success(), "{}", text(&out));
    set_pending_age(project.path(), 25 * 60 * 60 * 1000);
    let out = run(project.path(), home.path(), &["hook", "post", "0"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        artifacts(project.path()),
        before + 1,
        "day-old state was recorded:\n{}",
        text(&out)
    );
    assert!(text(&out).contains("older than 24h"), "{}", text(&out));
    assert!(!project.path().join(".treeship/.pending_hook").exists());

    // The installed hooks pass the command after `--`, so a command that
    // starts with a dash is not read as a flag.
    let out = run(
        project.path(),
        home.path(),
        &["hook", "pre", "--", "-n deploy"],
    );
    assert!(out.status.success(), "{}", text(&out));
    let out = run(
        project.path(),
        home.path(),
        &["hook", "post", "0", "--", "-n deploy"],
    );
    assert!(out.status.success(), "{}", text(&out));
}
