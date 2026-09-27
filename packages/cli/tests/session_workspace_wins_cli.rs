//! An active session's workspace is where session commands record, even with
//! TREESHIP_CONFIG exported to another store. The Claude Code plugin's hooks
//! appended events to the project's session but signed approvals and
//! attestations into the other store (0.31.11 re-test, N-12 / N-36).

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
fn the_active_sessions_workspace_wins_over_an_exported_treeship_config() {
    let home = tempfile::tempdir().unwrap();
    let project = home.path().join("proj");
    let sub = project.join("src");
    std::fs::create_dir_all(&sub).unwrap();
    let other = tempfile::tempdir().unwrap();
    let project_cfg = project.join(".treeship/config.json");
    let other_cfg = other.path().join(".treeship/config.json");
    for (dir, cfg) in [
        (project.as_path(), &project_cfg),
        (other.path(), &other_cfg),
    ] {
        let out = run(
            dir,
            home.path(),
            &[],
            &["init", "--name", "w", "--config", &cfg.to_string_lossy()],
        );
        assert!(out.status.success(), "{}", text(&out));
    }
    let env = [("TREESHIP_CONFIG", other_cfg.to_str().unwrap())];
    let before_other = artifacts(other.path());

    // The plugin's SessionStart hook: no --config, the variable exported.
    let out = run(
        &project,
        home.path(),
        &env,
        &["session", "start", "--name", "s"],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(project.join(".treeship/session.json").is_file());
    let after_start = artifacts(&project);
    assert!(
        after_start >= 1,
        "the session root did not land in the project store"
    );

    // What the hooks run from a subdirectory: an event, a chained receipt,
    // an approval, halt list, session status.
    let out = run(
        &sub,
        home.path(),
        &env,
        &[
            "session",
            "event",
            "--type",
            "agent.called_tool",
            "--tool",
            "Read",
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    let out = run(
        &sub,
        home.path(),
        &env,
        &[
            "attest",
            "action",
            "--actor",
            "agent://claude",
            "--action",
            "approved: deploy",
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    let out = run(
        &sub,
        home.path(),
        &env,
        &["halt", "list", "--format", "json"],
    );
    assert!(out.status.success(), "{}", text(&out));
    let out = run(
        &sub,
        home.path(),
        &env,
        &["session", "status", "--format", "json"],
    );
    assert!(out.status.success(), "{}", text(&out));

    assert!(
        artifacts(&project) > after_start,
        "the attestation did not land in the session's workspace:\n{}",
        text(&out)
    );
    assert_eq!(
        artifacts(other.path()),
        before_other,
        "the exported TREESHIP_CONFIG store received the session's artifacts"
    );

    let out = run(
        &sub,
        home.path(),
        &env,
        &["session", "close", "--format", "json"],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(!project.join(".treeship/session.json").exists());
    assert_eq!(artifacts(other.path()), before_other);

    // With no active session, the variable applies as before.
    let out = run(
        &sub,
        home.path(),
        &env,
        &["attest", "action", "--actor", "agent://x", "--action", "y"],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(artifacts(other.path()), before_other + 1, "{}", text(&out));
}
