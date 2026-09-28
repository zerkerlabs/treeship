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

/// A harness that sandboxes HOME and TREESHIP_CONFIG but runs from the real
/// user's project must not climb to the real user's session and sign with
/// their key: only a workspace inside the (canonical) HOME qualifies.
#[test]
fn a_session_outside_home_never_outranks_the_sandbox() {
    let real = tempfile::tempdir().unwrap();
    let real_project = real.path().join("project");
    std::fs::create_dir_all(&real_project).unwrap();
    let real_cfg = real_project.join(".treeship/config.json");
    let out = run(
        &real_project,
        real.path(),
        &[],
        &[
            "init",
            "--name",
            "real",
            "--config",
            &real_cfg.to_string_lossy(),
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    let out = run(
        &real_project,
        real.path(),
        &[],
        &["session", "start", "--name", "theirs"],
    );
    assert!(out.status.success(), "{}", text(&out));
    let real_before = artifacts(&real_project);

    let sandbox = tempfile::tempdir().unwrap();
    let sandbox_cfg = sandbox.path().join(".treeship/config.json");
    let out = run(
        sandbox.path(),
        sandbox.path(),
        &[],
        &[
            "init",
            "--name",
            "sandbox",
            "--config",
            &sandbox_cfg.to_string_lossy(),
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    let env = [("TREESHIP_CONFIG", sandbox_cfg.to_str().unwrap())];
    let out = run(
        &real_project,
        sandbox.path(),
        &env,
        &[
            "attest",
            "action",
            "--actor",
            "agent://harness",
            "--action",
            "fixture",
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        artifacts(&real_project),
        real_before,
        "the harness signed into the real user's store"
    );
    assert_eq!(
        artifacts(sandbox.path()),
        1,
        "the fixture did not land in the sandbox:\n{}",
        text(&out)
    );
}

/// A repository cannot plant a real `.treeship/session.json` with
/// `config.json -> ~/.treeship/config.json` to have the global key sign into
/// the global store with its session as the parent.
#[cfg(unix)]
#[test]
fn a_linked_config_beside_a_planted_session_is_refused() {
    let home = tempfile::tempdir().unwrap();
    let global_cfg = home.path().join(".treeship/config.json");
    let out = run(
        home.path(),
        home.path(),
        &[],
        &[
            "init",
            "--name",
            "me",
            "--config",
            &global_cfg.to_string_lossy(),
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    // A real session manifest to plant: start and read one, then close it.
    let out = run(
        home.path(),
        home.path(),
        &[],
        &["session", "start", "--name", "mine"],
    );
    assert!(out.status.success(), "{}", text(&out));
    let manifest = std::fs::read(home.path().join(".treeship/session.json")).unwrap();
    let out = run(home.path(), home.path(), &[], &["session", "close"]);
    assert!(out.status.success(), "{}", text(&out));
    let global_before = artifacts(home.path());

    let repo = home.path().join("evil");
    std::fs::create_dir_all(repo.join(".treeship")).unwrap();
    std::fs::write(repo.join(".treeship/session.json"), &manifest).unwrap();
    std::os::unix::fs::symlink(&global_cfg, repo.join(".treeship/config.json")).unwrap();

    let out = run(
        &repo,
        home.path(),
        &[],
        &[
            "attest",
            "action",
            "--actor",
            "agent://evil",
            "--action",
            "plant",
        ],
    );
    assert!(
        !out.status.success(),
        "a linked config beside a planted session was accepted:\n{}",
        text(&out)
    );
    assert!(
        text(&out).to_lowercase().contains("symlink"),
        "{}",
        text(&out)
    );
    assert_eq!(
        artifacts(home.path()),
        global_before,
        "the global store received the planted attestation"
    );
}
