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

/// A repository can ship any `.treeship/config.json`; the shell hook runs
/// on every prompt, so its config must get the same checks as `treeship`
/// discovery. Before this, the hook opened the discovered file as if it
/// were an explicit --config and signed a receipt with the user's global
/// key into a directory the repository chose.
#[test]
fn a_cloned_repositorys_config_gets_the_discovery_checks_in_the_hook() {
    let home = tempfile::tempdir().unwrap();
    let global_cfg = home.path().join(".treeship/config.json");
    let out = run(
        home.path(),
        home.path(),
        &[],
        &[
            "init",
            "--name",
            "victim",
            "--config",
            &global_cfg.to_string_lossy(),
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    let env = [("TREESHIP_CONFIG", global_cfg.to_str().unwrap())];

    // The malicious repo: the user's global keys as keys_dir, a loot dir in
    // the repo as storage_dir, a rule matching every git command, and an
    // active-looking session so the hook prefers the project config.
    let evil = home.path().join("evil");
    std::fs::create_dir_all(evil.join(".treeship")).unwrap();
    std::fs::write(
        evil.join(".treeship/config.yaml"),
        "treeship: { version: 1 }\nsession: { actor: \"agent://attacker-chosen\" }\nattest:\n  commands:\n    - { pattern: \"git *\", label: \"pwned\" }\n",
    )
    .unwrap();
    let mut cfg: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&global_cfg).unwrap()).unwrap();
    cfg["keys_dir"] =
        serde_json::Value::String(home.path().join(".treeship/keys").to_string_lossy().into());
    cfg["storage_dir"] = serde_json::Value::String(evil.join("loot").to_string_lossy().into());
    std::fs::write(
        evil.join(".treeship/config.json"),
        serde_json::to_vec_pretty(&cfg).unwrap(),
    )
    .unwrap();
    std::fs::write(
        evil.join(".treeship/session.json"),
        b"{\"session_id\":\"ssn_fake\"}",
    )
    .unwrap();

    let out = run(&evil, home.path(), &env, &["hook", "pre", "git status"]);
    assert!(out.status.success(), "{}", text(&out));
    let out = run(&evil, home.path(), &env, &["hook", "post", "0"]);
    assert!(
        !out.status.success(),
        "the hook recorded with a repository-chosen config:\n{}",
        text(&out)
    );
    assert!(text(&out).contains("outside"), "{}", text(&out));
    assert!(
        !evil.join("loot").exists(),
        "a receipt was written into the repository's loot dir"
    );
    assert_eq!(artifacts(home.path()), 0, "the global store was written to");

    // A symlinked .treeship is refused the same way.
    let real = home.path().join("real");
    std::fs::create_dir_all(real.join(".treeship")).unwrap();
    std::fs::write(real.join(".treeship/config.yaml"), "treeship: { version: 1 }\nsession: { actor: \"agent://x\" }\nattest:\n  commands:\n    - { pattern: \"git *\", label: \"x\" }\n").unwrap();
    std::fs::write(
        real.join(".treeship/config.json"),
        serde_json::to_vec_pretty(&cfg).unwrap(),
    )
    .unwrap();
    std::fs::write(real.join(".treeship/session.json"), b"{}").unwrap();
    let link = home.path().join("link");
    std::fs::create_dir_all(&link).unwrap();
    std::os::unix::fs::symlink(real.join(".treeship"), link.join(".treeship")).unwrap();
    // Either hook refuses the link (pre writes no state through it; post
    // never opens a store through it); what matters is that nothing lands.
    let pre = run(&link, home.path(), &env, &["hook", "pre", "git log"]);
    let post = run(&link, home.path(), &env, &["hook", "post", "0"]);
    assert!(
        !pre.status.success() || !post.status.success(),
        "a linked .treeship was followed:\n{}\n{}",
        text(&pre),
        text(&post)
    );
    assert!(!real.join("loot").exists());
    assert_eq!(artifacts(home.path()), 0);
}

/// Without an active session in the project, the documented precedence
/// holds: TREESHIP_CONFIG beats discovery.
#[test]
fn without_a_session_in_the_project_the_environment_still_wins() {
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
    let env = [("TREESHIP_CONFIG", other_cfg.to_str().unwrap())];
    let before_other = artifacts(other.path());
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
        artifacts(other.path()),
        before_other + 1,
        "TREESHIP_CONFIG did not win with no session in the project"
    );
    assert_eq!(artifacts(project.path()), 0);
}
