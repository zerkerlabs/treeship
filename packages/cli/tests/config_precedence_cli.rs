//! Which workspace a command uses. An explicit `--config` or
//! `TREESHIP_CONFIG` always wins over discovery; discovery never climbs
//! above HOME; and a discovered project stub that extends a config outside
//! this HOME is refused. A test harness with HOME=$(mktemp -d) once signed
//! a fixture with the user's real key into the real store, because the
//! stub in the working tree named that keystore by absolute path.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

fn run(cwd: &Path, home: &Path, env_config: Option<&Path>, args: &[&str]) -> Output {
    let mut cmd = Command::new(cli_path());
    cmd.current_dir(cwd)
        .env("HOME", home)
        .env_remove("TREESHIP_CONFIG")
        .args(args);
    if let Some(c) = env_config {
        cmd.env("TREESHIP_CONFIG", c);
    }
    cmd.output().unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn artifacts(home: &Path) -> usize {
    std::fs::read_dir(home.join(".treeship/artifacts"))
        .map(|d| {
            d.flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("art_"))
                .count()
        })
        .unwrap_or(0)
}

/// An "account": a HOME with a global workspace and a project dir whose
/// stub extends it (what `treeship init` in a project leaves behind).
fn account() -> (tempfile::TempDir, PathBuf) {
    let home = tempfile::tempdir().unwrap();
    let proj = home.path().join("work").join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    let out = run(&proj, home.path(), None, &["init", "--name", "acct"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(std::fs::read_to_string(proj.join(".treeship/config.json"))
        .unwrap()
        .contains("extends"));
    (home, proj)
}

#[test]
fn an_explicit_config_wins_over_a_project_stub_in_cwd() {
    let (real_home, proj) = account();
    let other = tempfile::tempdir().unwrap();
    let other_cfg = other.path().join(".treeship/config.json");
    let out = run(
        other.path(),
        other.path(),
        None,
        &[
            "init",
            "--config",
            other_cfg.to_str().unwrap(),
            "--name",
            "other",
        ],
    );
    assert!(out.status.success(), "{}", text(&out));

    // TREESHIP_CONFIG, from inside the project directory.
    let out = run(
        &proj,
        other.path(),
        Some(&other_cfg),
        &[
            "attest",
            "action",
            "--actor",
            "agent://a",
            "--action",
            "env",
        ],
    );
    assert!(out.status.success(), "{}", text(&out));
    // --config, from inside the project directory.
    let out = run(
        &proj,
        other.path(),
        None,
        &[
            "attest",
            "action",
            "--actor",
            "agent://a",
            "--action",
            "flag",
            "--config",
            other_cfg.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", text(&out));

    assert_eq!(
        artifacts(other.path()),
        2,
        "the explicit workspace did not receive the artifacts"
    );
    assert_eq!(
        artifacts(real_home.path()),
        0,
        "the account's real store was written to"
    );
}

#[test]
fn a_stub_extending_another_home_is_refused_under_a_different_home() {
    let (real_home, proj) = account();
    let other = tempfile::tempdir().unwrap();
    // No override, a different HOME, cwd inside the project: discovery finds
    // the stub, whose `extends` names the real account's keystore.
    let out = run(
        &proj,
        other.path(),
        None,
        &[
            "attest",
            "action",
            "--actor",
            "agent://a",
            "--action",
            "leak",
        ],
    );
    assert!(
        !out.status.success(),
        "signed with another account's key:\n{}",
        text(&out)
    );
    assert!(text(&out).contains("outside this HOME"), "{}", text(&out));
    assert_eq!(
        artifacts(real_home.path()),
        0,
        "the account's real store was written to"
    );
    assert!(!other.path().join(".treeship/artifacts").exists());
}

#[test]
fn discovery_still_works_for_the_accounts_own_projects_and_stops_at_home() {
    let (home, proj) = account();
    // The account's own project: fine, signs into the account's store.
    let out = run(
        &proj,
        home.path(),
        None,
        &["attest", "action", "--actor", "agent://a", "--action", "ok"],
    );
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(artifacts(home.path()), 1);

    // A stub in a parent of HOME is not this user's project: a fresh dir
    // under HOME with a stub two levels above HOME is not found.
    let outer = tempfile::tempdir().unwrap();
    let nested_home = outer.path().join("h");
    let cwd = nested_home.join("code");
    std::fs::create_dir_all(&cwd).unwrap();
    std::fs::create_dir_all(outer.path().join(".treeship")).unwrap();
    std::fs::write(
        outer.path().join(".treeship/config.json"),
        b"{\"extends\": \"/nowhere\", \"project\": true}",
    )
    .unwrap();
    let out = run(&cwd, &nested_home, None, &["status"]);
    let t = text(&out);
    assert!(!t.contains("/nowhere"), "discovery climbed above HOME: {t}");
}
