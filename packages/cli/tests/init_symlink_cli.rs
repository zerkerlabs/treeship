//! A repository's `.treeship` cannot point `treeship init` at the user's
//! own files: neither the directory nor the files inside it are followed
//! when they are symlinks.

use std::process::{Command, Output};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

struct Repo {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
}

impl Repo {
    fn new() -> Self {
        Self {
            home: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        }
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(cli_path())
            .current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(args)
            .output()
            .unwrap()
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[cfg(unix)]
#[test]
fn a_linked_treeship_directory_is_refused_and_its_target_untouched() {
    let repo = Repo::new();
    let docker = repo.home.path().join(".docker");
    std::fs::create_dir_all(&docker).unwrap();
    std::fs::write(docker.join("config.json"), b"{\"auths\":{\"keep\":1}}").unwrap();
    std::os::unix::fs::symlink(&docker, repo.work.path().join(".treeship")).unwrap();

    for args in [
        vec!["init", "--name", "x"],
        vec!["init", "--force", "--name", "x"],
    ] {
        let out = repo.run(&args);
        assert!(
            !out.status.success(),
            "`{}` succeeded through a linked .treeship:\n{}",
            args.join(" "),
            text(&out)
        );
    }
    assert_eq!(
        std::fs::read(docker.join("config.json")).unwrap(),
        b"{\"auths\":{\"keep\":1}}"
    );
    assert!(
        !docker.join("keys").exists()
            && !docker.join("artifacts").exists()
            && !docker.join("config.yaml").exists(),
        "init wrote into the link target: {:?}",
        std::fs::read_dir(&docker)
            .unwrap()
            .flatten()
            .map(|e| e.file_name())
            .collect::<Vec<_>>()
    );
}

#[cfg(unix)]
#[test]
fn linked_config_files_inside_treeship_are_refused() {
    for name in ["config.yaml", "config.json"] {
        let repo = Repo::new();
        let victim = repo.home.path().join("authorized_keys");
        std::fs::write(&victim, b"ssh-ed25519 AAAA victim").unwrap();
        let ts = repo.work.path().join(".treeship");
        std::fs::create_dir_all(&ts).unwrap();
        std::os::unix::fs::symlink(&victim, ts.join(name)).unwrap();
        let out = repo.run(&["init", "--force", "--name", "x"]);
        assert!(
            !out.status.success(),
            "{name}: init wrote through the link:\n{}",
            text(&out)
        );
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"ssh-ed25519 AAAA victim",
            "{name}"
        );
    }
}

#[test]
fn a_plain_repository_still_initialises() {
    let repo = Repo::new();
    let out = repo.run(&["init", "--name", "x"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(repo.work.path().join(".treeship/config.yaml").exists());
}

#[cfg(unix)]
#[test]
fn template_apply_never_writes_through_a_linked_config_yaml() {
    let repo = Repo::new();
    let out = repo.run(&["init", "--name", "x"]);
    assert!(out.status.success(), "{}", text(&out));
    let victim = repo.home.path().join("authorized_keys");
    std::fs::write(&victim, b"ssh-ed25519 AAAA victim").unwrap();
    let yaml = repo.work.path().join(".treeship").join("config.yaml");
    std::fs::remove_file(&yaml).unwrap();
    std::os::unix::fs::symlink(&victim, &yaml).unwrap();
    let out = repo.run(&["template", "apply", "github-contributor"]);
    assert!(
        !out.status.success(),
        "template apply wrote through the link:\n{}",
        text(&out)
    );
    assert_eq!(std::fs::read(&victim).unwrap(), b"ssh-ed25519 AAAA victim");
}

/// A repository initialised as a workspace of its own (a plain `init`
/// makes a stub that extends the global config, whose stores live under
/// `$HOME`), with `home` standing in for the user's real files.
fn initialised() -> Repo {
    let repo = Repo::new();
    let config = repo.work.path().join(".treeship").join("config.json");
    let out = repo.run(&["init", "--name", "x", "--config", &config.to_string_lossy()]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        repo.work
            .path()
            .join(".treeship")
            .join("config.yaml")
            .exists(),
        "init --config inside the repository did not write config.yaml"
    );
    repo
}

fn names_in(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(unix)]
#[test]
fn hook_pre_never_writes_pending_state_through_a_link() {
    let repo = initialised();
    let victim = repo.home.path().join("authorized_keys");
    std::fs::write(&victim, b"ssh-ed25519 AAAA victim").unwrap();
    let ts = repo.work.path().join(".treeship");
    std::os::unix::fs::symlink(&victim, ts.join(".pending_hook")).unwrap();
    // `git commit*` is a rule in the default config.yaml, so the pre-hook
    // records pending state for it.
    let out = repo.run(&["hook", "pre", "git commit -m x"]);
    assert!(
        !out.status.success(),
        "hook pre wrote through the link:\n{}",
        text(&out)
    );
    assert_eq!(std::fs::read(&victim).unwrap(), b"ssh-ed25519 AAAA victim");
    assert!(
        ts.join(".pending_hook").is_symlink(),
        "the link was replaced"
    );
}

#[cfg(unix)]
#[test]
fn a_hard_linked_config_is_replaced_not_written_through() {
    use std::os::unix::fs::MetadataExt;
    for name in ["config.json", "config.yaml"] {
        let repo = initialised();
        let victim = repo.home.path().join("victim");
        std::fs::write(&victim, b"victim bytes").unwrap();
        let ours = repo.work.path().join(".treeship").join(name);
        std::fs::remove_file(&ours).unwrap();
        std::fs::hard_link(&victim, &ours).unwrap();
        let out = repo.run(&["init", "--force", "--name", "y"]);
        assert!(out.status.success(), "{name}: {}", text(&out));
        assert_eq!(std::fs::read(&victim).unwrap(), b"victim bytes", "{name}");
        assert_eq!(std::fs::metadata(&victim).unwrap().nlink(), 1, "{name}");
        assert_ne!(std::fs::read(&ours).unwrap(), b"victim bytes", "{name}");
    }
}

#[cfg(unix)]
#[test]
fn a_linked_sessions_directory_is_refused_by_start_and_close() {
    let repo = initialised();
    let outside = repo.home.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let ts = repo.work.path().join(".treeship");
    std::os::unix::fs::symlink(&outside, ts.join("sessions")).unwrap();
    let out = repo.run(&["session", "start", "--name", "s"]);
    assert!(
        !out.status.success(),
        "session start wrote through .treeship/sessions:\n{}",
        text(&out)
    );
    let out = repo.run(&["session", "close"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        names_in(&outside).is_empty(),
        "written outside the repository: {:?}",
        names_in(&outside)
    );
}

fn set_store_dirs(repo: &Repo, keys_dir: &str, storage_dir: &str) {
    let path = repo.work.path().join(".treeship").join("config.json");
    let mut cfg: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    cfg["keys_dir"] = serde_json::Value::String(keys_dir.into());
    cfg["storage_dir"] = serde_json::Value::String(storage_dir.into());
    std::fs::write(&path, serde_json::to_vec_pretty(&cfg).unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn a_linked_ancestor_inside_treeship_is_refused_for_the_stores() {
    let repo = initialised();
    let outside = repo.home.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    set_store_dirs(&repo, "sub/keys", "sub/artifacts");
    std::os::unix::fs::symlink(&outside, repo.work.path().join(".treeship").join("sub")).unwrap();
    let out = repo.run(&["attest", "action", "--actor", "agent://a", "--action", "x"]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("symlink"),
        "the refusal should name the link:\n{}",
        text(&out)
    );
    assert!(
        names_in(&outside).is_empty(),
        "stores created outside the repository: {:?}",
        names_in(&outside)
    );
}

#[test]
fn a_discovered_config_may_not_point_its_stores_outside_the_project() {
    let repo = initialised();
    let steal = repo.home.path().join("steal");
    let absolute = steal.join("keys").to_string_lossy().into_owned();
    for (keys_dir, storage_dir) in [
        (absolute.as_str(), "artifacts"),
        ("keys", absolute.as_str()),
        ("keys/../../../escape/keys", "artifacts"),
    ] {
        set_store_dirs(&repo, keys_dir, storage_dir);
        let out = repo.run(&["status"]);
        assert!(
            !out.status.success(),
            "{keys_dir} {storage_dir}: {}",
            text(&out)
        );
        assert!(
            text(&out).contains("outside") && text(&out).contains("--config"),
            "{keys_dir} {storage_dir}: the refusal should explain and point at --config:\n{}",
            text(&out)
        );
        assert!(
            !steal.exists(),
            "{keys_dir} {storage_dir}: the store was created"
        );
    }
    // The same file named explicitly is the user's choice and is honoured.
    set_store_dirs(&repo, &absolute, "artifacts");
    let config = repo.work.path().join(".treeship").join("config.json");
    let out = repo.run(&["--config", &config.to_string_lossy(), "status"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(steal.join("keys").is_dir());
    // Relative paths inside the project, and absolute ones that spell the
    // project's own .treeship, are fine.
    let inside = repo.work.path().join(".treeship").join("keys");
    set_store_dirs(&repo, &inside.to_string_lossy(), "artifacts");
    let out = repo.run(&["status"]);
    assert!(out.status.success(), "{}", text(&out));
}

#[test]
fn a_project_stub_keeps_the_global_stores() {
    // A stub extends the global config, whose stores live under $HOME:
    // outside the project, and exactly what a stub is for.
    let repo = Repo::new();
    let out = repo.run(&[
        "init",
        "--name",
        "global",
        "--config",
        &repo
            .home
            .path()
            .join(".treeship")
            .join("config.json")
            .to_string_lossy(),
    ]);
    assert!(out.status.success(), "{}", text(&out));
    let ts = repo.work.path().join(".treeship");
    std::fs::create_dir_all(&ts).unwrap();
    std::fs::write(
        ts.join("config.json"),
        format!(
            "{{\"extends\": \"{}\", \"project\": true}}",
            repo.home
                .path()
                .join(".treeship")
                .join("config.json")
                .display()
        ),
    )
    .unwrap();
    let out = repo.run(&["status"]);
    assert!(out.status.success(), "{}", text(&out));
}
