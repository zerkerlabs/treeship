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
