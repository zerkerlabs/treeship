//! A repository's `.treeship/config.json` stub must not choose which file
//! a command writes. Review of the first W1-12 fix found that a stub whose
//! `extends` pointed at `../../../.ssh/authorized_keys` plus `init --force`
//! replaced that file with config JSON, and that `init --force` in a
//! legitimate stub directory rewrote the global config.

use std::process::{Command, Output};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

struct Ship {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
}

impl Ship {
    /// A global workspace under HOME and a project stub in the work dir,
    /// the way a plain `treeship init` in a project leaves things.
    fn init_project() -> Self {
        let home = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let ship = Self { home, work };
        let out = ship.run(&["init", "--name", "proj"]);
        assert!(
            out.status.success(),
            "init: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stub = std::fs::read_to_string(ship.stub_path()).unwrap();
        assert!(stub.contains("\"extends\""), "no stub written: {stub}");
        ship
    }

    fn stub_path(&self) -> std::path::PathBuf {
        self.work.path().join(".treeship/config.json")
    }

    fn global_path(&self) -> std::path::PathBuf {
        self.home.path().join(".treeship/config.json")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(cli_path())
            .current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(args)
            .output()
            .expect("run treeship")
    }
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_malicious_stub_cannot_choose_what_init_writes() {
    let ship = Ship::init_project();
    // The file a hostile repository would like overwritten.
    let target = ship.home.path().join("precious.txt");
    std::fs::write(&target, b"keep me").unwrap();
    let stub_dir = ship.stub_path();
    let rel = pathdiff(&target, stub_dir.parent().unwrap());
    std::fs::write(
        ship.stub_path(),
        serde_json::to_string(&serde_json::json!({ "extends": rel, "project": true })).unwrap(),
    )
    .unwrap();

    let out = ship.run(&["init", "--force", "--name", "own"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"keep me",
        "the extends target was written"
    );
    // The stub itself became a workspace of its own, at its own path.
    let stub: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(ship.stub_path()).unwrap()).unwrap();
    assert!(stub.get("extends").is_none(), "{stub}");
    assert!(stub["ship_id"].is_string(), "{stub}");
}

#[test]
fn init_force_in_a_stub_directory_leaves_the_global_config_alone() {
    let ship = Ship::init_project();
    let global_before = std::fs::read(ship.global_path()).unwrap();
    let out = ship.run(&["init", "--force", "--name", "own"]);
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(
        std::fs::read(ship.global_path()).unwrap(),
        global_before,
        "init --force in a project rewrote the global config"
    );
    // And the project is now its own workspace with its own key.
    let out = ship.run(&["attest", "action", "--actor", "agent://a", "--action", "x"]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(ship.work.path().join(".treeship/keys").exists());
}

#[cfg(unix)]
#[test]
fn a_symlinked_config_is_never_replaced() {
    let ship = Ship::init_project();
    let target = ship.home.path().join("elsewhere.json");
    std::fs::write(&target, b"{\"keep\":1}").unwrap();
    std::fs::remove_file(ship.stub_path()).unwrap();
    std::os::unix::fs::symlink(&target, ship.stub_path()).unwrap();

    let out = ship.run(&["init", "--force", "--name", "own"]);
    assert!(
        !out.status.success(),
        "init wrote through a symlink:\n{}",
        text(&out)
    );
    assert!(text(&out).contains("symlink"), "{}", text(&out));
    assert_eq!(std::fs::read(&target).unwrap(), b"{\"keep\":1}");
}

/// Relative path from `from_dir` to `target` (both absolute, same volume).
fn pathdiff(target: &std::path::Path, from_dir: &std::path::Path) -> String {
    let t: Vec<_> = target.components().collect();
    let f: Vec<_> = from_dir.components().collect();
    let common = t.iter().zip(f.iter()).take_while(|(a, b)| a == b).count();
    let mut out = std::path::PathBuf::new();
    for _ in common..f.len() {
        out.push("..");
    }
    for c in &t[common..] {
        out.push(c.as_os_str());
    }
    out.to_string_lossy().into_owned()
}
