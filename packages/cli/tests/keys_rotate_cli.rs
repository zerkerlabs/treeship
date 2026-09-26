//! `keys rotate` moves the default signer, and every reader agrees.
//!
//! Through 0.31.9 the keystore promoted the successor while `hub attach`
//! read the predecessor from config.json (0.31.9 full test, CLI-9). A first
//! fix wrote config.json, which flattened a project stub onto itself and
//! broke the ship. The keystore manifest is now the one source of truth,
//! nothing writes config.json, and rotations are serialised.

use std::process::{Command, Output};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

struct Ship {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
    /// `Some` when commands pass `--config`; `None` for a project stub
    /// found from the working directory, the way a person runs it.
    explicit_config: bool,
}

impl Ship {
    fn init(explicit_config: bool) -> Self {
        let home = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let ship = Self {
            home,
            work,
            explicit_config,
        };
        let out = ship.run(&["init", "--name", "rotate"]);
        assert!(
            out.status.success(),
            "init: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        ship
    }

    fn run(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(cli_path());
        cmd.current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(args);
        if self.explicit_config {
            cmd.arg("--config")
                .arg(self.work.path().join(".treeship/config.json"));
        }
        cmd.output().expect("run treeship")
    }

    fn json(&self, args: &[&str]) -> serde_json::Value {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "`treeship {}`: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).unwrap()
    }

    fn keystore_default(&self) -> String {
        let list = self.json(&["keys", "list", "--format", "json"]);
        let defaults: Vec<String> = list
            .as_array()
            .unwrap()
            .iter()
            .filter(|k| k["is_default"] == true)
            .map(|k| k["id"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(defaults.len(), 1, "one default key: {list}");
        defaults[0].clone()
    }

    /// The key that signed an artifact, from the stored record wherever the
    /// store is (the global home for a project stub).
    fn signer_of(&self, artifact_id: &str) -> String {
        for root in [
            self.work.path().join(".treeship"),
            self.home.path().join(".treeship"),
        ] {
            let p = root.join("artifacts").join(format!("{artifact_id}.json"));
            if p.exists() {
                let rec: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
                return rec["key_id"].as_str().unwrap().to_string();
            }
        }
        panic!("no stored record for {artifact_id}");
    }
}

#[test]
fn rotate_moves_the_default_and_the_new_key_signs() {
    let ship = Ship::init(true);
    let before = ship.keystore_default();
    let rotated = ship.json(&["keys", "rotate", "--format", "json"]);
    let successor = rotated["successor"]["id"].as_str().unwrap().to_string();
    assert_ne!(successor, before);
    assert_eq!(
        rotated["default_key_id"].as_str(),
        Some(successor.as_str()),
        "{rotated}"
    );
    assert_eq!(ship.keystore_default(), successor);

    let attested = ship.json(&[
        "attest",
        "action",
        "--actor",
        "agent://a",
        "--action",
        "after",
        "--format",
        "json",
    ]);
    assert_eq!(ship.signer_of(attested["id"].as_str().unwrap()), successor);
    let out = ship.run(&["verify", "last"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn rotate_no_default_leaves_the_default_alone() {
    let ship = Ship::init(true);
    let before = ship.keystore_default();
    let rotated = ship.json(&["keys", "rotate", "--no-default", "--format", "json"]);
    assert_eq!(rotated["successor"]["is_default"], false, "{rotated}");
    assert_eq!(
        rotated["default_key_id"].as_str(),
        Some(before.as_str()),
        "{rotated}"
    );
    assert_eq!(ship.keystore_default(), before);
}

/// The P0 from review: init in a project directory writes a stub that
/// extends the global config. Rotating there used to rewrite the stub as
/// a flattened config with store paths pointing into the project, and the
/// next attest failed with "no default key".
#[test]
fn rotate_from_a_project_directory_keeps_the_ship_working() {
    let ship = Ship::init(false);
    let stub_path = ship.work.path().join(".treeship/config.json");
    let stub_before = std::fs::read_to_string(&stub_path).unwrap();
    assert!(
        stub_before.contains("\"extends\""),
        "init did not write a project stub: {stub_before}"
    );
    let global_before =
        std::fs::read_to_string(ship.home.path().join(".treeship/config.json")).unwrap();

    let rotated = ship.json(&["keys", "rotate", "--format", "json"]);
    let successor = rotated["successor"]["id"].as_str().unwrap().to_string();

    // Neither file was rewritten: the keystore manifest carries the change.
    assert_eq!(
        std::fs::read_to_string(&stub_path).unwrap(),
        stub_before,
        "the project stub was rewritten"
    );
    assert_eq!(
        std::fs::read_to_string(ship.home.path().join(".treeship/config.json")).unwrap(),
        global_before,
        "the global config was rewritten"
    );

    let attested = ship.json(&[
        "attest",
        "action",
        "--actor",
        "agent://a",
        "--action",
        "after",
        "--format",
        "json",
    ]);
    assert_eq!(ship.signer_of(attested["id"].as_str().unwrap()), successor);
    let out = ship.run(&["verify", "last"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(ship.keystore_default(), successor);
}

/// Two rotations at once are serialised: the second rotates what the
/// first left as default, so no key ever has two successors.
#[test]
fn concurrent_rotations_form_one_chain() {
    let ship = Ship::init(true);
    let first = ship.keystore_default();
    let outs: Vec<Output> = std::thread::scope(|scope| {
        let hs: Vec<_> = (0..2)
            .map(|_| scope.spawn(|| ship.run(&["keys", "rotate", "--format", "json"])))
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for o in &outs {
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    }
    let list = ship.json(&["keys", "list", "--format", "json"]);
    let keys = list.as_array().unwrap();
    assert_eq!(keys.len(), 3, "{list}");
    let successors: Vec<&str> = keys
        .iter()
        .filter_map(|k| k["successor_key_id"].as_str())
        .collect();
    assert_eq!(
        successors.len(),
        2,
        "two rotated keys, each with one successor: {list}"
    );
    let mut uniq = successors.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), 2, "a key has two successors: {list}");
    let first_succ = keys
        .iter()
        .find(|k| k["id"] == first)
        .and_then(|k| k["successor_key_id"].as_str())
        .expect("the original key was rotated once");
    let second = keys.iter().find(|k| k["id"] == first_succ).unwrap();
    assert!(
        second["successor_key_id"].is_string(),
        "chain is first -> second -> third: {list}"
    );
    assert_eq!(
        ship.keystore_default(),
        second["successor_key_id"].as_str().unwrap()
    );
}
