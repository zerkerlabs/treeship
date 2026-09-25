//! `keys rotate` moves the default in the keystore and in config.json.
//! Through 0.31.9 config.json kept the predecessor, so `hub attach` bound a
//! key that stopped being valid when the grace window closed (0.31.9 full
//! test, CLI-9).

use std::process::{Command, Output};

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

struct Ship {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
}

impl Ship {
    fn init() -> Self {
        let home = tempfile::tempdir().unwrap();
        let work = tempfile::tempdir().unwrap();
        let ship = Self { home, work };
        let out = ship.run(&["init", "--name", "rotate"]);
        assert!(
            out.status.success(),
            "init: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        ship
    }

    fn config_path(&self) -> std::path::PathBuf {
        self.work.path().join(".treeship/config.json")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(cli_path())
            .current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(args)
            .arg("--config")
            .arg(self.config_path())
            .output()
            .expect("run treeship")
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

    fn config_default_key(&self) -> String {
        let cfg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(self.config_path()).unwrap()).unwrap();
        cfg["default_key_id"].as_str().unwrap().to_string()
    }

    /// The key that signed an artifact, from its stored record.
    fn signer_of(&self, artifact_id: &str) -> String {
        let cfg: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(self.config_path()).unwrap()).unwrap();
        let storage = cfg["storage_dir"].as_str().unwrap();
        let storage = self.work.path().join(".treeship").join(storage);
        let storage = if storage.exists() {
            storage
        } else {
            std::path::PathBuf::from(cfg["storage_dir"].as_str().unwrap())
        };
        let rec: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(storage.join(format!("{artifact_id}.json"))).unwrap(),
        )
        .unwrap();
        rec["key_id"].as_str().unwrap().to_string()
    }
}

#[test]
fn rotate_updates_the_config_default_and_the_new_key_signs() {
    let ship = Ship::init();
    let before = ship.config_default_key();

    let rotated = ship.json(&["keys", "rotate", "--format", "json"]);
    let successor = rotated["successor"]["id"].as_str().unwrap().to_string();
    assert_ne!(successor, before);
    assert_eq!(rotated["config_updated"], true, "{rotated}");
    assert_eq!(
        rotated["config_default_key_id"].as_str(),
        Some(successor.as_str())
    );

    // config.json follows the keystore.
    assert_eq!(
        ship.config_default_key(),
        successor,
        "config.json still names the predecessor"
    );

    // keys list agrees.
    let list = ship.json(&["keys", "list", "--format", "json"]);
    let defaults: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|k| k["is_default"] == true)
        .map(|k| k["id"].as_str().unwrap())
        .collect();
    assert_eq!(defaults, vec![successor.as_str()], "{list}");

    // The next attestation is signed by the successor.
    let attested = ship.json(&[
        "attest",
        "action",
        "--actor",
        "agent://a",
        "--action",
        "after-rotate",
        "--format",
        "json",
    ]);
    let id = attested["id"].as_str().unwrap();
    assert_eq!(
        ship.signer_of(id),
        successor,
        "attest still signs with the predecessor"
    );
}

#[test]
fn rotate_no_default_leaves_the_config_alone() {
    let ship = Ship::init();
    let before = ship.config_default_key();
    let rotated = ship.json(&["keys", "rotate", "--no-default", "--format", "json"]);
    assert_eq!(rotated["successor"]["is_default"], false, "{rotated}");
    assert_eq!(rotated["config_updated"], false, "{rotated}");
    assert_eq!(ship.config_default_key(), before);
    let attested = ship.json(&[
        "attest",
        "action",
        "--actor",
        "agent://a",
        "--action",
        "x",
        "--format",
        "json",
    ]);
    assert_eq!(ship.signer_of(attested["id"].as_str().unwrap()), before);
}
