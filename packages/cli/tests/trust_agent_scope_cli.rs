//! `trust add --agent`: one canonical spelling, a scope change needs
//! --replace, and one public key pinned as two agents warns.

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

struct Ship {
    home: tempfile::TempDir,
}

impl Ship {
    fn init() -> Self {
        let ship = Self {
            home: tempfile::tempdir().unwrap(),
        };
        let out = ship.run(&["init", "--name", "t"]);
        assert!(out.status.success(), "{}", text(&out));
        ship
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(cli_path())
            .current_dir(self.home.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(args)
            .arg("--config")
            .arg(self.home.path().join(".treeship/config.json"))
            .output()
            .expect("run treeship")
    }
    fn json(&self, args: &[&str]) -> serde_json::Value {
        let out = self.run(&[args, &["--format", "json"]].concat());
        assert!(out.status.success(), "{}", text(&out));
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {}", text(&out)))
    }
}

const PK_A: &str = "ed25519:AkeP0YomPIIOnZi0xG6MOxlgp3kHdL_R-cQ_heeDWLA";
const PK_B: &str = "ed25519:9PfbpAhWYgo81lyzCcdeYbcdSJzOIIfNNiqnbXgZrnM";

#[test]
fn agent_is_canonicalized_and_spelling_tricks_are_refused() {
    let ship = Ship::init();
    let out = ship.run(&[
        "trust",
        "add",
        "key_1234567890abcdef",
        PK_A,
        "--kind",
        "agent_cert",
        "--agent",
        "agent://alice/",
        "--yes",
    ]);
    assert!(out.status.success(), "{}", text(&out));
    let list = ship.json(&["trust", "list"]);
    let roots = list["roots"].as_array().cloned().unwrap_or_default();
    let pin = roots
        .iter()
        .find(|r| r["key_id"] == "key_1234567890abcdef")
        .unwrap_or_else(|| panic!("{list}"));
    assert_eq!(pin["agent"], "agent://alice", "{pin}");

    for bad in [
        "agent://vic tim",
        "agent://alice?x=1",
        "agent://a/../alice",
        "alice",
        "agent://alice#f",
    ] {
        let out = ship.run(&[
            "trust",
            "add",
            "key_00000000000000aa",
            PK_B,
            "--kind",
            "agent_cert",
            "--agent",
            bad,
            "--yes",
        ]);
        assert_eq!(out.status.code(), Some(4), "{bad:?}: {}", text(&out));
    }
    // --agent belongs to agent_cert only.
    let out = ship.run(&[
        "trust",
        "add",
        "key_00000000000000aa",
        PK_B,
        "--kind",
        "cert_issuer",
        "--agent",
        "agent://x",
        "--yes",
    ]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
}

#[test]
fn changing_a_pins_agent_needs_replace_and_two_agents_on_one_key_warn() {
    let ship = Ship::init();
    assert!(ship
        .run(&[
            "trust",
            "add",
            "key_1234567890abcdef",
            PK_A,
            "--kind",
            "agent_cert",
            "--agent",
            "agent://alice",
            "--yes"
        ])
        .status
        .success());
    // Same key id, another agent: refused without --replace, accepted with it.
    let out = ship.run(&[
        "trust",
        "add",
        "key_1234567890abcdef",
        PK_A,
        "--kind",
        "agent_cert",
        "--agent",
        "agent://other",
        "--yes",
    ]);
    assert!(
        !out.status.success() && text(&out).contains("--replace"),
        "{}",
        text(&out)
    );
    let out = ship.run(&[
        "trust",
        "add",
        "key_1234567890abcdef",
        PK_A,
        "--kind",
        "agent_cert",
        "--agent",
        "agent://other",
        "--replace",
        "--yes",
    ]);
    assert!(out.status.success(), "{}", text(&out));
    // Dropping the scope is a change too.
    let out = ship.run(&[
        "trust",
        "add",
        "key_1234567890abcdef",
        PK_A,
        "--kind",
        "agent_cert",
        "--yes",
    ]);
    assert!(
        !out.status.success() && text(&out).contains("--replace"),
        "{}",
        text(&out)
    );
    // The same public key under a second key id as a third agent: warns.
    let out = ship.run(&[
        "trust",
        "add",
        "key_00000000000000bb",
        PK_A,
        "--kind",
        "agent_cert",
        "--agent",
        "agent://third",
        "--yes",
    ]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("one key cannot be two agents"),
        "{}",
        text(&out)
    );
}
