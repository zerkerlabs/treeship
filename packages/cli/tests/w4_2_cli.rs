//! Output that contradicted itself or misled (0.31.9 full test, CLI-15 and
//! P3-UX): a revoked card under a green header, a second revocation or
//! resolution that "succeeded", `ui` failing with an OS error off a
//! terminal, and a --v2 action signed outside its grant with no warning.

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
        let out = ship.run(&["init", "--name", "w4-2"]);
        assert!(
            out.status.success(),
            "init: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        ship
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(cli_path())
            .current_dir(self.work.path())
            .env("HOME", self.home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(args)
            .arg("--config")
            .arg(self.work.path().join(".treeship/config.json"))
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
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn a_revoked_card_never_gets_a_green_headline() {
    let ship = Ship::init();
    // A registered agent with its own key: its revocation is a
    // self-revocation, which verify-capability honours.
    let reg = ship.run(&["agent", "register", "--name", "bot", "--own-key"]);
    assert!(reg.status.success(), "{}", text(&reg));
    let card = ship.json(&[
        "attest",
        "card",
        "--agent",
        "agent://bot",
        "--tools",
        "read",
        "--format",
        "json",
    ]);
    let id = card["id"]
        .as_str()
        .or_else(|| card["artifact_id"].as_str())
        .or_else(|| card["card"].as_str())
        .unwrap_or_else(|| panic!("no card id in {card}"))
        .to_string();
    let out = ship.run(&["revoke-capability", &id, "--reason", "compromised"]);
    assert!(out.status.success(), "{}", text(&out));

    let out = ship.run(&["verify-capability", &id]);
    let all = text(&out);
    assert_eq!(out.status.code(), Some(1), "{all}");
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("✓ capability card"),
        "revoked card printed under a green header:\n{all}"
    );
    assert!(all.contains("REVOKED"), "{all}");
}

#[test]
fn a_second_grant_revocation_is_refused_and_names_the_first() {
    let ship = Ship::init();
    let g = ship.json(&[
        "grant",
        "issue",
        "--scope",
        "x",
        "--audience",
        "agent://a",
        "--expiry",
        "30d",
        "--grantee-self",
        "--format",
        "json",
    ]);
    let id = g["grant_id"].as_str().unwrap().to_string();
    let first = ship.run(&["grant", "revoke", &id, "--reason", "r"]);
    assert!(first.status.success(), "{}", text(&first));
    let second = ship.run(&["grant", "revoke", &id, "--reason", "again"]);
    assert!(
        !second.status.success(),
        "second revoke succeeded:\n{}",
        text(&second)
    );
    assert!(
        text(&second).contains("already revoked"),
        "{}",
        text(&second)
    );
}

#[test]
fn a_second_conflicting_resolution_is_refused() {
    let ship = Ship::init();
    let v = ship.json(&[
        "judge",
        "--tool",
        "Bash",
        "--input",
        r#"{"command":"rm -rf /"}"#,
        "--attest",
        "--format",
        "json",
    ]);
    let judgement = v["receipts"][0].as_str().unwrap().to_string();
    let first = ship.run(&[
        "judge",
        "--resolve",
        &judgement,
        "--by",
        "human://alice",
        "--decision",
        "allow",
    ]);
    assert!(first.status.success(), "{}", text(&first));
    let second = ship.run(&[
        "judge",
        "--resolve",
        &judgement,
        "--by",
        "human://bob",
        "--decision",
        "deny",
    ]);
    assert!(
        !second.status.success(),
        "conflicting resolution accepted:\n{}",
        text(&second)
    );
    let t = text(&second);
    assert!(
        t.contains("already resolved") && t.contains("human://alice") && t.contains("allow"),
        "{t}"
    );
}

#[test]
fn ui_off_a_terminal_says_so_instead_of_an_os_error() {
    let ship = Ship::init();
    let out = ship.run(&["ui"]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    let t = text(&out);
    assert!(t.contains("needs a terminal"), "{t}");
    assert!(!t.contains("os error"), "{t}");
}

#[test]
fn a_v2_action_outside_its_grant_is_signed_with_a_warning() {
    let ship = Ship::init();
    let g = ship.json(&[
        "grant",
        "issue",
        "--scope",
        "payments.refund",
        "--audience",
        "agent://me",
        "--expiry",
        "30d",
        "--grantee-self",
        "--format",
        "json",
    ]);
    let id = g["grant_id"].as_str().unwrap().to_string();
    let out = ship.run(&[
        "attest",
        "action",
        "--v2",
        "--actor",
        "agent://me",
        "--action",
        "admin.delete",
        "--grant",
        &id,
    ]);
    let t = text(&out);
    assert!(
        out.status.success(),
        "the receipt records the violation; signing must not fail:\n{t}"
    );
    assert!(
        t.contains("outside the grant's scope"),
        "no warning at signing time:\n{t}"
    );
    let ok = ship.run(&[
        "attest",
        "action",
        "--v2",
        "--actor",
        "agent://me",
        "--action",
        "payments.refund",
        "--grant",
        &id,
    ]);
    assert!(
        !text(&ok).contains("outside the grant's scope"),
        "{}",
        text(&ok)
    );
}
