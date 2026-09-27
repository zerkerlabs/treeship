//! Revoking an asserted (not key-bound) capability card printed "revoked"
//! and exited 0, but verify-capability and resolve kept honoring the card:
//! the revocation was verified only against pinned trust roots, and an
//! asserted card's key is the ship's own, unpinned key (0.31.11 re-test,
//! N-38). A revoke must take effect or fail loudly.

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
        let out = ship.run(&["init", "--name", "r"]);
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

#[test]
fn revoking_an_asserted_card_takes_effect_everywhere() {
    let ship = Ship::init();
    let card = ship.json(&["attest", "card", "--agent", "agent://bot", "--tools", "git"]);
    assert_eq!(card["key-bound"], "no (asserted)", "{card}");
    let id = card["id"].as_str().unwrap().to_string();

    // Before: the card resolves and verifies.
    assert!(ship.run(&["verify-capability", &id]).status.success());
    assert!(ship.run(&["resolve", "agent://bot"]).status.success());

    let out = ship.run(&["revoke-capability", &id, "--reason", "retired"]);
    assert!(out.status.success(), "{}", text(&out));
    let said = text(&out);
    assert!(
        said.contains("the card's key, the ship default key"),
        "an asserted card has no agent key to revoke with:\n{said}"
    );

    // After: every reader honors the revocation.
    let out = ship.run(&["verify-capability", &id]);
    let all = text(&out);
    assert_eq!(
        out.status.code(),
        Some(1),
        "revoked card still verifies:\n{all}"
    );
    assert!(all.contains("REVOKED") && all.contains("retired"), "{all}");
    assert!(
        all.contains("self-revoked (the card's own key)"),
        "the revocation must name its signer:\n{all}"
    );
    let out = ship.run(&["resolve", "agent://bot"]);
    let all = text(&out);
    assert!(
        all.to_lowercase().contains("revoked"),
        "resolve still honors the revoked card:\n{all}"
    );
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("✓ agent resolved"),
        "a revoked card resolved under a green header:\n{all}"
    );

    // A second revocation is refused and names the first.
    let out = ship.run(&["revoke-capability", &id]);
    assert!(!out.status.success(), "{}", text(&out));
    assert!(text(&out).contains("already revoked"), "{}", text(&out));
}
