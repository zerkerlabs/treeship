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

/// A revocation another ship signed for this card, copied into the store,
/// is not honored by any verifier and must not block the owner's revoke
/// either (review of #541: `existing_card_revocation` checked no signature).
#[test]
fn a_foreign_revocation_in_the_store_does_not_block_the_owners_revoke() {
    let ship = Ship::init();
    let card = ship.json(&["attest", "card", "--agent", "agent://bot", "--tools", "git"]);
    let id = card["id"].as_str().unwrap().to_string();

    // Another ship signs an agent_card_revocation.v1 naming our card.
    let other = Ship::init();
    let payload = format!(
        r#"{{"schema":"agent_card_revocation.v1","card":"{id}","keyid":"key_0000000000000000","revoked_at":"2026-09-28T00:00:00Z"}}"#
    );
    let forged = other.json(&[
        "attest",
        "receipt",
        "--system",
        "system://registry",
        "--kind",
        "agent_card_revocation.v1",
        "--payload",
        &payload,
    ]);
    let forged_id = forged["id"].as_str().unwrap().to_string();
    // Copy it into our store: the artifact file plus its index entry.
    let src = other.home.path().join(".treeship/artifacts");
    let dst = ship.home.path().join(".treeship/artifacts");
    std::fs::copy(
        src.join(format!("{forged_id}.json")),
        dst.join(format!("{forged_id}.json")),
    )
    .unwrap();
    let other_index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(src.join("index.json")).unwrap()).unwrap();
    let entry = other_index["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["id"] == forged_id)
        .cloned()
        .unwrap();
    let mut index: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dst.join("index.json")).unwrap()).unwrap();
    index["entries"].as_array_mut().unwrap().push(entry);
    std::fs::write(
        dst.join("index.json"),
        serde_json::to_vec_pretty(&index).unwrap(),
    )
    .unwrap();

    // The stranger's revocation changes nothing: the card still verifies...
    let out = ship.run(&["verify-capability", &id]);
    assert!(out.status.success(), "{}", text(&out));
    // ...and the owner can still revoke.
    let out = ship.run(&["revoke-capability", &id, "--reason", "retired"]);
    assert!(
        out.status.success(),
        "a foreign revocation blocked the owner's revoke:\n{}",
        text(&out)
    );
    let out = ship.run(&["verify-capability", &id]);
    assert_eq!(out.status.code(), Some(1), "{}", text(&out));
    assert!(text(&out).contains("REVOKED"), "{}", text(&out));
}
