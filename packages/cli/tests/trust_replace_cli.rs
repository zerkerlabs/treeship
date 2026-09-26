//! `trust add` does not silently re-point a pinned key id at another key
//! (round-3 review). A key id is only a label; a pin line pasted from a
//! forged package reusing a victim's id must not replace the victim's key.

use std::process::{Command, Output};

fn run(home: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_treeship"))
        .env("HOME", home)
        .env("TREESHIP_CONFIG", home.join(".treeship/config.json"))
        .current_dir(home)
        .args(args)
        .output()
        .expect("run treeship")
}

const ID: &str = "key_57e0c8ba2b2bc32c";
const KEY_A: &str = "ed25519:AkeP0YomPIIOnZi0xG6MOxlgp3kHdL_R-cQ_heeDWLA";
const KEY_B: &str = "ed25519:9PfbpAhWYgo81lyzCcdeYbcdSJzOIIfNNiqnbXgZrnM";

#[test]
fn trust_add_refuses_a_different_key_under_a_pinned_id_without_replace() {
    let home = tempfile::tempdir().unwrap();
    assert!(run(home.path(), &["init", "--name", "t"]).status.success());
    let out = run(
        home.path(),
        &["trust", "add", ID, KEY_A, "--kind", "cert_issuer", "--yes"],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Same id, different key: refused, naming both fingerprints.
    let out = run(
        home.path(),
        &["trust", "add", ID, KEY_B, "--kind", "cert_issuer", "--yes"],
    );
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--replace") && err.contains("already pinned"),
        "{err}"
    );

    // The original pin is untouched.
    let list = run(home.path(), &["trust", "list", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    let pinned: Vec<&str> = v["roots"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["key_id"] == ID)
        .map(|r| r["public_key"].as_str().unwrap())
        .collect();
    assert_eq!(pinned, vec![KEY_A]);

    // Re-pinning the same key is fine; an explicit --replace replaces.
    assert!(run(
        home.path(),
        &["trust", "add", ID, KEY_A, "--kind", "cert_issuer", "--yes"]
    )
    .status
    .success());
    let out = run(
        home.path(),
        &[
            "trust",
            "add",
            ID,
            KEY_B,
            "--kind",
            "cert_issuer",
            "--yes",
            "--replace",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
