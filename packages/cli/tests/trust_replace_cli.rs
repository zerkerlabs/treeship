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

/// Round 4: a forger's package whose key id is the VERIFIER's own key id.
/// It fails key_id_collision, the row offers no pin line, trust add refuses
/// to re-point an own key id (even with --replace), and the ship's own
/// packages still verify.
#[test]
fn a_package_reusing_this_ships_own_key_id_cannot_be_pinned_into_trust() {
    let verifier = tempfile::tempdir().unwrap();
    let forger = tempfile::tempdir().unwrap();
    for h in [verifier.path(), forger.path()] {
        assert!(run(h, &["init", "--name", "t"]).status.success());
    }
    let own = run(verifier.path(), &["keys", "export", "--format", "json"]);
    let own: serde_json::Value = serde_json::from_slice(&own.stdout).unwrap();
    let own_id = own["key_id"].as_str().unwrap().to_string();

    // The forger's honest session, re-labelled under the verifier's key id.
    let close = |h: &std::path::Path, dir: &str| {
        assert!(run(
            h,
            &["session", "start", "--name", "s", "--actor", "agent://a"]
        )
        .status
        .success());
        assert!(run(
            h,
            &["attest", "action", "--actor", "agent://a", "--action", "x"]
        )
        .status
        .success());
        let out = run(
            h,
            &["session", "close", "--receipt-dir", dir, "--format", "json"],
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let v: serde_json::Value = serde_json::Deserializer::from_slice(&out.stdout)
            .into_iter::<serde_json::Value>()
            .next()
            .unwrap()
            .unwrap();
        std::path::PathBuf::from(v["receipt_copy"].as_str().unwrap())
    };
    let pkg = close(forger.path(), forger.path().join("r").to_str().unwrap());
    let fkeys: serde_json::Value =
        serde_json::from_slice(&std::fs::read(pkg.join("keys.json")).unwrap()).unwrap();
    let (fid, fpub) = fkeys["keys"]
        .as_object()
        .unwrap()
        .iter()
        .next()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .unwrap();
    for f in std::fs::read_dir(pkg.join("artifacts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .chain([pkg.join("record.json")])
    {
        let s = std::fs::read_to_string(&f).unwrap().replace(&fid, &own_id);
        std::fs::write(&f, s).unwrap();
    }
    std::fs::write(
        pkg.join("keys.json"),
        serde_json::json!({"schema": fkeys["schema"], "keys": {own_id.clone(): fpub.clone()}})
            .to_string(),
    )
    .unwrap();

    let out = run(
        verifier.path(),
        &[
            "package",
            "verify",
            pkg.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert!(!out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let rows = v["checks"].as_array().unwrap();
    assert!(
        rows.iter()
            .any(|c| c["name"] == "key_id_collision" && c["status"] == "fail"),
        "{v}"
    );
    assert!(
        !rows.iter().any(|c| c["detail"]
            .as_str()
            .unwrap_or("")
            .contains(&format!("trust add {own_id}"))),
        "no row may offer to pin the colliding id: {v}"
    );

    // trust add refuses to re-point the own id, with or without --replace.
    for extra in [&[][..], &["--replace"][..]] {
        let mut args = vec![
            "trust",
            "add",
            own_id.as_str(),
            fpub.as_str(),
            "--kind",
            "cert_issuer",
            "--yes",
        ];
        args.extend_from_slice(extra);
        let out = run(verifier.path(), &args);
        assert!(
            !out.status.success(),
            "trust add {extra:?} must refuse an own key id"
        );
        assert!(String::from_utf8_lossy(&out.stderr).contains("this ship's own key"));
    }

    // The ship's own package still verifies.
    let mine = close(verifier.path(), verifier.path().join("r").to_str().unwrap());
    let out = run(
        verifier.path(),
        &[
            "package",
            "verify",
            mine.to_str().unwrap(),
            "--format",
            "json",
        ],
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
