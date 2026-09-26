//! `approval-use-limit` judges approvals by their SIGNED scope, in every
//! mode: a carried grant whose signature fails is a failure under
//! `--structural` too, and an approval with no maxActions is reported as
//! unbounded rather than "within its limit".

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

fn ok(home: &std::path::Path, args: &[&str]) -> String {
    let out = run(home, args);
    assert!(
        out.status.success(),
        "`{}` failed: {}{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn json(s: &str) -> serde_json::Value {
    serde_json::Deserializer::from_str(s)
        .into_iter::<serde_json::Value>()
        .next()
        .unwrap()
        .unwrap_or_else(|e| panic!("not JSON ({e}): {s}"))
}

/// A session whose consuming action uses an approval minted BEFORE the
/// session started, so the grant travels in `approvals/grants/` (carried)
/// rather than in the sealed set. `max_uses` None mints an unscoped grant.
fn package_with_carried_grant(
    home: &std::path::Path,
    max_uses: Option<&str>,
) -> (std::path::PathBuf, String) {
    ok(home, &["init", "--name", "t"]);
    let mut mint = vec![
        "--format",
        "json",
        "attest",
        "approval",
        "--approver",
        "human://h",
        "--allowed-actor",
        "agent://a",
        "--allowed-action",
        "deploy",
    ];
    if let Some(m) = max_uses {
        mint.extend(["--max-uses", m]);
    }
    let minted = json(&ok(home, &mint));
    let nonce = minted["nonce"].as_str().unwrap().to_string();
    let grant_id = minted["artifact_id"]
        .as_str()
        .or_else(|| minted["id"].as_str())
        .unwrap()
        .to_string();
    ok(
        home,
        &["session", "start", "--name", "s", "--actor", "agent://a"],
    );
    ok(
        home,
        &[
            "attest",
            "action",
            "--actor",
            "agent://a",
            "--action",
            "deploy",
            "--approval-nonce",
            &nonce,
        ],
    );
    let dir = home.join("r");
    let closed = json(&ok(
        home,
        &[
            "session",
            "close",
            "--receipt-dir",
            dir.to_str().unwrap(),
            "--format",
            "json",
        ],
    ));
    let pkg = std::path::PathBuf::from(closed["receipt_copy"].as_str().unwrap());
    assert!(
        pkg.join("approvals")
            .join("grants")
            .join(format!("{grant_id}.json"))
            .is_file(),
        "the grant minted before the session is not carried in approvals/grants"
    );
    (pkg, grant_id)
}

fn rows(home: &std::path::Path, pkg: &std::path::Path, mode: &[&str]) -> serde_json::Value {
    let mut args = vec![
        "package",
        "verify",
        pkg.to_str().unwrap(),
        "--format",
        "json",
    ];
    args.extend_from_slice(mode);
    json(&String::from_utf8_lossy(&run(home, &args).stdout))
}

fn row<'a>(v: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no {name} row in {v}"))
}

#[test]
fn a_carried_grant_with_a_broken_signature_fails_under_structural_too() {
    let home = tempfile::tempdir().unwrap();
    let (pkg, grant_id) = package_with_carried_grant(home.path(), Some("1"));
    // Honest first: every mode passes the limit row.
    for mode in [&[][..], &["--strict"][..], &["--structural"][..]] {
        let v = rows(home.path(), &pkg, mode);
        assert_eq!(
            row(&v, "approval-use-limit")["status"],
            "pass",
            "{mode:?}: {v}"
        );
    }
    // Break the carried grant's signature (last character of `sig`).
    let path = pkg
        .join("approvals")
        .join("grants")
        .join(format!("{grant_id}.json"));
    let mut env: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let sig = env["signatures"][0]["sig"].as_str().unwrap().to_string();
    let flipped = {
        let mut c: Vec<char> = sig.chars().collect();
        let last = c.len() - 1;
        c[last] = if c[last] == 'A' { 'B' } else { 'A' };
        c.into_iter().collect::<String>()
    };
    env["signatures"][0]["sig"] = serde_json::Value::String(flipped);
    std::fs::write(&path, serde_json::to_vec_pretty(&env).unwrap()).unwrap();
    for mode in [&[][..], &["--strict"][..], &["--structural"][..]] {
        let v = rows(home.path(), &pkg, mode);
        let r = row(&v, "approval-use-limit");
        assert_eq!(r["status"], "fail", "{mode:?}: {v}");
        assert!(
            r["detail"].as_str().unwrap().contains("invalid signature"),
            "{mode:?}: {v}"
        );
        assert_ne!(v["verdict"], "structural-pass", "{mode:?}: {v}");
        assert_ne!(v["verdict"], "verified", "{mode:?}: {v}");
    }
}

#[test]
fn an_unscoped_approval_is_reported_as_unbounded_not_within_a_limit() {
    let home = tempfile::tempdir().unwrap();
    let (pkg, grant_id) = package_with_carried_grant(home.path(), None);
    let v = rows(home.path(), &pkg, &[]);
    let r = row(&v, "approval-use-limit");
    assert_eq!(r["status"], "pass", "{v}");
    let detail = r["detail"].as_str().unwrap();
    assert!(detail.contains(&grant_id), "{v}");
    assert!(
        detail.contains("unbounded (no maxActions in the signed scope)"),
        "{v}"
    );
    assert!(
        !detail.starts_with("every approval is used within the limit"),
        "{v}"
    );
}
