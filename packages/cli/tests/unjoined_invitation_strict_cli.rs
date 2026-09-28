//! An honest host that mints an invitation nobody joins must still pass
//! `package verify --strict`: the invitation is sealed but unchained, and
//! chain_completeness had nothing binding it (0.31.11 re-test, N-39). The
//! host's own signature over an invitation naming this session is the
//! binding.

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

#[test]
fn an_unjoined_invitation_passes_strict_verify() {
    let home = tempfile::tempdir().unwrap();
    let project = home.path().join("proj");
    std::fs::create_dir_all(&project).unwrap();
    let cfg = project.join(".treeship/config.json");
    let run = |args: &[&str]| -> Output {
        Command::new(cli_path())
            .current_dir(&project)
            .env("HOME", home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(args)
            .arg("--config")
            .arg(&cfg)
            .output()
            .expect("run treeship")
    };
    assert!(run(&["init", "--name", "host"]).status.success());
    let out = run(&["session", "start", "--name", "s", "--format", "json"]);
    assert!(out.status.success(), "{}", text(&out));
    let session: serde_json::Value =
        serde_json::from_slice(&std::fs::read(project.join(".treeship/session.json")).unwrap())
            .unwrap();
    let sid = session["session_id"].as_str().unwrap().to_string();
    let out = run(&["session", "invite", &sid, "--open", "--format", "json"]);
    assert!(out.status.success(), "{}", text(&out));
    let out = run(&[
        "session",
        "close",
        "--receipt-dir",
        project.join("r").to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(out.status.success(), "{}", text(&out));
    let pkg = std::fs::read_dir(project.join("r"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.extension().map(|x| x == "treeship").unwrap_or(false))
        .expect("no package written");

    let out = run(&[
        "package",
        "verify",
        pkg.to_str().unwrap(),
        "--strict",
        "--format",
        "json",
    ]);
    let all = text(&out);
    assert!(
        out.status.success(),
        "an honest unjoined invitation failed --strict:\n{all}"
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {all}"));
    let row = doc["checks"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|c| c["name"] == "chain_completeness")
        .unwrap_or_else(|| panic!("no chain_completeness row: {doc}"));
    assert_eq!(row["status"], "pass", "{row}");
    assert!(
        row["detail"]
            .as_str()
            .unwrap_or("")
            .contains("invitation issued for this session"),
        "{row}"
    );
}
