//! A session receipt carries no absolute home paths: files under $HOME are
//! recorded as `~/...` when the receipt is composed, so the close record
//! signs the redacted form. A published receipt once leaked 1014 local
//! `/Users/<name>/...` paths.

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
fn the_receipt_names_home_files_with_a_tilde() {
    let home = tempfile::tempdir().unwrap();
    // The project lives under the home, as real projects do.
    let project = home.path().join("src").join("proj");
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
    assert!(run(&["init", "--name", "t"]).status.success());
    assert!(
        run(&["session", "start", "--name", "s", "--actor", "agent://a"])
            .status
            .success()
    );
    let written = project.join("notes.txt");
    std::fs::write(&written, b"hello").unwrap();
    let out = run(&[
        "session",
        "event",
        "--type",
        "agent.wrote_file",
        "--actor",
        "agent://a",
        "--file",
        written.to_str().unwrap(),
    ]);
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
    let receipt = std::fs::read_to_string(pkg.join("receipt.json")).unwrap();
    let home_str = home.path().to_string_lossy();
    assert!(
        !receipt.contains(home_str.as_ref()),
        "receipt carries the home path:\n{receipt}"
    );
    assert!(
        !receipt.contains("/Users/") && !receipt.contains("/home/"),
        "{receipt}"
    );
    assert!(
        receipt.contains("~/src/proj/notes.txt"),
        "the written file is not recorded as ~/...:\n{receipt}"
    );
    // The package still verifies: the redacted form is what the close record signed.
    let out = run(&["package", "verify", pkg.to_str().unwrap()]);
    assert!(out.status.success(), "{}", text(&out));
}
