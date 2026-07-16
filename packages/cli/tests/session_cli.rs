use std::process::Command;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

#[test]
fn session_close_json_is_one_parseable_document() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path();
    let config = root.join(".treeship/config.json");

    let command = |args: &[&str]| {
        let mut cmd = Command::new(cli_path());
        cmd.current_dir(root).env("HOME", root).args(args);
        cmd.output().expect("run treeship")
    };

    let init = command(&[
        "init",
        "--config",
        config.to_str().unwrap(),
        "--name",
        "session-json-test",
    ]);
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let start = command(&[
        "session",
        "start",
        "--config",
        config.to_str().unwrap(),
        "--name",
        "json-close",
    ]);
    assert!(
        start.status.success(),
        "start: {}",
        String::from_utf8_lossy(&start.stderr)
    );

    let wrap = command(&[
        "wrap",
        "--config",
        config.to_str().unwrap(),
        "--",
        "printf",
        "ok",
    ]);
    assert!(
        wrap.status.success(),
        "wrap: {}",
        String::from_utf8_lossy(&wrap.stderr)
    );

    let close = command(&[
        "session",
        "close",
        "--config",
        config.to_str().unwrap(),
        "--summary",
        "done",
        "--format",
        "json",
    ]);
    assert!(
        close.status.success(),
        "close: stdout={} stderr={}",
        String::from_utf8_lossy(&close.stdout),
        String::from_utf8_lossy(&close.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&close.stdout).unwrap_or_else(|e| {
        panic!(
            "session close must emit exactly one JSON document: {e}; stdout={}",
            String::from_utf8_lossy(&close.stdout)
        )
    });
    assert_eq!(json["status"], "ok");
    assert_eq!(json["message"], "session closed");
    assert!(json["session_id"].as_str().is_some());
    assert!(json["package"].as_str().is_some());
}
