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

/// `session event --format json` exited 0 and printed nothing.
///
/// It built the response and passed it to `printer.info`, which returns early
/// in JSON mode -- so the document was constructed and discarded. Every SDK
/// wrapper reading `event_id` off the result got `undefined` from an empty
/// stdout, and the command's exit code said success.
///
/// Found reviewing an external contributor's SDK PR (#203). The PR was right;
/// the CLI it wrapped was not.
#[test]
fn session_event_json_actually_emits_the_event_id() {
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
        "event-json-test",
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
        "json-event",
    ]);
    assert!(
        start.status.success(),
        "start: {}",
        String::from_utf8_lossy(&start.stderr)
    );

    let event = command(&[
        "session",
        "event",
        "--config",
        config.to_str().unwrap(),
        "--type",
        "agent.called_tool",
        "--tool",
        "bash",
        "--format",
        "json",
    ]);
    assert!(
        event.status.success(),
        "event: {}",
        String::from_utf8_lossy(&event.stderr)
    );

    let stdout = String::from_utf8_lossy(&event.stdout);
    assert!(
        !stdout.trim().is_empty(),
        "`--format json` produced no output; exit code 0 with an empty document \
         is the shape that made this bug invisible"
    );

    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be one parseable JSON document");
    assert!(
        json["event_id"].as_str().is_some_and(|s| !s.is_empty()),
        "event_id is what an SDK reads off this call: {json}"
    );
    assert!(json["session_id"].as_str().is_some(), "{json}");
    assert!(json["sequence_no"].as_u64().is_some(), "{json}");
}
