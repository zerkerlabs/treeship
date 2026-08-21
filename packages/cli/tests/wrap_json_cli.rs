use std::process::Command;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

/// `wrap --format json` printed nothing and exited 0.
///
/// Every output line went through `printer.info`, which returns early in JSON
/// mode, so the receipt was built and discarded. The only thing on stdout was
/// the wrapped command's own output — so a caller parsing the result got the
/// program's output where a receipt should be. The Python SDK's `wrap()` could
/// not work at all.
///
/// Emitting the document was necessary but not sufficient: the child's stdout
/// shared the stream, so `json.loads` still failed on the first line. In JSON
/// mode the child's output moves to stderr — not discarded, just off the
/// channel that promises one machine-readable document.
#[test]
fn wrap_json_emits_one_parseable_document_on_stdout() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path();
    let config = root.join(".treeship/config.json");
    let cfg = config.to_str().unwrap();

    let run = |args: &[&str]| {
        let mut cmd = Command::new(cli_path());
        cmd.current_dir(root).env("HOME", root).args(args);
        cmd.output().expect("run treeship")
    };

    let init = run(&["init", "--config", cfg, "--name", "wrap-json"]);
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let out = run(&[
        "wrap", "--config", cfg, "--format", "json", "--", "echo", "NOISE",
    ]);
    assert!(
        out.status.success(),
        "wrap: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.trim().is_empty(),
        "`--format json` produced no output; exit 0 with an empty document is \
         the shape that made this bug invisible"
    );

    // The load-bearing assertion: stdout parses whole. Before the fix it began
    // with the wrapped program's output and failed here.
    let json: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("stdout must be exactly one JSON document, got {e}:\n{stdout}"));

    assert!(
        json["artifact_id"]
            .as_str()
            .is_some_and(|s| s.starts_with("art_")),
        "artifact_id is what an SDK reads off this call: {json}"
    );
    assert!(json["digest"].as_str().is_some(), "{json}");
    assert_eq!(json["exit_code"], 0, "{json}");
    assert_eq!(json["succeeded"], true, "{json}");

    // The child's output is moved, not dropped. A caller running --format json
    // interactively must still see what their command printed.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("NOISE"),
        "the wrapped command's output must still reach the user on stderr: {stderr}"
    );
    // Not `!stdout.contains("NOISE")` -- that fails on the correct output,
    // because the argv is legitimately in the document as `command`. The real
    // property is that stdout holds NOTHING but the document: no bare line
    // before it. Parsing whole (above) proves that; this pins the reason.
    assert_eq!(
        json["command"],
        serde_json::json!(["echo", "NOISE"]),
        "the argv belongs in the document; the child's stdout does not: {json}"
    );
    assert!(
        stdout.trim_start().starts_with('{'),
        "stdout must begin with the document, not the wrapped program's output: {stdout}"
    );
}

/// Human mode is unchanged: the child's output belongs on stdout there.
#[test]
fn wrap_human_mode_still_passes_child_stdout_through() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path();
    let config = root.join(".treeship/config.json");
    let cfg = config.to_str().unwrap();

    let run = |args: &[&str]| {
        let mut cmd = Command::new(cli_path());
        cmd.current_dir(root).env("HOME", root).args(args);
        cmd.output().expect("run treeship")
    };

    let init = run(&["init", "--config", cfg, "--name", "wrap-human"]);
    assert!(init.status.success());

    let out = run(&["wrap", "--config", cfg, "--", "echo", "VISIBLE"]);
    assert!(
        out.status.success(),
        "wrap: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("VISIBLE"),
        "human mode must keep the child's output on stdout"
    );
}
