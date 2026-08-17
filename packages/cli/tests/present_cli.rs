use std::process::Command;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

/// `present` panicked with "range end index 3 out of range for slice of
/// length 2" on a fresh onboard.
///
/// `load_latest_checkpoint` reads ~/.treeship/merkle/checkpoints
/// unconditionally, while `build_tree` reads the artifacts for the current
/// context. `--config`, a second workspace, or a pruned store all give a
/// checkpoint describing more leaves than the store holds, and the slice
/// panicked.
///
/// A panic is the wrong answer here twice over: it is a crash where the
/// honest result is a diagnosis, and the message named an index rather than
/// the actual problem, which is that two stores do not describe the same
/// history.
#[test]
fn present_reports_a_checkpoint_store_mismatch_instead_of_panicking() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path();
    let config = root.join(".treeship/config.json");

    let command = |args: &[&str]| {
        let mut cmd = Command::new(cli_path());
        // HOME is redirected so the checkpoint store is this test's, not the
        // developer's -- the bug itself is that those can differ.
        cmd.current_dir(root).env("HOME", root).args(args);
        cmd.output().expect("run treeship")
    };

    let init = command(&[
        "init",
        "--config",
        config.to_str().unwrap(),
        "--name",
        "present-test",
    ]);
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let onboard = command(&[
        "onboard",
        "agent://deployer",
        "--config",
        config.to_str().unwrap(),
        "--tools",
        "deploy.*",
    ]);
    assert!(
        onboard.status.success(),
        "onboard: {}",
        String::from_utf8_lossy(&onboard.stderr)
    );

    let out = root.join("d.presentation.json");
    let present = command(&[
        "present",
        "agent://deployer",
        "--config",
        config.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);

    let stderr = String::from_utf8_lossy(&present.stderr);
    assert!(
        !stderr.contains("panicked"),
        "present must not panic; it did:\n{stderr}"
    );

    // Either it succeeds (checkpoint and store agree) or it explains itself.
    // Both are acceptable; a panic is not.
    if !present.status.success() {
        let combined = format!("{}{}", String::from_utf8_lossy(&present.stdout), stderr);
        assert!(
            combined.contains("checkpoint") && combined.contains("treeship checkpoint"),
            "a failure must name the mismatch and the fix, got:\n{combined}"
        );
    } else {
        assert!(out.exists(), "reported success but wrote no presentation");
    }
}
