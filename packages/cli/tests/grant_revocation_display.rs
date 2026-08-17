use std::process::Command;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

/// `grant show` printed a clean success for a grant revoked seconds earlier,
/// and `grant list` rendered it identically to a live one.
///
/// A signature stays valid forever; revocation is what makes a grant stop
/// counting. Both commands reported the signature and neither consulted the
/// revocation receipt they had just written -- so the two commands whose whole
/// job is "tell me about this grant" were the surfaces that never looked.
///
/// This asserts the marker appears in both, and that a *live* grant is not
/// marked, because a check that fires on everything is not a check.
#[test]
fn revoked_grants_are_marked_in_show_and_list() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path();
    let config = root.join(".treeship/config.json");
    let cfg = config.to_str().unwrap();

    let command = |args: &[&str]| {
        let mut cmd = Command::new(cli_path());
        cmd.current_dir(root).env("HOME", root).args(args);
        cmd.output().expect("run treeship")
    };

    let init = command(&["init", "--config", cfg, "--name", "revocation-display"]);
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let issue = |scope: &str| {
        let out = command(&[
            "grant",
            "issue",
            "--config",
            cfg,
            "--scope",
            scope,
            "--audience",
            "agent://worker",
            "--expiry",
            "2030-12-31T23:59:59Z",
        ]);
        assert!(
            out.status.success(),
            "issue: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let text = String::from_utf8_lossy(&out.stdout);
        text.split_whitespace()
            .find(|t| t.starts_with("grn_"))
            .map(|t| {
                t.trim_end_matches(|c: char| !c.is_alphanumeric() && c != '_')
                    .to_string()
            })
            .unwrap_or_else(|| panic!("no grant id in: {text}"))
    };

    let revoked = issue("deploy.*");
    let live = issue("build.*");

    let rev = command(&[
        "grant",
        "revoke",
        &revoked,
        "--config",
        cfg,
        "--reason",
        "compromised",
    ]);
    assert!(
        rev.status.success(),
        "revoke: {}",
        String::from_utf8_lossy(&rev.stderr)
    );

    // ── show ──
    let show = command(&["grant", "show", &revoked, "--config", cfg]);
    let shown = String::from_utf8_lossy(&show.stdout);
    assert!(
        shown.to_lowercase().contains("revoked"),
        "`grant show` must report the revocation it just wrote, got:\n{shown}"
    );

    // A live grant must NOT be marked, or the marker means nothing.
    let show_live = command(&["grant", "show", &live, "--config", cfg]);
    let shown_live = String::from_utf8_lossy(&show_live.stdout);
    assert!(
        !shown_live.contains("REVOKED"),
        "a live grant must not be marked revoked, got:\n{shown_live}"
    );

    // ── list ──
    let list = command(&["grant", "list", "--config", cfg]);
    let listed = String::from_utf8_lossy(&list.stdout);
    let revoked_line = listed
        .lines()
        .find(|l| l.contains(&revoked))
        .unwrap_or_else(|| panic!("revoked grant missing from list:\n{listed}"));
    assert!(
        revoked_line.contains("REVOKED"),
        "the revoked row must be marked, got: {revoked_line}"
    );
    let live_line = listed
        .lines()
        .find(|l| l.contains(&live))
        .unwrap_or_else(|| panic!("live grant missing from list:\n{listed}"));
    assert!(
        !live_line.contains("REVOKED"),
        "the live row must not be marked, got: {live_line}"
    );

    // ── json carries the same fact, structured ──
    let json = command(&[
        "grant", "show", &revoked, "--config", cfg, "--format", "json",
    ]);
    let v: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("show --format json must be one document");
    assert_eq!(
        v["revocation"]["state"], "revoked",
        "json must carry the state too: {v}"
    );
    assert!(
        v["revocation"]["revoked_at"].as_str().is_some(),
        "a revoked state must carry when: {v}"
    );
}
