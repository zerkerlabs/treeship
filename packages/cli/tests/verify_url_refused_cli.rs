//! A URL that names no receipt is refused before any request is made, and
//! the exit code says "usage" (4), not "network error" (3): a retry loop
//! keyed on 3 must not spin on a typo. (0.31.9 full test, CLI-11 review.)

use std::process::Command;

fn cli_path() -> &'static str {
    env!("CARGO_BIN_EXE_treeship")
}

#[test]
fn a_non_receipt_url_is_refused_with_exit_4_and_no_request() {
    let home = tempfile::tempdir().unwrap();
    // 127.0.0.1:1 has nothing listening; if the CLI tried to fetch, the
    // failure would be a connection error and exit 3.
    for target in [
        "http://127.0.0.1:1/verify/art_23e6b18b1c0de245",
        "http://127.0.0.1:1/receipt/..",
        "http://127.0.0.1:1/receipt/ssn_x%2Fadmin",
        "http://treeship.dev@127.0.0.1:1/receipt/ssn_ed0fc8f61253a406",
    ] {
        let out = Command::new(cli_path())
            .env("HOME", home.path())
            .env_remove("TREESHIP_CONFIG")
            .args(["verify", target])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(4), "{target}: {stderr}");
        assert!(stderr.contains("not a receipt URL"), "{target}: {stderr}");
        assert!(
            !stderr.contains("HTTP request failed"),
            "{target}: a request was made: {stderr}"
        );
    }
}

#[test]
fn an_unreachable_receipt_url_is_a_network_error_exit_3() {
    let home = tempfile::tempdir().unwrap();
    let out = Command::new(cli_path())
        .env("HOME", home.path())
        .env_remove("TREESHIP_CONFIG")
        .args(["verify", "http://127.0.0.1:1/receipt/ssn_ed0fc8f61253a406"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
