//! Runs the shared redaction vectors against the real `treeship wrap` path.
//!
//! The OpenClaw plugin runs the same vector file
//! (`integrations/openclaw-plugin/test/redaction.test.mjs`). Two
//! implementations of one security control drift, and drift here is silent --
//! receipts keep being produced, they just stop being safe.
//!
//! # Why this asserts on the decoded payload
//!
//! The first version of this test grepped the artifact files for the secret
//! and passed with redaction **completely disabled**. A DSSE envelope stores
//! its payload base64-encoded, so the plaintext never appears in the file and
//! the search could not fail. It also invoked `wrap` with a flag that does not
//! exist, so every run errored out and wrote nothing at all.
//!
//! Two independent reasons the same test was vacuous, which is why the
//! negative control below is part of the test rather than something that was
//! run once by hand: `wrap` must produce an artifact, and that artifact's
//! decoded payload must contain the command. If either stops being true this
//! fails loudly instead of passing for free.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("vectors")
        .join("redaction.json")
}

/// Run `treeship wrap` on a vector and return every signed payload it wrote,
/// decoded. `echo` stands in for the real program: only what gets *recorded*
/// matters, and the arguments are preserved verbatim.
fn wrap_and_decode(input: &str) -> Vec<String> {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = tmp.path().join("config.json");
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_treeship"));

    let init = Command::new(&bin)
        .arg("init")
        .arg("--config")
        .arg(&config)
        .output()
        .expect("run treeship init");
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );

    let args: Vec<&str> = input.split_whitespace().collect();
    let mut cmd = Command::new(&bin);
    // cwd inside the temp dir so a repo-local .treeship cannot be picked up.
    cmd.current_dir(tmp.path())
        .arg("wrap")
        .arg("--config")
        .arg(&config)
        .arg("--")
        .arg("echo");
    for a in &args[1..] {
        cmd.arg(a);
    }
    let out = cmd.output().expect("run treeship wrap");
    assert!(
        out.status.success(),
        "wrap failed for {input:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let dir = tmp.path().join("artifacts");
    let mut payloads = Vec::new();
    for entry in fs::read_dir(&dir).expect("artifacts dir").flatten() {
        let path = entry.path();
        if !path.file_name().is_some_and(|n| {
            n.to_string_lossy().starts_with("art_") && n.to_string_lossy().ends_with(".json")
        }) {
            continue;
        }
        payloads.push(decode_payload(&path));
    }

    // An empty result would make every assertion below vacuous -- which is
    // exactly how the first version of this test passed while broken.
    assert!(
        !payloads.is_empty(),
        "wrap wrote no artifact for {input:?}; nothing was checked"
    );
    payloads
}

fn decode_payload(path: &Path) -> String {
    let raw = fs::read_to_string(path).expect("read artifact");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("parse artifact");
    let envelope = v.get("envelope").unwrap_or(&v);
    let payload = envelope["payload"]
        .as_str()
        .expect("artifact has a DSSE payload");
    let bytes = STANDARD_NO_PAD
        .decode(payload.trim_end_matches('='))
        .expect("payload is base64");
    String::from_utf8(bytes).expect("payload is utf-8")
}

#[test]
fn shared_vectors_do_not_leak_into_signed_payloads() {
    let raw = fs::read_to_string(vectors_path()).expect("read shared redaction vectors");
    let vectors: serde_json::Value = serde_json::from_str(&raw).expect("parse vectors");
    let leaks = vectors["leaks"].as_array().expect("leaks array");
    assert!(!leaks.is_empty(), "vector file has no leak cases");

    for v in leaks {
        let input = v["input"].as_str().expect("input");
        let name = v["name"].as_str().unwrap_or("<unnamed>");
        let payloads = wrap_and_decode(input);
        let joined = payloads.join("\n");

        for secret in v["must_not_contain"].as_array().expect("must_not_contain") {
            let secret = secret.as_str().expect("secret string");
            assert!(
                !joined.contains(secret),
                "vector {name:?}: secret {secret:?} reached the signed payload\n\
                 input:   {input}\n\
                 payload: {joined}"
            );
        }

        // The opposite failure, and not a hypothetical one: redacting the
        // whole line satisfies every assertion above while destroying the
        // evidence the receipt exists to carry. This check is what caught
        // `is_value_flag` matching the bare word `auth` in `gh auth login`
        // and redacting `login` -- the leak assertions were all green.
        // The vector's program name is not in the payload: this harness
        // substitutes `echo` for it so the vectors cannot actually run curl,
        // git or aws. Skipping it here keeps the check honest -- asserting on
        // something the harness deliberately removed would be testing the
        // harness, not the redactor.
        let program = input.split_whitespace().next().unwrap_or("");
        for keep in v["preserved"].as_array().unwrap_or(&vec![]) {
            let keep = keep.as_str().expect("preserved string");
            if keep == program {
                continue;
            }
            assert!(
                joined.contains(keep),
                "vector {name:?}: over-redacted, lost {keep:?}\n\
                 input:   {input}\n\
                 payload: {joined}"
            );
        }
    }
}

/// The control that the previous version of this test needed and did not have.
///
/// Proves the harness can observe a leak at all: the command really does reach
/// the signed payload, so a redaction failure would be caught rather than
/// silently passing. Asserts on a value no redaction rule touches.
#[test]
fn harness_can_observe_the_command_in_the_payload() {
    let payloads = wrap_and_decode("echo harmlessmarkervalue");
    let joined = payloads.join("\n");
    assert!(
        joined.contains("harmlessmarkervalue"),
        "the wrapped command never reached the payload, so the leak assertions \
         in this file cannot fail and prove nothing.\npayload: {joined}"
    );
}
