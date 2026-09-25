//! T2 (audit 2026-09-25): the receipt-only verifier over the frozen package
//! vectors in `tests/vectors/packages/`.
//!
//! `verify_receipt` in core-wasm, which `@treeship/verify`'s `verifyReceipt`
//! runs, sees only `receipt.json`: no envelopes, no keys, no close record. The
//! strongest thing it may ever say is `structural-pass`. This test holds it to
//! the `receipt_only` column of `expected.json`, and to the hard rule that it
//! never returns anything stronger on any vector. The CLI columns of the same
//! file are checked by `tests/vectors/packages/run.sh`.
//!
//! Vector provenance: `tests/vectors/packages/README.md`.

use std::path::{Path, PathBuf};

use treeship_core::session::{SessionReceipt, VerifyStatus};
use treeship_core::verify::verify_receipt_json_checks;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/vectors/packages")
}

/// The outcome core-wasm's `verify_receipt` reports for a receipt
/// (packages/core-wasm/src/lib.rs, `verify_receipt`): `fail` when any check
/// fails or the receipt seals no artifacts, otherwise `structural-pass`.
fn receipt_only_outcome(receipt_json: &str) -> &'static str {
    let receipt: SessionReceipt = match serde_json::from_str(receipt_json) {
        Ok(r) => r,
        Err(_) => return "error",
    };
    let checks = verify_receipt_json_checks(&receipt);
    if checks.iter().any(|c| c.status == VerifyStatus::Fail) || receipt.artifacts.is_empty() {
        "fail"
    } else {
        "structural-pass"
    }
}

#[test]
fn receipt_only_verdicts_match_expected() {
    let dir = vectors_dir();
    let expected: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("expected.json")).unwrap()).unwrap();
    let vectors = expected["vectors"].as_object().expect("vectors object");
    assert!(
        vectors.len() >= 10,
        "expected.json lists {} vectors; the set only grows",
        vectors.len()
    );

    let mut wrong = Vec::new();
    for (name, exp) in vectors {
        let want = exp["receipt_only"]
            .as_str()
            .unwrap_or_else(|| panic!("{name}: no receipt_only column"));
        let raw = std::fs::read_to_string(dir.join(name).join("receipt.json"))
            .unwrap_or_else(|e| panic!("{name}: receipt.json: {e}"));
        let got = receipt_only_outcome(&raw);
        // A keyless verifier that says anything stronger than structural-pass
        // is claiming authenticity it cannot check (AUD-01).
        assert!(
            got == "structural-pass" || got == "fail",
            "{name}: receipt-only verifier returned {got}"
        );
        if got != want {
            wrong.push(format!("{name}: got {got}, expected {want}"));
        }
    }
    assert!(
        wrong.is_empty(),
        "receipt_only mismatches:\n{}",
        wrong.join("\n")
    );
}
