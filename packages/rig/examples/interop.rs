//! Proves the two claims the README makes about interoperability:
//!
//!   1. `open_default` resolves the same store the `treeship` CLI would, so
//!      an agent run inside a project writes into that project's ship.
//!   2. The receipts it writes are ordinary Treeship artifacts, so
//!      `treeship verify` accepts them with no special flags.
//!
//! Run from a directory containing `.treeship/config.json`:
//!
//! ```text
//! cargo run --example interop
//! treeship verify <printed id>
//! ```
use rig_treeship::TreeshipLedger;

fn main() {
    let ledger = TreeshipLedger::open_default("agent://rig-interop").expect("open ledger");

    let a = ledger
        .attest_action(
            "tool.call.calculator",
            serde_json::json!({
                "args_hash": "sha256:aa", "output_hash": "sha256:bb", "outcome": "success"
            }),
        )
        .expect("attest a");

    let b = ledger
        .attest_action(
            "tool.call.search",
            serde_json::json!({
                "args_hash": "sha256:cc", "output_hash": "sha256:dd", "outcome": "success"
            }),
        )
        .expect("attest b");

    println!("{}", a.artifact_id);
    println!("{}", b.artifact_id);
}
