//! # rig-treeship
//!
//! Signed, chained, offline-verifiable receipts for every tool call a
//! [Rig](https://crates.io/crates/rig-core) agent makes — built natively on
//! [`treeship-core`](https://crates.io/crates/treeship-core). No CLI
//! subprocess, no wrapper scripts: signing happens in-process, the compiler
//! checks the seam, and receipts carry SHA-256 hashes of arguments and
//! outputs rather than raw content.
//!
//! ```no_run
//! use std::sync::Arc;
//! use rig_treeship::{AttestedExt, TreeshipLedger};
//! # use rig::tool::PortableTool;
//! # #[derive(serde::Deserialize, serde::Serialize)] struct Args { x: i64 }
//! # struct MyTool;
//! # impl PortableTool for MyTool {
//! #     const NAME: &'static str = "my_tool";
//! #     type Args = Args; type Output = i64; type Error = std::io::Error;
//! #     fn description(&self) -> String { "".into() }
//! #     fn parameters(&self) -> serde_json::Value { serde_json::json!({}) }
//! #     async fn call(&self, a: Args) -> Result<i64, std::io::Error> { Ok(a.x) }
//! # }
//!
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let ledger = Arc::new(TreeshipLedger::open_default("agent://my-agent")?);
//! let tool = MyTool.attested(ledger.clone());
//! // register `tool` with your Rig runtime exactly like the bare tool —
//! // same NAME, description, and JSON schema; every call now signs a
//! // treeship/action/v1 receipt chained to the previous one.
//! # Ok(()) }
//! ```

mod attested;
mod error;
mod ledger;

pub use attested::{Attested, AttestedExt};
pub use error::{AttestError, AttestedError};
pub use ledger::{sha256_json, tool_call_meta, Attestation, ChainVerification, TreeshipLedger};

#[cfg(test)]
mod tests {
    use super::*;
    use rig::tool::PortableTool;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;

    #[derive(Debug, thiserror::Error)]
    #[error("division by zero")]
    struct DivByZero;

    #[derive(Serialize, Deserialize)]
    struct DivArgs {
        a: i64,
        b: i64,
    }

    struct Divide;

    impl PortableTool for Divide {
        const NAME: &'static str = "divide";
        type Args = DivArgs;
        type Output = i64;
        type Error = DivByZero;

        fn description(&self) -> String {
            "Divide a by b".into()
        }

        fn parameters(&self) -> serde_json::Value {
            serde_json::json!({
                "type": "object",
                "properties": {
                    "a": { "type": "integer" },
                    "b": { "type": "integer" }
                },
                "required": ["a", "b"]
            })
        }

        async fn call(&self, args: DivArgs) -> Result<i64, DivByZero> {
            if args.b == 0 {
                return Err(DivByZero);
            }
            Ok(args.a / args.b)
        }
    }

    #[tokio::test]
    async fn attests_and_chains_calls() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Arc::new(TreeshipLedger::open(dir.path(), "agent://test").unwrap());
        let tool = Divide.attested(ledger.clone());

        assert_eq!(tool.call(DivArgs { a: 10, b: 2 }).await.unwrap(), 5);
        assert_eq!(tool.call(DivArgs { a: 9, b: 3 }).await.unwrap(), 3);
        // A failing call is attested too.
        assert!(tool.call(DivArgs { a: 1, b: 0 }).await.is_err());

        let head = ledger.head().expect("chain head after three calls");
        let verified = ledger.verify_chain(&head).unwrap();
        assert_eq!(verified.length, 3);
    }

    #[tokio::test]
    async fn wrapper_is_transparent_to_the_model() {
        let ledger = Arc::new(TreeshipLedger::ephemeral("agent://test").unwrap());
        let tool = Divide.attested(ledger);
        assert_eq!(<Attested<Divide> as PortableTool>::NAME, "divide");
        assert_eq!(tool.description(), Divide.description());
        assert_eq!(tool.parameters(), Divide.parameters());
    }

    #[tokio::test]
    async fn tampering_breaks_verification() {
        let dir = tempfile::tempdir().unwrap();
        let ledger = Arc::new(TreeshipLedger::open(dir.path(), "agent://test").unwrap());
        let tool = Divide.attested(ledger.clone());
        tool.call(DivArgs { a: 8, b: 2 }).await.unwrap();
        let head = ledger.head().unwrap();

        // Flip bytes in the stored artifact's payload.
        let path = dir.path().join("artifacts").join(format!("{head}.json"));
        let mut record: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        record["envelope"]["payload"] = serde_json::json!("dGFtcGVyZWQ");
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();

        assert!(ledger.verify_chain(&head).is_err());
    }
}
