//! `Attested<T>` — wrap any Rig [`PortableTool`] so every call produces a
//! signed, chained Treeship receipt before the result is returned to the
//! model.

use std::sync::Arc;

use rig::tool::PortableTool;
use rig::wasm_compat::WasmCompatSend;
use serde::Serialize;

use crate::error::{AttestError, AttestedError};
use crate::ledger::{sha256_json, tool_call_meta, TreeshipLedger};

/// A Rig tool whose every invocation is attested on a [`TreeshipLedger`].
///
/// The wrapper is transparent to the model: same name, description, and
/// parameter schema as the inner tool. On each call it:
///
/// 1. hashes the deserialized arguments (SHA-256 over compact JSON),
/// 2. runs the inner tool,
/// 3. hashes the output (or records the failure),
/// 4. signs a `treeship/action/v1` statement carrying both hashes,
///    chained to the previous attestation, and
/// 5. returns the inner result only after the receipt is stored.
///
/// **Fail-closed:** if signing or storage fails, the call errors even when
/// the tool succeeded. Failed tool calls are attested too (`outcome:
/// "error"`) — a receipt chain with gaps proves nothing.
pub struct Attested<T> {
    inner: T,
    ledger: Arc<TreeshipLedger>,
}

impl<T> Attested<T> {
    pub fn new(inner: T, ledger: Arc<TreeshipLedger>) -> Self {
        Self { inner, ledger }
    }

    pub fn ledger(&self) -> &Arc<TreeshipLedger> {
        &self.ledger
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> PortableTool for Attested<T>
where
    T: PortableTool,
    T::Args: Serialize,
    T::Output: Serialize,
{
    const NAME: &'static str = T::NAME;
    type Args = T::Args;
    type Output = T::Output;
    type Error = AttestedError<T::Error>;

    fn description(&self) -> String {
        self.inner.description()
    }

    fn parameters(&self) -> serde_json::Value {
        self.inner.parameters()
    }

    // clippy suggests `async fn` here, and it is wrong: `async fn` desugars to
    // a bare `impl Future` with no way to add the `+ WasmCompatSend` bound
    // that `PortableTool::call` requires. Taking the suggestion would drop the
    // bound and break the wasm targets Rig supports.
    #[allow(clippy::manual_async_fn)]
    fn call(
        &self,
        arguments: Self::Args,
    ) -> impl std::future::Future<Output = Result<Self::Output, Self::Error>> + WasmCompatSend {
        async move {
            let args_hash = sha256_json(&arguments).map_err(AttestedError::Attest)?;
            let action = format!("tool.call.{}", T::NAME);

            match self.inner.call(arguments).await {
                Ok(output) => {
                    let output_hash = sha256_json(&output).map_err(AttestedError::Attest)?;
                    self.attest(&action, &args_hash, Some(&output_hash), "success")?;
                    Ok(output)
                }
                Err(tool_err) => {
                    self.attest(&action, &args_hash, None, "error")?;
                    Err(AttestedError::Tool(tool_err))
                }
            }
        }
    }
}

impl<T> Attested<T>
where
    T: PortableTool,
{
    fn attest(
        &self,
        action: &str,
        args_hash: &str,
        output_hash: Option<&str>,
        outcome: &str,
    ) -> Result<(), AttestedError<T::Error>> {
        self.ledger
            .attest_action(
                action,
                tool_call_meta(T::NAME, args_hash, output_hash, outcome),
            )
            .map(|_| ())
            .map_err(|e: AttestError| AttestedError::Attest(e))
    }
}

/// Extension method so wrapping reads left-to-right at the call site:
/// `Calculator.attested(ledger.clone())`.
pub trait AttestedExt: PortableTool + Sized {
    fn attested(self, ledger: Arc<TreeshipLedger>) -> Attested<Self> {
        Attested::new(self, ledger)
    }
}

impl<T: PortableTool> AttestedExt for T {}
