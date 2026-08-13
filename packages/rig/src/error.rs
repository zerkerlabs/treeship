use thiserror::Error;

/// Errors produced by the Treeship side of the integration.
#[derive(Debug, Error)]
pub enum AttestError {
    #[error("keystore: {0}")]
    Keys(String),

    #[error("signing: {0}")]
    Sign(String),

    #[error("artifact store: {0}")]
    Storage(String),

    #[error("verification failed for {artifact_id}: {reason}")]
    Verify { artifact_id: String, reason: String },

    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Error type surfaced by an [`crate::Attested`] tool.
///
/// Distinguishes the wrapped tool's own failure from a failure to produce
/// the attestation. The wrapper is **fail-closed**: if the receipt cannot
/// be signed and stored, the call fails even when the underlying tool
/// succeeded — an unattested action is treated as no action.
#[derive(Debug, Error)]
pub enum AttestedError<E: std::error::Error + 'static> {
    #[error("tool: {0}")]
    Tool(#[source] E),

    #[error("attestation: {0}")]
    Attest(#[source] AttestError),
}
