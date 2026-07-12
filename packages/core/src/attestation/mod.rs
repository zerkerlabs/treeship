pub mod envelope;
pub mod id;
pub mod pae;
pub mod sign;
pub mod signer;
pub mod verify;

// Re-exports for ergonomic use: `use treeship_core::attestation::*`
pub use envelope::{Envelope, Signature};
pub use id::{artifact_id_from_pae, digest_from_pae, ArtifactId};
pub use pae::pae;
pub use sign::{sign, SignError, SignResult};
pub use signer::{Ed25519Signer, Signer, SignerError};
pub use verify::{verify_with_key, Verifier, VerifyError, VerifyResult};
