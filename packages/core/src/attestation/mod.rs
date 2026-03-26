pub mod pae;
pub mod id;
pub mod signer;
pub mod envelope;
pub mod sign;
pub mod verify;

// Re-exports for ergonomic use: `use treeship_core::attestation::*`
pub use pae::pae;
pub use id::{artifact_id_from_pae, digest_from_pae, ArtifactId};
pub use signer::{Signer, Ed25519Signer, SignerError};
pub use envelope::{Envelope, Signature};
pub use sign::{sign, SignResult, SignError};
pub use verify::{Verifier, VerifyResult, VerifyError};
