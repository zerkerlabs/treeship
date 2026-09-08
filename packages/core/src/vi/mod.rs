//! Verifiable Intent (VI) support: Treeship as one `agent_attestation`
//! scheme inside a VI Layer 3 credential.
//!
//! [Verifiable Intent](https://verifiableintent.dev/) is an open, Mastercard-
//! maintained credential standard for agent commerce (draft v0.1, February
//! 2026). A user delegates bounded authority to an agent through a chain of
//! SD-JWTs: L1 (issuer → user), L2 (user → agent, with constraints and the
//! agent's key under `cnf`), and in autonomous mode two Layer 3 credentials
//! the agent signs itself: L3a for the payment network and L3b for the
//! merchant. Every layer is ES256 (ECDSA over P-256, SHA-256).
//!
//! This module is an independent implementation against the published draft
//! and its Python reference SDK. It is not endorsed by, and does not speak
//! for, the standard's maintainers. Byte formats follow the reference so that
//! credentials built here verify with the reference `verify_chain`, and vice
//! versa; the interop suite under `tests/vi-interop` holds that line.
//!
//! What Treeship adds is the value of the spec's own optional
//! `agent_attestation` claim (§9.2 of the v0.1 README): a signed statement,
//! chained into the agent's receipt chain, that names the session, the chain
//! head, the Merkle checkpoint over that chain, and the approval use the
//! action ran under. A verifier that does not know the scheme ignores the
//! claim, as the spec requires. One that does can fetch the session package
//! and check that the credential was minted at the end of exactly that
//! sequence of signed steps.
//!
//! Layout:
//! - [`jws`]: base64url, SHA-256, P-256 keys and ES256 compact JWS.
//! - [`sd_jwt`]: SD-JWT serialization, disclosures, selective presentations.
//! - [`mandate`]: a parsed view of an L2 mandate.
//! - [`constraints`]: the eight registered constraint types, checked the way
//!   the reference checks them.
//! - [`l3`]: building L3a / L3b.
//! - [`attestation`]: the Treeship attestation statement and claim.
//! - [`verify`]: verifying L3 credentials against their L2 (and L2 against L1).
//! - [`keys`]: the agent's P-256 key at rest, sealed by the ship keystore.

pub mod attestation;
pub mod constraints;
pub mod jws;
pub mod keys;
pub mod l3;
pub mod mandate;
pub mod sd_jwt;
pub mod verify;

pub use attestation::{
    attestation_payload_type, build_attestation_claim, verify_attestation_claim, AttestationClaim,
    AttestationStatement, AttestationVerified, ATTESTATION_ACTION, ATTESTATION_SCHEME,
    ATTESTATION_STATEMENT_TYPE,
};
pub use constraints::{check_constraints, CheckResult};
pub use jws::{AgentKey, Jwk};
pub use l3::{build_l3, L3Bundle, L3Request, LineItem};
pub use mandate::L2View;
pub use sd_jwt::SdJwt;
pub use verify::{verify_l2_against_l1, verify_l3, Check, Report};

/// Errors produced by the VI module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ViError {
    /// Malformed input: bad base64url, bad JSON, a token with the wrong shape.
    Malformed(String),
    /// A key could not be parsed, generated, sealed or unsealed.
    Key(String),
    /// A signature did not verify.
    Signature(String),
    /// The requested action falls outside the mandate, or the mandate is
    /// unusable (empty allowlist, missing constraint).
    Mandate(String),
    /// A verification check failed (see [`Report`] for the full list).
    Verification(String),
}

impl std::fmt::Display for ViError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) => write!(f, "malformed: {m}"),
            Self::Key(m) => write!(f, "key: {m}"),
            Self::Signature(m) => write!(f, "signature: {m}"),
            Self::Mandate(m) => write!(f, "mandate: {m}"),
            Self::Verification(m) => write!(f, "verification: {m}"),
        }
    }
}

impl std::error::Error for ViError {}
