//! Quarantined: the Circom/Groth16 proof path is not sound as implemented.
//!
//! The July 2026 ZK audit found two independent defects that make this path
//! unfit to produce or verify a trustworthy proof (see
//! `docs/specs/zk-verification.md`):
//!
//!   1. **No phase-2 trusted setup.** The prover generated proving keys
//!      locally with `snarkjs groth16 setup` and zero MPC contributions, so
//!      the proving key's trapdoor is derivable and *any* statement is
//!      forgeable. This is the absence of soundness, not a weak spot.
//!   2. **No artifact binding, and an unsatisfiable constraint.** Three of
//!      four circuits left the artifact identifier unconstrained, and the
//!      off-circuit hash was a SHA-256 stand-in for the on-circuit Poseidon,
//!      so the policy circuit's one hard constraint could never be satisfied.
//!
//! Rather than ship a forgeable proof path behind a feature flag, every entry
//! point fails closed with a pointer to the rebuild. The `.circom` sources are
//! retained as design references; a sound path returns only under a real
//! trusted-setup ceremony or a transparent proof system, statement-first, per
//! the spec. The transparent RISC Zero zkVM path (`packages/zk-risc0`) is the
//! primary non-interactive path in the rebuild.

use crate::CircomProof;
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CircomError {
    #[error("{0}")]
    Quarantined(String),
}

pub type Result<T> = std::result::Result<T, CircomError>;

const QUARANTINE: &str = "the Circom/Groth16 proof path is quarantined: it has no real \
trusted setup (forgeable by construction) and its policy constraint is unsatisfiable. \
It is being rebuilt statement-first; see docs/specs/zk-verification.md. The transparent \
RISC Zero zkVM path is the non-interactive proof path in the rebuild.";

fn quarantined<T>() -> Result<T> {
    Err(CircomError::Quarantined(QUARANTINE.to_string()))
}

/// Circom proof system integration. Every method fails closed while the path
/// is quarantined; see the module docs.
pub struct CircomProver;

impl CircomProver {
    pub fn new<P: AsRef<Path>>(_circuits_path: P) -> Result<Self> {
        quarantined()
    }

    pub fn prove_policy(
        &self,
        _action: &str,
        _allowed_actions: &[String],
        _artifact_id: &str,
    ) -> Result<CircomProof> {
        quarantined()
    }

    pub fn prove_io_binding(
        &self,
        _input_digest: &[u8; 32],
        _output_digest: &[u8; 32],
        _artifact_id: &str,
    ) -> Result<CircomProof> {
        quarantined()
    }

    pub fn prove_prompt_template(
        &self,
        _prompt_digest: &[u8; 32],
        _template_digest: &[u8; 32],
        _artifact_id: &str,
    ) -> Result<CircomProof> {
        quarantined()
    }

    pub fn prove_spend_limit(
        &self,
        _artifact_id: &str,
        _actual_amount_cents: u64,
        _max_spend_cents: u64,
    ) -> Result<CircomProof> {
        quarantined()
    }

    pub fn verify_all_proofs(&self, _proofs: &HashMap<String, CircomProof>) -> Result<bool> {
        quarantined()
    }

    pub fn verify_single_proof(&self, _circuit_name: &str, _proof: &CircomProof) -> Result<bool> {
        quarantined()
    }
}
