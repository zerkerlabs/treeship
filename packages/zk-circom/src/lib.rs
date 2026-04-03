pub mod circuits;
pub mod prover;
pub mod utils;

pub use prover::CircomProver;
use serde::{Deserialize, Serialize};

/// Circom proof structure matching the expected format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircomProof {
    pub proof: ProofData,
    pub public_signals: Vec<String>,
    pub circuit_name: String,
}

/// Proof data structure for Groth16 proofs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofData {
    pub pi_a: [String; 3],
    pub pi_b: [[String; 2]; 3],
    pub pi_c: [String; 3],
    pub protocol: String,
    pub curve: String,
}

/// High-level ZK proof wrapper for Treeship consumption.
/// Carries enough metadata to identify what was proved and how.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProof {
    /// Schema version (currently 1)
    pub version: u32,
    /// Proof system identifier, e.g. "circom-groth16"
    pub system: String,
    /// Circuit name, e.g. "policy-checker"
    pub circuit: String,
    /// Opaque identifier for the artifact being proved
    pub artifact_id: String,
    /// The raw Groth16 proof data
    pub proof: ProofData,
    /// Public signals emitted by the circuit
    pub public_signals: Vec<String>,
    /// RFC 3339 timestamp of when the proof was generated
    pub proved_at: String,
}
